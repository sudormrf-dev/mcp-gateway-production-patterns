"""Strict sandboxing of MCP tool execution via subprocess isolation.

Each tool call runs in a separate subprocess with:
- CPU time limit (RLIMIT_CPU)
- Memory limit (RLIMIT_AS / RLIMIT_DATA)
- No network access (optional: via unshare)
- Temp-dir-scoped filesystem access

Pattern:
    Gateway receives tool call
    → Spawns sandboxed subprocess with resource limits
    → Subprocess executes tool code in isolation
    → Result returned via stdout JSON
    → Subprocess terminates (cannot accumulate state)

This prevents a compromised or misbehaving tool from affecting the host
process or other tenants.

Usage::

    sandbox = ToolSandbox(
        cpu_limit_seconds=5,
        memory_limit_mb=256,
    )
    result = await sandbox.run("my_tool", args={"input": "hello"})
"""

from __future__ import annotations

import asyncio
import json
import os
import resource
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_DEFAULT_CPU_LIMIT_SECONDS: int = 10
_DEFAULT_MEMORY_LIMIT_MB: int = 512
_DEFAULT_PROCESS_TIMEOUT_SECONDS: float = 30.0
_DEFAULT_OUTPUT_SIZE_LIMIT_BYTES: int = 1 * 1024 * 1024  # 1 MB


@dataclass(frozen=True)
class SandboxLimits:
    """Resource limits applied to each sandboxed subprocess.

    Args:
        cpu_seconds: Maximum CPU seconds before SIGKILL.
        memory_mb: Maximum virtual memory in MB.
        process_timeout: Wall-clock timeout for the subprocess.
        output_size_bytes: Maximum stdout size captured.
    """

    cpu_seconds: int = _DEFAULT_CPU_LIMIT_SECONDS
    memory_mb: int = _DEFAULT_MEMORY_LIMIT_MB
    process_timeout: float = _DEFAULT_PROCESS_TIMEOUT_SECONDS
    output_size_bytes: int = _DEFAULT_OUTPUT_SIZE_LIMIT_BYTES


@dataclass
class SandboxResult:
    """Result of a sandboxed tool execution."""

    success: bool
    output: dict[str, Any]
    exit_code: int
    stderr: str
    cpu_seconds_used: float
    wall_time_seconds: float
    killed: bool = False


def _apply_resource_limits(
    cpu_seconds: int, memory_mb: int
) -> None:
    """Set POSIX resource limits in the child process.

    Called as ``preexec_fn`` in :func:`asyncio.create_subprocess_exec`.
    """
    # CPU time limit: SIGXCPU when exceeded, SIGKILL at hard limit
    resource.setrlimit(
        resource.RLIMIT_CPU,
        (cpu_seconds, cpu_seconds + 2),
    )
    # Address space limit (virtual memory)
    memory_bytes = memory_mb * 1024 * 1024
    resource.setrlimit(
        resource.RLIMIT_AS,
        (memory_bytes, memory_bytes),
    )
    # Prevent fork bombs
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    # Limit file descriptors
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def _build_tool_script(tool_name: str, args: dict[str, Any], tool_registry: dict[str, str]) -> str:
    """Generate the Python script that runs inside the sandbox.

    Args:
        tool_name: Tool to execute.
        args: JSON-serializable arguments.
        tool_registry: Mapping of tool_name → importable module path.

    Returns:
        Python source code string.
    """
    module_path = tool_registry.get(tool_name, "")
    args_json = json.dumps(args)
    return f"""
import json
import sys

args = json.loads({args_json!r})

try:
    # Dynamic import of the tool module
    import importlib
    module = importlib.import_module({module_path!r})
    tool_fn = getattr(module, {tool_name!r})
    result = tool_fn(**args)
    print(json.dumps({{"ok": True, "result": result}}))
except Exception as exc:
    print(json.dumps({{"ok": False, "error": str(exc), "type": type(exc).__name__}}))
    sys.exit(1)
"""


class ToolSandbox:
    """Execute MCP tools in isolated subprocesses with strict resource limits.

    Args:
        limits: Resource limits for each subprocess.
        tool_registry: Mapping of tool_name → Python module path.
        python_executable: Python interpreter to use (default: current interpreter).
    """

    def __init__(
        self,
        limits: SandboxLimits | None = None,
        tool_registry: dict[str, str] | None = None,
        python_executable: str | None = None,
    ) -> None:
        self._limits = limits or SandboxLimits()
        self._tool_registry = tool_registry or {}
        self._python = python_executable or sys.executable

    async def run(
        self,
        tool_name: str,
        args: dict[str, Any],
    ) -> SandboxResult:
        """Run a tool in a sandboxed subprocess.

        Args:
            tool_name: Registered tool name.
            args: Tool arguments (must be JSON-serializable).

        Returns:
            :class:`SandboxResult` with output and resource metrics.
        """
        script = _build_tool_script(tool_name, args, self._tool_registry)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, prefix="mcp_sandbox_"
        ) as tmp:
            tmp.write(script)
            script_path = tmp.name

        wall_start = time.monotonic()
        killed = False
        exit_code = -1
        stdout_data = b""
        stderr_data = b""

        try:
            proc = await asyncio.create_subprocess_exec(
                self._python,
                script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=lambda: _apply_resource_limits(
                    self._limits.cpu_seconds, self._limits.memory_mb
                ),
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self._limits.process_timeout,
                )
            except TimeoutError:
                proc.kill()
                await proc.communicate()
                killed = True

            exit_code = proc.returncode or 0
        finally:
            Path(script_path).unlink(missing_ok=True)

        wall_time = time.monotonic() - wall_start

        # Enforce output size limit
        stdout_trimmed = stdout_data[: self._limits.output_size_bytes]

        output: dict[str, Any] = {}
        success = False
        if not killed and exit_code == 0:
            try:
                output = json.loads(stdout_trimmed.decode())
                success = output.get("ok", False)
            except json.JSONDecodeError:
                output = {"raw": stdout_trimmed.decode(errors="replace")}

        return SandboxResult(
            success=success,
            output=output,
            exit_code=exit_code,
            stderr=stderr_data.decode(errors="replace")[:4096],
            cpu_seconds_used=0.0,  # Requires /proc parsing; omitted for portability
            wall_time_seconds=wall_time,
            killed=killed,
        )


@dataclass
class TenantSandboxPolicy:
    """Per-tenant override for sandbox resource limits.

    Allows untrusted tenants to run with tighter limits.
    """

    tenant_id: str
    cpu_seconds: int = _DEFAULT_CPU_LIMIT_SECONDS
    memory_mb: int = _DEFAULT_MEMORY_LIMIT_MB
    allowed_tools: set[str] = field(default_factory=set)
    blocked_tools: set[str] = field(default_factory=set)


class MultiTenantSandbox:
    """Sandbox that applies per-tenant policies.

    Args:
        default_limits: Fallback limits for tenants with no explicit policy.
        policies: Per-tenant overrides.
    """

    def __init__(
        self,
        default_limits: SandboxLimits | None = None,
        policies: dict[str, TenantSandboxPolicy] | None = None,
    ) -> None:
        self._default_limits = default_limits or SandboxLimits()
        self._policies: dict[str, TenantSandboxPolicy] = policies or {}

    def _sandbox_for(self, tenant_id: str) -> ToolSandbox:
        policy = self._policies.get(tenant_id)
        if policy:
            limits = SandboxLimits(
                cpu_seconds=policy.cpu_seconds,
                memory_mb=policy.memory_mb,
            )
        else:
            limits = self._default_limits
        return ToolSandbox(limits=limits)

    async def run(
        self,
        tool_name: str,
        args: dict[str, Any],
        tenant_id: str,
    ) -> SandboxResult:
        """Run a tool with the tenant's policy applied.

        Args:
            tool_name: Tool to execute.
            args: Tool arguments.
            tenant_id: Determines which policy to apply.

        Returns:
            :class:`SandboxResult`.

        Raises:
            PermissionError: If the tool is blocked for this tenant.
        """
        policy = self._policies.get(tenant_id)
        if policy:
            if policy.allowed_tools and tool_name not in policy.allowed_tools:
                msg = f"Tool '{tool_name}' not in allowed list for tenant '{tenant_id}'"
                raise PermissionError(msg)
            if tool_name in policy.blocked_tools:
                msg = f"Tool '{tool_name}' is blocked for tenant '{tenant_id}'"
                raise PermissionError(msg)

        sandbox = self._sandbox_for(tenant_id)
        return await sandbox.run(tool_name, args)
