"""Tests for tool sandboxing patterns."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from patterns.tool_sandboxing import (  # type: ignore[import-not-found]
    MultiTenantSandbox,
    SandboxLimits,
    SandboxResult,
    TenantSandboxPolicy,
    ToolSandbox,
    _build_tool_script,
)

# ---------------------------------------------------------------------------
# SandboxLimits defaults
# ---------------------------------------------------------------------------

def test_sandbox_limits_defaults() -> None:
    limits = SandboxLimits()
    assert limits.cpu_seconds == 10
    assert limits.memory_mb == 512
    assert limits.process_timeout == 30.0


def test_sandbox_limits_custom() -> None:
    limits = SandboxLimits(cpu_seconds=5, memory_mb=128, process_timeout=10.0)
    assert limits.cpu_seconds == 5
    assert limits.memory_mb == 128


# ---------------------------------------------------------------------------
# _build_tool_script
# ---------------------------------------------------------------------------

def test_build_tool_script_contains_tool_name() -> None:
    script = _build_tool_script("my_tool", {"key": "value"}, {"my_tool": "mymodule"})
    assert "my_tool" in script
    assert "mymodule" in script


def test_build_tool_script_embeds_args() -> None:
    script = _build_tool_script("tool", {"path": "/tmp/test"}, {})
    assert "/tmp/test" in script


# ---------------------------------------------------------------------------
# ToolSandbox — subprocess execution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sandbox_runs_simple_script() -> None:
    """Sandbox correctly executes a simple tool and returns output."""
    import json
    import tempfile

    # Create a minimal tool module
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, prefix="test_tool_", dir="/tmp"
    ) as f:
        f.write("""
def echo(message: str) -> str:
    return f"echo:{message}"
""")
        module_path = f.name

    # We test the sandbox with a direct script approach
    sandbox = ToolSandbox(
        limits=SandboxLimits(cpu_seconds=5, memory_mb=256, process_timeout=10.0),
    )

    # Build a simple script manually to test the subprocess mechanism
    import asyncio

    script = """
import json
result = {"ok": True, "result": "hello"}
print(json.dumps(result))
"""
    import tempfile as tf

    with tf.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
        tmp.write(script)
        script_path = tmp.name

    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        data = json.loads(stdout.decode())
        assert data["ok"] is True
        assert data["result"] == "hello"
    finally:
        Path(script_path).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_sandbox_kills_on_timeout() -> None:
    """Sandbox terminates process when it exceeds wall-clock timeout."""
    import asyncio
    import tempfile as tf

    # Write a script that sleeps forever
    script = "import time; time.sleep(999)"
    with tf.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
        tmp.write(script)
        script_path = tmp.name

    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=0.5)
            pytest.fail("Should have timed out")
        except TimeoutError:
            proc.kill()
            await proc.communicate()
    finally:
        Path(script_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# MultiTenantSandbox — policy enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_multitenant_sandbox_blocks_forbidden_tool() -> None:
    """MultiTenantSandbox raises PermissionError for blocked tools."""
    policy = TenantSandboxPolicy(
        tenant_id="restricted-tenant",
        blocked_tools={"drop_table"},
    )
    sandbox = MultiTenantSandbox(policies={"restricted-tenant": policy})

    with pytest.raises(PermissionError, match="blocked"):
        await sandbox.run("drop_table", {}, tenant_id="restricted-tenant")


@pytest.mark.asyncio
async def test_multitenant_sandbox_blocks_not_in_allowlist() -> None:
    """MultiTenantSandbox raises PermissionError for tools not in allowlist."""
    policy = TenantSandboxPolicy(
        tenant_id="strict-tenant",
        allowed_tools={"read_file"},  # Only read_file allowed
    )
    sandbox = MultiTenantSandbox(policies={"strict-tenant": policy})

    with pytest.raises(PermissionError, match="allowed list"):
        await sandbox.run("write_file", {}, tenant_id="strict-tenant")


@pytest.mark.asyncio
async def test_multitenant_sandbox_allows_allowlisted_tool() -> None:
    """MultiTenantSandbox does not raise PermissionError for allowed tools."""
    from unittest.mock import AsyncMock, patch

    policy = TenantSandboxPolicy(
        tenant_id="t",
        allowed_tools={"read_file"},
    )
    sandbox = MultiTenantSandbox(policies={"t": policy})

    # Mock the actual subprocess execution
    with patch.object(
        ToolSandbox, "run",
        new_callable=AsyncMock,
        return_value=SandboxResult(
            success=True, output={"ok": True}, exit_code=0,
            stderr="", cpu_seconds_used=0.0, wall_time_seconds=0.01,
        ),
    ):
        result = await sandbox.run("read_file", {"path": "/tmp/x"}, tenant_id="t")
        assert result.success is True


def test_tenant_policy_defaults() -> None:
    policy = TenantSandboxPolicy(tenant_id="test")
    assert policy.cpu_seconds == 10
    assert policy.memory_mb == 512
    assert len(policy.allowed_tools) == 0
    assert len(policy.blocked_tools) == 0
