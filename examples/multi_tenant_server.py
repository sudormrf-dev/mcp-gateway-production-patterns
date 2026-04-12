"""Complete multi-tenant MCP server with per-tenant tool isolation.

Demonstrates 3 tenants (acme, globex, initech) each with scoped tools,
rate limiting, and audit logging. The server uses FastMCP with a custom
TokenVerifier that reads tenant claims from a JWT-like header.

Run::

    pip install mcp redis
    python examples/multi_tenant_server.py

Then connect with any MCP client to http://localhost:8000/mcp
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
log = logging.getLogger("mcp.multi_tenant")

# ---------------------------------------------------------------------------
# Tenant registry (replace with database in production)
# ---------------------------------------------------------------------------

_TENANTS: dict[str, dict[str, Any]] = {
    "acme": {
        "allowed_tools": {"read_file", "list_directory", "search_docs"},
        "rate_limit_rpm": 60,
        "tier": "standard",
    },
    "globex": {
        "allowed_tools": {"read_file", "list_directory", "search_docs", "write_file"},
        "rate_limit_rpm": 300,
        "tier": "premium",
    },
    "initech": {
        "allowed_tools": {"read_file", "list_directory"},
        "rate_limit_rpm": 20,
        "tier": "free",
    },
}

# Simple in-process rate limiter (use Redis in production)
_rate_limiter: dict[str, list[float]] = {}
_RATE_WINDOW_SECONDS: int = 60


def _check_rate_limit(tenant_id: str, limit_rpm: int) -> bool:
    """Return True if the request is within the rate limit."""
    now = time.time()
    window_start = now - _RATE_WINDOW_SECONDS
    calls = _rate_limiter.get(tenant_id, [])
    # Prune old entries
    calls = [t for t in calls if t > window_start]
    if len(calls) >= limit_rpm:
        return False
    calls.append(now)
    _rate_limiter[tenant_id] = calls
    return True


# ---------------------------------------------------------------------------
# Simple token verifier (demo: token == "tenant:{tenant_id}")
# Replace with real JWT validation in production
# ---------------------------------------------------------------------------


class MultiTenantTokenVerifier(TokenVerifier):
    """Verify tokens in format ``tenant:{tenant_id}`` for demo purposes.

    In production: validate a real JWT, extract tenant_id from claims.
    """

    async def verify_token(self, token: str) -> AccessToken | None:
        """Validate token and return scoped AccessToken or None."""
        if not token.startswith("tenant:"):
            return None
        tenant_id = token.removeprefix("tenant:")
        if tenant_id not in _TENANTS:
            log.warning("Unknown tenant: %s", tenant_id)
            return None

        tenant = _TENANTS[tenant_id]
        limit_rpm = tenant["rate_limit_rpm"]
        if not _check_rate_limit(tenant_id, limit_rpm):
            log.warning("Rate limit exceeded for tenant: %s", tenant_id)
            return None

        return AccessToken(
            token=token,
            client_id=tenant_id,
            scopes=list(tenant["allowed_tools"]),
            expires_at=None,
        )


# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "Multi-Tenant MCP Gateway",
    json_response=True,
    token_verifier=MultiTenantTokenVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl("https://auth.example.com"),
        resource_server_url=AnyHttpUrl("http://localhost:8000"),
        required_scopes=["read_file"],
    ),
)


def _get_tenant_from_context() -> str:
    """Extract tenant_id from the current request context.

    In production FastMCP exposes a lifespan context or request-local storage.
    This is a placeholder showing the pattern.
    """
    return os.environ.get("MCP_TENANT_ID", "unknown")


@mcp.tool()
async def read_file(path: str) -> dict[str, Any]:
    """Read a file from the tenant's scoped directory.

    Args:
        path: Relative file path within the tenant's directory.

    Returns:
        File contents and metadata.
    """
    import pathlib

    tenant_id = _get_tenant_from_context()
    log.info("read_file tenant=%s path=%s", tenant_id, path)

    # Scope to tenant directory to prevent path traversal
    tenant_root = pathlib.Path(f"/data/tenants/{tenant_id}")
    target = (tenant_root / path).resolve()

    # Verify the resolved path is still inside the tenant root
    if not str(target).startswith(str(tenant_root)):
        return {"error": "Path traversal not allowed"}

    if not target.exists():
        return {"error": f"File not found: {path}"}

    content = target.read_text(encoding="utf-8")
    return {
        "path": path,
        "content": content,
        "size_bytes": target.stat().st_size,
        "tenant_id": tenant_id,
    }


@mcp.tool()
async def list_directory(path: str = ".") -> dict[str, Any]:
    """List directory contents within the tenant's scope.

    Args:
        path: Relative directory path (default: tenant root).

    Returns:
        Directory listing with file metadata.
    """
    import pathlib

    tenant_id = _get_tenant_from_context()
    tenant_root = pathlib.Path(f"/data/tenants/{tenant_id}")
    target = (tenant_root / path).resolve()

    if not str(target).startswith(str(tenant_root)):
        return {"error": "Path traversal not allowed"}

    if not target.is_dir():
        return {"error": f"Not a directory: {path}"}

    entries = [
        {
            "name": item.name,
            "type": "dir" if item.is_dir() else "file",
            "size_bytes": item.stat().st_size if item.is_file() else 0,
        }
        for item in target.iterdir()
    ]

    return {"path": path, "entries": entries, "tenant_id": tenant_id}


@mcp.tool()
async def search_docs(query: str, max_results: int = 10) -> dict[str, Any]:
    """Search indexed documents for this tenant.

    Args:
        query: Search query string.
        max_results: Maximum number of results (1-50).

    Returns:
        Matching documents with relevance scores.
    """
    tenant_id = _get_tenant_from_context()
    log.info("search_docs tenant=%s query=%r", tenant_id, query)

    max_results = max(1, min(50, max_results))

    # Placeholder: in production, call a vector store scoped to the tenant
    return {
        "query": query,
        "results": [
            {"doc_id": f"{tenant_id}/doc_{i}", "score": 0.9 - i * 0.05, "snippet": f"...{query}..."}
            for i in range(min(3, max_results))
        ],
        "tenant_id": tenant_id,
    }


@mcp.tool()
async def write_file(path: str, content: str) -> dict[str, Any]:
    """Write content to a file (premium tier only).

    Args:
        path: Relative file path within the tenant's directory.
        content: Content to write.

    Returns:
        Write confirmation.
    """
    import pathlib

    tenant_id = _get_tenant_from_context()
    tenant = _TENANTS.get(tenant_id, {})

    if "write_file" not in tenant.get("allowed_tools", set()):
        return {"error": "write_file requires premium tier"}

    tenant_root = pathlib.Path(f"/data/tenants/{tenant_id}")
    target = (tenant_root / path).resolve()

    if not str(target).startswith(str(tenant_root)):
        return {"error": "Path traversal not allowed"}

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    log.info("write_file tenant=%s path=%s bytes=%d", tenant_id, path, len(content))

    return {"path": path, "bytes_written": len(content), "tenant_id": tenant_id}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    log.info("Starting multi-tenant MCP server on port %d", port)
    log.info("Tenants: %s", list(_TENANTS.keys()))
    log.info("Test with: MCP_TENANT_ID=acme token=tenant:acme")
    uvicorn.run(mcp.get_asgi_app(), host="0.0.0.0", port=port)
