"""Tests for the Zero-Trust gateway patterns."""

from __future__ import annotations

import os
import sys
import time
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from patterns.zero_trust_gateway import (  # type: ignore[import-not-found]
    AgentIdentity,
    EnvSecretStore,
    GatewayRequest,
    InMemoryTokenStore,
    OAuthToken,
    OAuthTokenInjector,
    ZeroTrustGateway,
    _ClientCredentials,
)

# ---------------------------------------------------------------------------
# InMemoryTokenStore
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_store_miss_on_empty() -> None:
    store = InMemoryTokenStore()
    result = await store.get("acme", ["mcp:read"])
    assert result is None


@pytest.mark.asyncio
async def test_token_store_returns_valid_token() -> None:
    store = InMemoryTokenStore()
    token = OAuthToken(
        access_token="tok-123",
        token_type="Bearer",
        expires_at=time.time() + 900,
        scopes=["mcp:read"],
        tenant_id="acme",
    )
    await store.put(token)
    result = await store.get("acme", ["mcp:read"])
    assert result is not None
    assert result.access_token == "tok-123"


@pytest.mark.asyncio
async def test_token_store_rejects_expired_token() -> None:
    store = InMemoryTokenStore()
    expired = OAuthToken(
        access_token="old-tok",
        token_type="Bearer",
        expires_at=time.time() - 1,  # already expired
        scopes=["mcp:read"],
        tenant_id="acme",
    )
    await store.put(expired)
    result = await store.get("acme", ["mcp:read"])
    assert result is None


def test_token_is_valid() -> None:
    """OAuthToken.is_valid() returns True when not about to expire."""
    token = OAuthToken("t", "Bearer", time.time() + 500, ["r"], "t1")
    assert token.is_valid() is True


def test_token_is_invalid_near_expiry() -> None:
    """OAuthToken.is_valid() returns False within the 60s buffer."""
    token = OAuthToken("t", "Bearer", time.time() + 30, ["r"], "t1")
    assert token.is_valid() is False


# ---------------------------------------------------------------------------
# EnvSecretStore
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_env_secret_store_with_preloaded_credentials() -> None:
    store = EnvSecretStore(
        credentials={
            "acme": _ClientCredentials(
                client_id="cid",
                client_secret="csec",
                token_url="https://auth.acme.com/token",
            )
        }
    )
    cid, csec, url = await store.get_client_credentials("acme")
    assert cid == "cid"
    assert csec == "csec"
    assert url == "https://auth.acme.com/token"


@pytest.mark.asyncio
async def test_env_secret_store_raises_for_missing_tenant() -> None:
    store = EnvSecretStore()
    with pytest.raises(KeyError):
        await store.get_client_credentials("nonexistent")


# ---------------------------------------------------------------------------
# OAuthTokenInjector
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_injector_uses_cached_token() -> None:
    """Token injector returns cached token without calling the OAuth endpoint."""
    store = InMemoryTokenStore()
    cached = OAuthToken(
        access_token="cached-token",
        token_type="Bearer",
        expires_at=time.time() + 900,
        scopes=["mcp:read"],
        tenant_id="acme",
    )
    await store.put(cached)

    mock_http = AsyncMock()
    secret_store = EnvSecretStore(
        credentials={"acme": _ClientCredentials("cid", "csec", "https://auth.example.com/token")}
    )
    injector = OAuthTokenInjector(store, secret_store, http_client=mock_http)

    token = await injector.get_token("acme", ["mcp:read"])
    assert token.access_token == "cached-token"
    mock_http.post.assert_not_called()


@pytest.mark.asyncio
async def test_injector_fetches_on_cache_miss() -> None:
    """Token injector fetches a new token when cache is empty."""
    store = InMemoryTokenStore()
    mock_http = AsyncMock()
    mock_response = AsyncMock()
    mock_response.raise_for_status = AsyncMock()
    from unittest.mock import MagicMock

    mock_response.json = MagicMock(
        return_value={
            "access_token": "fresh-token",
            "expires_in": 900,
            "scope": "mcp:read",
        }
    )
    mock_http.post.return_value = mock_response

    secret_store = EnvSecretStore(
        credentials={"acme": _ClientCredentials("cid", "csec", "https://auth.example.com/token")}
    )
    injector = OAuthTokenInjector(store, secret_store, http_client=mock_http)

    token = await injector.get_token("acme", ["mcp:read"])
    assert token.access_token == "fresh-token"
    mock_http.post.assert_called_once()


# ---------------------------------------------------------------------------
# ZeroTrustGateway
# ---------------------------------------------------------------------------


def _make_identity(
    scopes: list[str] | None = None,
    tenant: str = "acme",
    agent: str = "agent-1",
) -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent,
        tenant_id=tenant,
        scopes=scopes or ["mcp:tools"],
        expires_at=time.time() + 3600,
    )


@pytest.mark.asyncio
async def test_gateway_rejects_missing_scope() -> None:
    """Gateway raises PermissionError if agent lacks required scope."""
    store = InMemoryTokenStore()
    secret_store = EnvSecretStore()
    gateway = ZeroTrustGateway(store, secret_store)

    identity = _make_identity(scopes=["mcp:read"])  # missing mcp:admin
    request = GatewayRequest(
        method="POST",
        url="http://internal:8001/mcp",
        required_scopes=["mcp:admin"],
    )

    with pytest.raises(PermissionError, match="lacks scopes"):
        await gateway.forward(request, identity)


@pytest.mark.asyncio
async def test_gateway_strips_auth_header() -> None:
    """Gateway replaces any existing Authorization header with a fresh token."""
    store = InMemoryTokenStore()
    # Pre-populate cache so no HTTP call needed
    await store.put(OAuthToken("new-tok", "Bearer", time.time() + 900, ["mcp:tools"], "acme"))

    mock_http = AsyncMock()
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.content = b'{"ok": true}'
    mock_response.json.return_value = {"ok": True}
    mock_response.headers = {}
    mock_http.request.return_value = mock_response

    secret_store = EnvSecretStore(
        credentials={"acme": _ClientCredentials("c", "s", "https://auth.example.com")}
    )
    gateway = ZeroTrustGateway(store, secret_store, http_client=mock_http)

    identity = _make_identity(scopes=["mcp:tools"])
    request = GatewayRequest(
        method="POST",
        url="http://internal:8001/mcp",
        headers={"Authorization": "Bearer old-leaked-token"},
        required_scopes=["mcp:tools"],
        tenant_id="acme",
    )

    response = await gateway.forward(request, identity)
    assert response.status_code == 200

    # Verify the Authorization header sent to upstream is NOT the old one
    call_kwargs = mock_http.request.call_args
    headers_sent = (
        call_kwargs.kwargs.get("headers", {}) or call_kwargs.args[2] if call_kwargs.args else {}
    )
    auth_sent = call_kwargs.kwargs.get("headers", {}).get("Authorization", "")
    assert "old-leaked-token" not in auth_sent
    assert "new-tok" in auth_sent


@pytest.mark.asyncio
async def test_gateway_injects_tenant_header() -> None:
    """Gateway adds X-Tenant-ID and X-Agent-ID headers."""
    store = InMemoryTokenStore()
    await store.put(OAuthToken("tok", "Bearer", time.time() + 900, ["mcp:tools"], "acme"))

    mock_http = AsyncMock()
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.content = b"{}"
    mock_response.json.return_value = {}
    mock_response.headers = {}
    mock_http.request.return_value = mock_response

    secret_store = EnvSecretStore(
        credentials={"acme": _ClientCredentials("c", "s", "https://auth.example.com")}
    )
    gateway = ZeroTrustGateway(store, secret_store, http_client=mock_http)
    identity = _make_identity(scopes=["mcp:tools"], tenant="acme", agent="my-agent")

    await gateway.forward(
        GatewayRequest("POST", "http://svc:8000", required_scopes=["mcp:tools"], tenant_id="acme"),
        identity,
    )

    headers_sent = mock_http.request.call_args.kwargs.get("headers", {})
    assert headers_sent.get("X-Tenant-ID") == "acme"
    assert headers_sent.get("X-Agent-ID") == "my-agent"
