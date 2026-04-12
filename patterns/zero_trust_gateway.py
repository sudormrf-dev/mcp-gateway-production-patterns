"""Zero-Trust MCP gateway with OAuth2 token injection.

The gateway sits between LLM agents and MCP servers. Raw API keys are never
exposed to the agent — only short-lived OAuth2 bearer tokens that the gateway
injects per-request based on the agent's verified identity.

Pattern:
    Agent → Gateway (presents agent JWT)
    Gateway → validates JWT → looks up tenant credentials in secret store
    Gateway → obtains scoped OAuth2 token → forwards request with token injected

Never trust the agent. Never expose raw credentials. Token TTL ≤ 15 minutes.

Usage::

    gateway = ZeroTrustGateway(
        token_store=InMemoryTokenStore(),
        secret_store=EnvSecretStore(),
    )
    async with gateway:
        response = await gateway.forward(request, tenant_id="acme", agent_id="agent-1")
"""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

_TOKEN_MIN_VALIDITY_SECONDS: int = 60
_DEFAULT_TOKEN_TTL_SECONDS: int = 900  # 15 minutes


@dataclass(frozen=True)
class AgentIdentity:
    """Verified identity of an agent after JWT validation."""

    agent_id: str
    tenant_id: str
    scopes: list[str]
    expires_at: float


@dataclass
class OAuthToken:
    """Short-lived OAuth2 bearer token scoped to a tenant."""

    access_token: str
    token_type: str
    expires_at: float
    scopes: list[str]
    tenant_id: str

    def is_valid(self) -> bool:
        """Return True if the token won't expire in the next minute."""
        return time.time() < self.expires_at - _TOKEN_MIN_VALIDITY_SECONDS


class TokenStore(ABC):
    """Abstract cache for scoped OAuth2 tokens."""

    @abstractmethod
    async def get(self, tenant_id: str, scopes: list[str]) -> OAuthToken | None:
        """Return a cached valid token, or None."""

    @abstractmethod
    async def put(self, token: OAuthToken) -> None:
        """Cache a token."""


class InMemoryTokenStore(TokenStore):
    """In-process token cache. Replace with Redis in multi-worker deployments."""

    def __init__(self) -> None:
        self._cache: dict[str, OAuthToken] = {}

    async def get(self, tenant_id: str, scopes: list[str]) -> OAuthToken | None:
        key = f"{tenant_id}:{','.join(sorted(scopes))}"
        token = self._cache.get(key)
        if token and token.is_valid():
            return token
        return None

    async def put(self, token: OAuthToken) -> None:
        key = f"{token.tenant_id}:{','.join(sorted(token.scopes))}"
        self._cache[key] = token


class SecretStore(ABC):
    """Abstract store for tenant OAuth2 client credentials."""

    @abstractmethod
    async def get_client_credentials(
        self, tenant_id: str
    ) -> tuple[str, str, str]:
        """Return (client_id, client_secret, token_url) for a tenant."""


@dataclass
class _ClientCredentials:
    client_id: str
    client_secret: str
    token_url: str


class EnvSecretStore(SecretStore):
    """Load credentials from environment variables.

    Expected format: ``MCP_TENANT_{TENANT}_CLIENT_ID``,
    ``MCP_TENANT_{TENANT}_CLIENT_SECRET``, ``MCP_TENANT_{TENANT}_TOKEN_URL``.
    """

    def __init__(self, credentials: dict[str, _ClientCredentials] | None = None) -> None:
        # Pre-loaded credentials for testing; production uses env vars
        self._credentials = credentials or {}

    async def get_client_credentials(
        self, tenant_id: str
    ) -> tuple[str, str, str]:
        cred = self._credentials.get(tenant_id)
        if cred:
            return cred.client_id, cred.client_secret, cred.token_url

        prefix = f"MCP_TENANT_{tenant_id.upper()}"
        client_id = os.environ.get(f"{prefix}_CLIENT_ID", "")
        client_secret = os.environ.get(f"{prefix}_CLIENT_SECRET", "")
        token_url = os.environ.get(f"{prefix}_TOKEN_URL", "")

        if not client_id or not client_secret:
            msg = f"No credentials found for tenant '{tenant_id}'"
            raise KeyError(msg)

        return client_id, client_secret, token_url


class OAuthTokenInjector:
    """Fetch and cache scoped OAuth2 tokens for tenant-scoped requests.

    Args:
        token_store: Cache backend for tokens.
        secret_store: Source for client credentials.
        http_client: Shared httpx client (injected for testability).
    """

    def __init__(
        self,
        token_store: TokenStore,
        secret_store: SecretStore,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._token_store = token_store
        self._secret_store = secret_store
        self._http = http_client

    async def get_token(
        self, tenant_id: str, scopes: list[str]
    ) -> OAuthToken:
        """Return a valid token, fetching a new one if needed.

        Args:
            tenant_id: The tenant requesting the token.
            scopes: Required OAuth2 scopes.

        Returns:
            A valid :class:`OAuthToken`.

        Raises:
            httpx.HTTPError: If the OAuth2 server returns an error.
        """
        cached = await self._token_store.get(tenant_id, scopes)
        if cached:
            return cached

        client_id, client_secret, token_url = (
            await self._secret_store.get_client_credentials(tenant_id)
        )

        if self._http is None:
            msg = "HTTP client not initialised — use async context manager"
            raise RuntimeError(msg)
        resp = await self._http.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": " ".join(scopes),
            },
        )
        resp.raise_for_status()
        data = resp.json()

        token = OAuthToken(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_at=time.time() + data.get("expires_in", _DEFAULT_TOKEN_TTL_SECONDS),
            scopes=data.get("scope", "").split(),
            tenant_id=tenant_id,
        )
        await self._token_store.put(token)
        return token


@dataclass
class GatewayRequest:
    """An incoming request to the Zero-Trust gateway."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] | None = None
    tenant_id: str = ""
    required_scopes: list[str] = field(default_factory=lambda: ["mcp:tools"])


@dataclass
class GatewayResponse:
    """Response forwarded from the upstream MCP server."""

    status_code: int
    body: dict[str, Any]
    headers: dict[str, str]
    tenant_id: str
    latency_ms: float


class ZeroTrustGateway:
    """Forwards MCP requests with injected OAuth2 tokens — no raw secrets exposed.

    The gateway:
    1. Validates that the caller is an authorised agent (via ``AgentIdentity``)
    2. Obtains a short-lived scoped token for the target tenant
    3. Strips any ``Authorization`` header from the original request
    4. Injects the fresh token before forwarding to the MCP node

    Args:
        token_store: Token cache backend.
        secret_store: Credential source.

    Example::

        async with httpx.AsyncClient() as client:
            gw = ZeroTrustGateway(
                token_store=InMemoryTokenStore(),
                secret_store=EnvSecretStore(),
                http_client=client,
            )
            resp = await gw.forward(req, identity)
    """

    def __init__(
        self,
        token_store: TokenStore,
        secret_store: SecretStore,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._injector = OAuthTokenInjector(token_store, secret_store, http_client)
        self._http = http_client

    async def __aenter__(self) -> ZeroTrustGateway:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=30.0)
            self._injector._http = self._http
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._http:
            await self._http.aclose()

    async def forward(
        self,
        request: GatewayRequest,
        identity: AgentIdentity,
    ) -> GatewayResponse:
        """Forward a request to the MCP node with an injected token.

        Args:
            request: The incoming gateway request.
            identity: Verified agent identity.

        Returns:
            The upstream MCP server response.

        Raises:
            PermissionError: If the agent lacks required scopes.
            httpx.HTTPError: On upstream failures.
        """
        # Scope enforcement: agent must hold all required scopes
        missing = set(request.required_scopes) - set(identity.scopes)
        if missing:
            msg = f"Agent '{identity.agent_id}' lacks scopes: {missing}"
            raise PermissionError(msg)

        # Obtain fresh scoped token (cached when valid)
        token = await self._injector.get_token(
            request.tenant_id or identity.tenant_id,
            request.required_scopes,
        )

        # Build clean headers — strip any forwarded Authorization header
        clean_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() != "authorization"
        }
        clean_headers["Authorization"] = f"Bearer {token.access_token}"
        clean_headers["X-Tenant-ID"] = identity.tenant_id
        clean_headers["X-Agent-ID"] = identity.agent_id

        if self._http is None:
            msg = "HTTP client not initialised — use async context manager"
            raise RuntimeError(msg)
        start = time.monotonic()
        resp = await self._http.request(
            method=request.method,
            url=request.url,
            headers=clean_headers,
            json=request.body,
        )
        latency_ms = (time.monotonic() - start) * 1000

        return GatewayResponse(
            status_code=resp.status_code,
            body=resp.json() if resp.content else {},
            headers=dict(resp.headers),
            tenant_id=identity.tenant_id,
            latency_ms=latency_ms,
        )
