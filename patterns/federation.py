"""MCP node federation via Redis auto-discovery.

Multiple MCP servers register themselves in Redis and discover each other
automatically. The federation layer routes tool calls to the correct node
without any static configuration.

Pattern:
    Node starts → registers in Redis with TTL → health loop keeps it alive
    Gateway queries Redis → discovers all live nodes → routes requests

Usage::

    # Start a federated node
    node = FederatedNode("node-1", tools=my_tools, redis_url="redis://localhost:6379")
    await node.start()

    # Discover all live nodes
    registry = NodeRegistry(redis_url="redis://localhost:6379")
    nodes = await registry.discover()
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import redis.asyncio as aioredis

_REGISTRY_KEY: str = "mcp:nodes"
_NODE_TTL_SECONDS: int = 30
_HEARTBEAT_INTERVAL: int = 10
_DISCOVERY_TIMEOUT: float = 2.0


@dataclass
class NodeInfo:
    """Metadata for a registered MCP node."""

    node_id: str
    url: str
    tools: list[str]
    tenant_id: str
    registered_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to JSON for Redis storage."""
        return json.dumps(
            {
                "node_id": self.node_id,
                "url": self.url,
                "tools": self.tools,
                "tenant_id": self.tenant_id,
                "registered_at": self.registered_at,
                "metadata": self.metadata,
            }
        )

    @classmethod
    def from_json(cls, data: str) -> NodeInfo:
        """Deserialize from Redis JSON."""
        obj = json.loads(data)
        return cls(**obj)


class NodeRegistry:
    """Read-only view of the live node registry in Redis.

    Uses a Redis sorted set keyed by ``mcp:nodes``. Each member is a JSON-encoded
    :class:`NodeInfo`; the score is the expiry timestamp so stale entries can be
    pruned with a single ``ZRANGEBYSCORE`` call.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379") -> None:
        self._redis_url = redis_url
        self._client: aioredis.Redis[Any] | None = None

    async def _get_client(self) -> aioredis.Redis[Any]:
        if self._client is None:
            self._client = await aioredis.from_url(self._redis_url, decode_responses=True)
        return self._client

    async def discover(self, tenant_id: str | None = None) -> list[NodeInfo]:
        """Return all live nodes, optionally filtered by tenant.

        Args:
            tenant_id: If provided, only return nodes for this tenant.

        Returns:
            List of live :class:`NodeInfo` objects, sorted by registration time.
        """
        client = await self._get_client()
        now = time.time()

        # Remove expired entries first
        await client.zremrangebyscore(_REGISTRY_KEY, "-inf", now)

        # Fetch all remaining entries
        raw_entries: list[str] = await client.zrange(_REGISTRY_KEY, 0, -1)

        nodes = []
        for raw in raw_entries:
            try:
                node = NodeInfo.from_json(raw)
                if tenant_id is None or node.tenant_id == tenant_id:
                    nodes.append(node)
            except (json.JSONDecodeError, KeyError):
                continue

        return nodes

    async def find_tool_owner(self, tool_name: str, tenant_id: str) -> NodeInfo | None:
        """Find the node that owns a given tool for a tenant.

        Args:
            tool_name: The tool to locate.
            tenant_id: Tenant scope for the lookup.

        Returns:
            The owning :class:`NodeInfo`, or ``None`` if not found.
        """
        nodes = await self.discover(tenant_id=tenant_id)
        for node in nodes:
            if tool_name in node.tools:
                return node
        return None

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._client:
            await self._client.close()
            self._client = None


class FederatedNode:
    """An MCP node that self-registers into the Redis federation.

    Args:
        node_id: Unique identifier for this node (default: random UUID).
        url: HTTP URL where this node's MCP server is reachable.
        tools: List of tool names this node provides.
        tenant_id: Tenant this node belongs to.
        redis_url: Redis connection URL.
        metadata: Arbitrary extra metadata (e.g. GPU type, region).
    """

    def __init__(
        self,
        url: str,
        tools: list[str],
        tenant_id: str,
        node_id: str | None = None,
        redis_url: str = "redis://localhost:6379",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.info = NodeInfo(
            node_id=node_id or str(uuid.uuid4()),
            url=url,
            tools=tools,
            tenant_id=tenant_id,
            metadata=metadata or {},
        )
        self._redis_url = redis_url
        self._client: aioredis.Redis[Any] | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Register node and start heartbeat loop."""
        self._client = await aioredis.from_url(self._redis_url, decode_responses=True)
        await self._register()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self) -> None:
        """Deregister node and stop heartbeat."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        if self._client:
            await self._deregister()
            await self._client.close()

    async def _register(self) -> None:
        """Add this node to the sorted set with TTL as score."""
        if self._client is None:
            msg = "Redis client not initialised"
            raise RuntimeError(msg)
        expiry = time.time() + _NODE_TTL_SECONDS
        await self._client.zadd(
            _REGISTRY_KEY,
            {self.info.to_json(): expiry},
        )

    async def _deregister(self) -> None:
        """Remove this node from the sorted set."""
        if self._client is None:
            msg = "Redis client not initialised"
            raise RuntimeError(msg)
        # Score-based removal: re-fetch all, filter out ours
        raw_entries: list[str] = await self._client.zrange(_REGISTRY_KEY, 0, -1)
        for raw in raw_entries:
            try:
                node = NodeInfo.from_json(raw)
                if node.node_id == self.info.node_id:
                    await self._client.zrem(_REGISTRY_KEY, raw)
                    break
            except (json.JSONDecodeError, KeyError):
                continue

    async def _heartbeat_loop(self) -> None:
        """Refresh the TTL score every ``_HEARTBEAT_INTERVAL`` seconds."""
        while True:
            await asyncio.sleep(_HEARTBEAT_INTERVAL)
            try:
                await self._register()
            except Exception:
                # Best-effort: don't crash the heartbeat on transient Redis errors
                pass


class FederationRouter:
    """Route incoming tool calls to the correct federated node.

    Args:
        registry: The :class:`NodeRegistry` to use for discovery.

    Example::

        router = FederationRouter(NodeRegistry())
        target_url = await router.resolve("read_file", tenant_id="acme")
        # → "http://node-3:8001"
    """

    def __init__(self, registry: NodeRegistry) -> None:
        self._registry = registry

    async def resolve(self, tool_name: str, tenant_id: str) -> str:
        """Resolve a tool call to the owning node's URL.

        Args:
            tool_name: Tool to route.
            tenant_id: Tenant scope.

        Returns:
            HTTP URL of the owning node.

        Raises:
            LookupError: If no live node owns this tool for the tenant.
        """
        node = await self._registry.find_tool_owner(tool_name, tenant_id)
        if node is None:
            msg = f"No live node found for tool '{tool_name}' in tenant '{tenant_id}'"
            raise LookupError(msg)
        return node.url
