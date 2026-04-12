"""Tests for MCP node federation patterns.

Uses an in-memory mock of the Redis registry to avoid requiring a live Redis.
"""

from __future__ import annotations

import json
import os
import sys
import time
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from patterns.federation import (  # type: ignore[import-not-found]
    FederatedNode,
    FederationRouter,
    NodeInfo,
    NodeRegistry,
)

# ---------------------------------------------------------------------------
# NodeInfo serialization
# ---------------------------------------------------------------------------

def test_node_info_round_trip() -> None:
    """NodeInfo serializes and deserializes correctly."""
    node = NodeInfo(
        node_id="node-1",
        url="http://node-1:8001",
        tools=["read_file", "write_file"],
        tenant_id="acme",
        metadata={"region": "eu-west-1"},
    )
    restored = NodeInfo.from_json(node.to_json())
    assert restored.node_id == node.node_id
    assert restored.url == node.url
    assert restored.tools == node.tools
    assert restored.tenant_id == node.tenant_id
    assert restored.metadata == node.metadata


def test_node_info_from_json_minimal() -> None:
    """NodeInfo.from_json handles minimal required fields."""
    raw = json.dumps({
        "node_id": "n1",
        "url": "http://localhost:8000",
        "tools": [],
        "tenant_id": "test",
        "registered_at": time.time(),
        "metadata": {},
    })
    node = NodeInfo.from_json(raw)
    assert node.node_id == "n1"
    assert node.tools == []


# ---------------------------------------------------------------------------
# NodeRegistry with mocked Redis
# ---------------------------------------------------------------------------

def _make_mock_registry(live_nodes: list[NodeInfo]) -> NodeRegistry:
    """Create a NodeRegistry backed by a mock Redis client."""
    registry = NodeRegistry.__new__(NodeRegistry)
    registry._redis_url = "redis://mock"
    registry._client = None

    now = time.time()

    async def fake_get_client():
        mock_client = AsyncMock()
        # zremrangebyscore — prune expired (no-op for live nodes)
        mock_client.zremrangebyscore = AsyncMock(return_value=0)
        # zrange — return serialized live nodes
        mock_client.zrange = AsyncMock(
            return_value=[n.to_json() for n in live_nodes]
        )
        mock_client.zadd = AsyncMock(return_value=1)
        mock_client.aclose = AsyncMock()
        return mock_client

    registry._get_client = fake_get_client
    return registry


@pytest.mark.asyncio
async def test_discover_all_nodes() -> None:
    """discover() returns all live nodes."""
    nodes = [
        NodeInfo("n1", "http://n1:8001", ["read_file"], "acme"),
        NodeInfo("n2", "http://n2:8002", ["write_file"], "acme"),
        NodeInfo("n3", "http://n3:8003", ["run_query"], "globex"),
    ]
    registry = _make_mock_registry(nodes)
    result = await registry.discover()
    assert len(result) == 3


@pytest.mark.asyncio
async def test_discover_filters_by_tenant() -> None:
    """discover(tenant_id=...) returns only matching tenant's nodes."""
    nodes = [
        NodeInfo("n1", "http://n1:8001", ["read_file"], "acme"),
        NodeInfo("n2", "http://n2:8002", ["write_file"], "acme"),
        NodeInfo("n3", "http://n3:8003", ["run_query"], "globex"),
    ]
    registry = _make_mock_registry(nodes)
    result = await registry.discover(tenant_id="acme")
    assert len(result) == 2
    assert all(n.tenant_id == "acme" for n in result)


@pytest.mark.asyncio
async def test_find_tool_owner_found() -> None:
    """find_tool_owner returns the correct node for a tool."""
    nodes = [
        NodeInfo("n1", "http://n1:8001", ["read_file"], "acme"),
        NodeInfo("n2", "http://n2:8002", ["write_file"], "acme"),
    ]
    registry = _make_mock_registry(nodes)
    owner = await registry.find_tool_owner("write_file", "acme")
    assert owner is not None
    assert owner.node_id == "n2"


@pytest.mark.asyncio
async def test_find_tool_owner_cross_tenant_returns_none() -> None:
    """find_tool_owner respects tenant isolation."""
    nodes = [
        NodeInfo("n1", "http://n1:8001", ["run_query"], "globex"),
    ]
    registry = _make_mock_registry(nodes)
    owner = await registry.find_tool_owner("run_query", "acme")
    assert owner is None


@pytest.mark.asyncio
async def test_find_tool_owner_not_found() -> None:
    """find_tool_owner returns None when no node owns the tool."""
    registry = _make_mock_registry([])
    owner = await registry.find_tool_owner("nonexistent_tool", "acme")
    assert owner is None


# ---------------------------------------------------------------------------
# FederationRouter
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_router_resolves_url() -> None:
    """FederationRouter.resolve returns the URL of the owning node."""
    nodes = [
        NodeInfo("n1", "http://node-1:8001", ["search_docs"], "acme"),
    ]
    registry = _make_mock_registry(nodes)
    router = FederationRouter(registry)
    url = await router.resolve("search_docs", "acme")
    assert url == "http://node-1:8001"


@pytest.mark.asyncio
async def test_router_raises_on_missing_tool() -> None:
    """FederationRouter.resolve raises LookupError for unknown tools."""
    registry = _make_mock_registry([])
    router = FederationRouter(registry)
    with pytest.raises(LookupError, match="No live node found"):
        await router.resolve("unknown_tool", "acme")


# ---------------------------------------------------------------------------
# FederatedNode heartbeat (lightweight)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_federated_node_registers_on_start() -> None:
    """FederatedNode calls zadd on start."""
    mock_client = AsyncMock()
    mock_client.zadd = AsyncMock(return_value=1)
    mock_client.aclose = AsyncMock()

    with patch("patterns.federation.aioredis.from_url", AsyncMock(return_value=mock_client)):
        node = FederatedNode(
            url="http://test:8001",
            tools=["test_tool"],
            tenant_id="test-tenant",
        )
        await node.start()
        assert mock_client.zadd.called
        # Stop to clean up the heartbeat task
        mock_client.zrange = AsyncMock(return_value=[])
        mock_client.zrem = AsyncMock(return_value=1)
        await node.stop()


@pytest.mark.asyncio
async def test_federated_node_deregisters_on_stop() -> None:
    """FederatedNode removes itself from registry on stop."""
    node = NodeInfo("node-x", "http://test:8001", ["t"], "tenant")
    mock_client = AsyncMock()
    mock_client.zadd = AsyncMock(return_value=1)
    mock_client.zrange = AsyncMock(return_value=[node.to_json()])
    mock_client.zrem = AsyncMock(return_value=1)
    mock_client.aclose = AsyncMock()

    with patch("patterns.federation.aioredis.from_url", AsyncMock(return_value=mock_client)):
        n = FederatedNode(
            url="http://test:8001",
            tools=["t"],
            tenant_id="tenant",
            node_id="node-x",
        )
        await n.start()
        await n.stop()
        assert mock_client.zrem.called
