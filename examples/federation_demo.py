"""Redis federation demo: auto-discovery of MCP nodes.

Shows 3 nodes registering themselves into Redis, a router discovering them,
and tool call routing to the correct node without static config.

Requires: Redis running on localhost:6379

Run::

    redis-server &
    python examples/federation_demo.py
"""

from __future__ import annotations

import asyncio
import logging

from patterns.federation import (  # type: ignore[import-not-found]
    FederatedNode,
    FederationRouter,
    NodeRegistry,
)

log = logging.getLogger("mcp.federation_demo")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

REDIS_URL = "redis://localhost:6379"


async def demo_federation() -> None:
    """Demonstrate 3-node federation with auto-discovery routing."""

    # --- 1. Start 3 federated nodes for the 'acme' tenant ---
    node_a = FederatedNode(
        url="http://node-a:8001",
        tools=["read_file", "list_directory"],
        tenant_id="acme",
        node_id="node-a",
        redis_url=REDIS_URL,
    )
    node_b = FederatedNode(
        url="http://node-b:8002",
        tools=["search_docs", "write_file"],
        tenant_id="acme",
        node_id="node-b",
        redis_url=REDIS_URL,
    )
    node_c = FederatedNode(
        url="http://node-c:8003",
        tools=["run_query", "export_csv"],
        tenant_id="globex",  # Different tenant
        node_id="node-c",
        redis_url=REDIS_URL,
        metadata={"region": "eu-west-1", "gpu": "RTX 5080"},
    )

    print("\n=== MCP Federation Demo ===\n")
    print("Starting 3 nodes...")

    await asyncio.gather(node_a.start(), node_b.start(), node_c.start())
    print("✓ node-a: tools=[read_file, list_directory] tenant=acme")
    print("✓ node-b: tools=[search_docs, write_file]  tenant=acme")
    print("✓ node-c: tools=[run_query, export_csv]    tenant=globex")

    # Small delay to ensure registration propagates
    await asyncio.sleep(0.1)

    # --- 2. Discover all nodes ---
    registry = NodeRegistry(redis_url=REDIS_URL)
    router = FederationRouter(registry)

    all_nodes = await registry.discover()
    print(f"\nDiscovered {len(all_nodes)} live node(s):")
    for node in all_nodes:
        print(f"  {node.node_id} @ {node.url} tools={node.tools} tenant={node.tenant_id}")

    # --- 3. Route tool calls ---
    print("\nRouting tool calls:")

    for tool, tenant in [
        ("read_file", "acme"),
        ("write_file", "acme"),
        ("run_query", "globex"),
    ]:
        try:
            url = await router.resolve(tool, tenant)
            print(f"  {tool!r:20s} (tenant={tenant!r}) → {url}")
        except LookupError as e:
            print(f"  {tool!r:20s} (tenant={tenant!r}) → ERROR: {e}")

    # --- 4. Cross-tenant isolation ---
    print("\nCross-tenant isolation:")
    try:
        url = await router.resolve("run_query", "acme")  # globex tool, wrong tenant
        print(f"  FAIL: should not have found {url}")
    except LookupError:
        print("  ✓ 'run_query' not accessible from tenant 'acme' (correct)")

    # --- 5. Node failure simulation ---
    print("\nSimulating node-b failure...")
    await node_b.stop()
    await asyncio.sleep(0.1)

    remaining = await registry.discover(tenant_id="acme")
    print(f"After node-b stops: {len(remaining)} acme node(s) remaining")
    for node in remaining:
        print(f"  {node.node_id} @ {node.url}")

    try:
        await router.resolve("write_file", "acme")
        print("  FAIL: write_file should not be routable after node-b stopped")
    except LookupError:
        print("  ✓ 'write_file' correctly unavailable after node-b failure")

    # --- 6. Node re-join ---
    print("\nNode-b rejoining...")
    node_b_v2 = FederatedNode(
        url="http://node-b-v2:8004",  # New address
        tools=["write_file", "search_docs"],
        tenant_id="acme",
        node_id="node-b",
        redis_url=REDIS_URL,
    )
    await node_b_v2.start()
    await asyncio.sleep(0.1)

    url = await router.resolve("write_file", "acme")
    print(f"  ✓ write_file now routes to: {url}")

    # --- Cleanup ---
    await asyncio.gather(node_a.stop(), node_b_v2.stop(), node_c.stop())
    await registry.close()

    print("\n=== Demo complete ===")


if __name__ == "__main__":
    try:
        asyncio.run(demo_federation())
    except ConnectionError as e:
        print(f"\nERROR: Could not connect to Redis — {e}")
        print("Start Redis with: redis-server &")
