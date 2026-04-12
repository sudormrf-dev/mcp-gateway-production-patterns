"""Human-in-the-loop demo: agent submits critical tool for approval.

Simulates a full HITL cycle:
  1. Agent requests a critical tool call (delete_file)
  2. Request appears in the pending queue
  3. A simulated "human operator" approves the request
  4. Agent receives the approval and proceeds

Requires: Redis running on localhost:6379

Run::

    redis-server &
    python examples/hitl_demo.py
"""

from __future__ import annotations

import asyncio
import logging
import time

from patterns.human_in_the_loop import (  # type: ignore[import-not-found]
    ApprovalDecision,
    ApprovalStatus,
    HITLGateway,
    HITLQueue,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("mcp.hitl_demo")

REDIS_URL = "redis://localhost:6379"
CRITICAL_TOOLS = {"delete_file", "run_payment", "drop_table", "deploy_to_prod"}


async def simulate_agent(gateway: HITLGateway) -> None:
    """Simulate an agent trying to call various tools."""
    agent_id = "agent-demo-1"
    tenant_id = "acme"

    print("\n=== Agent Tool Calls ===\n")

    # Non-critical tool — instant
    print("Agent: calling 'read_file' (non-critical)...")
    result = await gateway.call_tool(
        "read_file", {"path": "/data/report.csv"}, agent_id, tenant_id
    )
    print(f"  → {result}")

    # Critical tool — requires approval
    print("\nAgent: calling 'delete_file' (CRITICAL — needs human approval)...")
    print("  [Agent suspends and waits for human decision]")

    # This will block until a human decides (or timeout)
    result = await gateway.call_tool(
        "delete_file",
        {"path": "/data/old_backups/2024-01.tar.gz"},
        agent_id,
        tenant_id,
        metadata={"reason": "Freeing disk space", "estimated_size_gb": 12},
    )
    print(f"  → Decision received: {result}")


async def simulate_human_operator(queue: HITLQueue, delay_seconds: float = 2.0) -> None:
    """Simulate a human operator reviewing and approving pending requests."""
    print("\n=== Human Operator Console ===\n")

    # Wait for the agent to enqueue a request
    await asyncio.sleep(delay_seconds)

    # Check pending requests
    pending = await queue.pending("acme")
    if not pending:
        print("  No pending requests found")
        return

    print(f"  Found {len(pending)} pending request(s):")
    for req in pending:
        age_seconds = time.time() - req.created_at
        print(f"  ┌─ Request ID: {req.request_id[:8]}...")
        print(f"  │  Tool:       {req.tool_name}")
        print(f"  │  Args:       {req.args}")
        print(f"  │  Agent:      {req.agent_id}")
        print(f"  │  Metadata:   {req.metadata}")
        print(f"  │  Pending:    {age_seconds:.1f}s")
        print(f"  └─ Expires in: {req.expires_at - time.time():.0f}s")

        # Human approves
        print(f"\n  [Operator] Approving request {req.request_id[:8]}...")
        decision = ApprovalDecision(
            request_id=req.request_id,
            status=ApprovalStatus.APPROVED,
            decided_by="alice@acme.com",
        )
        await queue.decide(decision)
        print("  ✓ Approval sent")


async def simulate_rejection_flow(queue: HITLQueue, gateway: HITLGateway) -> None:
    """Show the rejection path."""
    print("\n=== Rejection Demo ===\n")
    agent_id = "agent-demo-1"
    tenant_id = "acme"

    async def reject_after_delay(delay: float) -> None:
        await asyncio.sleep(delay)
        pending = await queue.pending(tenant_id)
        for req in pending:
            if req.tool_name == "run_payment":
                print("  [Operator] REJECTING payment request: too large amount")
                decision = ApprovalDecision(
                    request_id=req.request_id,
                    status=ApprovalStatus.REJECTED,
                    decided_by="bob@acme.com",
                    rejection_reason="Amount exceeds $10,000 — requires CFO approval",
                )
                await queue.decide(decision)
                break

    # Run agent and operator concurrently
    reject_task = asyncio.create_task(reject_after_delay(1.5))

    print("Agent: calling 'run_payment' $50,000...")
    result = await gateway.call_tool(
        "run_payment",
        {"amount_usd": 50000, "recipient": "vendor-123"},
        agent_id,
        tenant_id,
        metadata={"invoice_id": "INV-2026-0042"},
    )
    print(f"  → {result}")

    await reject_task


async def demo_hitl() -> None:
    """Full HITL demonstration."""
    queue = HITLQueue(redis_url=REDIS_URL)
    gateway = HITLGateway(
        queue=queue,
        critical_tools=CRITICAL_TOOLS,
        approval_timeout=30.0,  # 30s timeout in demo (use 120s+ in prod)
    )

    # Run approval demo
    agent_task = asyncio.create_task(simulate_agent(gateway))
    operator_task = asyncio.create_task(simulate_human_operator(queue, delay_seconds=1.5))

    await asyncio.gather(agent_task, operator_task)

    # Run rejection demo
    await simulate_rejection_flow(queue, gateway)

    await queue.close()
    print("\n=== Demo complete ===")


if __name__ == "__main__":
    try:
        asyncio.run(demo_hitl())
    except ConnectionError as e:
        print(f"\nERROR: Could not connect to Redis — {e}")
        print("Start Redis with: redis-server &")
