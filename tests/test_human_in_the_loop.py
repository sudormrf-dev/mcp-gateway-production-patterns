"""Tests for the HITL approval queue patterns."""

from __future__ import annotations

import os
import sys
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from patterns.human_in_the_loop import (  # type: ignore[import-not-found]
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    HITLGateway,
)

# ---------------------------------------------------------------------------
# ApprovalRequest
# ---------------------------------------------------------------------------


def test_approval_request_not_expired() -> None:
    req = ApprovalRequest(
        tool_name="delete_file",
        args={"path": "/tmp/test.txt"},
        agent_id="a1",
        tenant_id="acme",
    )
    assert req.is_expired() is False


def test_approval_request_expired() -> None:
    req = ApprovalRequest(
        tool_name="delete_file",
        args={"path": "/tmp/test.txt"},
        agent_id="a1",
        tenant_id="acme",
        expires_at=time.time() - 1,
    )
    assert req.is_expired() is True


def test_approval_request_serialization() -> None:
    req = ApprovalRequest(
        tool_name="run_payment",
        args={"amount": 100},
        agent_id="agent-1",
        tenant_id="globex",
        metadata={"invoice": "INV-001"},
    )
    raw = req.to_json()
    restored = ApprovalRequest.from_json(raw)
    assert restored.tool_name == req.tool_name
    assert restored.args == req.args
    assert restored.agent_id == req.agent_id
    assert restored.tenant_id == req.tenant_id
    assert restored.metadata == req.metadata
    assert restored.status == ApprovalStatus.PENDING


# ---------------------------------------------------------------------------
# HITLGateway — non-critical tool (fast path)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_critical_tool_executes_immediately() -> None:
    """Non-critical tools bypass the HITL queue entirely."""
    queue = MagicMock()
    queue.enqueue = AsyncMock()
    gateway = HITLGateway(
        queue=queue,
        critical_tools={"delete_file", "run_payment"},
    )

    result = await gateway.call_tool("read_file", {"path": "/data"}, "a1", "acme")

    assert result["status"] == "approved"
    assert result.get("immediate") is True
    queue.enqueue.assert_not_called()


@pytest.mark.asyncio
async def test_non_listed_tool_is_not_critical() -> None:
    """Tools not in critical_tools set are non-critical."""
    queue = MagicMock()
    queue.enqueue = AsyncMock()
    gateway = HITLGateway(queue=queue, critical_tools={"only_this_is_critical"})

    result = await gateway.call_tool("any_other_tool", {}, "a1", "acme")
    assert result["status"] == "approved"
    queue.enqueue.assert_not_called()


@pytest.mark.asyncio
async def test_critical_tool_enqueues_and_approves() -> None:
    """Critical tools enqueue a request and wait for human approval."""
    queue = MagicMock()
    queue.enqueue = AsyncMock(return_value="req-001")
    queue.poll_decision = AsyncMock(
        return_value=ApprovalDecision(
            request_id="req-001",
            status=ApprovalStatus.APPROVED,
            decided_by="alice@acme.com",
        )
    )

    gateway = HITLGateway(queue=queue, critical_tools={"delete_file"})
    result = await gateway.call_tool("delete_file", {"path": "/data"}, "a1", "acme")

    assert result["status"] == "approved"
    assert result["request_id"] == "req-001"
    queue.enqueue.assert_called_once()
    queue.poll_decision.assert_called_once_with("req-001", timeout=120.0)


@pytest.mark.asyncio
async def test_critical_tool_rejects_returns_reason() -> None:
    """Rejected critical tool calls return the rejection reason."""
    queue = MagicMock()
    queue.enqueue = AsyncMock(return_value="req-002")
    queue.poll_decision = AsyncMock(
        return_value=ApprovalDecision(
            request_id="req-002",
            status=ApprovalStatus.REJECTED,
            decided_by="bob@acme.com",
            rejection_reason="Amount exceeds policy",
        )
    )

    gateway = HITLGateway(queue=queue, critical_tools={"run_payment"})
    result = await gateway.call_tool("run_payment", {"amount": 99999}, "a1", "acme")

    assert result["status"] == "rejected"
    assert result["reason"] == "Amount exceeds policy"
    assert result["decided_by"] == "bob@acme.com"


@pytest.mark.asyncio
async def test_critical_tool_times_out() -> None:
    """HITL gateway propagates TimeoutError when no human decision arrives."""
    queue = MagicMock()
    queue.enqueue = AsyncMock(return_value="req-003")
    queue.poll_decision = AsyncMock(side_effect=TimeoutError("No decision in 30s"))

    gateway = HITLGateway(
        queue=queue,
        critical_tools={"deploy_to_prod"},
        approval_timeout=30.0,
    )

    with pytest.raises(TimeoutError):
        await gateway.call_tool("deploy_to_prod", {}, "a1", "acme")


def test_gateway_is_critical_flag() -> None:
    queue = MagicMock()
    gateway = HITLGateway(
        queue=queue,
        critical_tools={"drop_table", "run_payment"},
    )
    assert gateway.is_critical("drop_table") is True
    assert gateway.is_critical("run_payment") is True
    assert gateway.is_critical("read_file") is False
    assert gateway.is_critical("list_dir") is False
