"""Human-in-the-loop (HITL) async queue for critical MCP tool calls.

Pattern: agent proposes → HITL queue → human approves/rejects → execution.

Critical tools (file deletion, payments, infrastructure changes) are never
executed automatically. The agent submits an approval request and awaits the
human decision via a Redis-backed queue with WebSocket push notifications.

Architecture::

    Agent calls tool
        → HITLGateway intercepts (tool in CRITICAL_TOOLS)
        → ApprovalRequest pushed to Redis queue
        → Human notified (WebSocket / webhook)
        → Human approves or rejects
        → Agent receives decision (polling or await)
        → Tool executes only on approval

Usage::

    gateway = HITLGateway(
        redis_url="redis://localhost:6379",
        critical_tools={"delete_file", "run_payment", "deploy_infra"},
    )
    result = await gateway.call_tool("delete_file", args, agent_id="a1", tenant_id="acme")
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import redis.asyncio as aioredis

_QUEUE_KEY_PREFIX: str = "mcp:hitl:pending"
_DECISION_KEY_PREFIX: str = "mcp:hitl:decision"
_REQUEST_TTL_SECONDS: int = 300  # 5 minutes to respond
_POLL_INTERVAL: float = 0.5
_DEFAULT_TIMEOUT_SECONDS: float = 120.0


class ApprovalStatus(str, Enum):
    """Possible states of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    """A pending tool call awaiting human approval.

    Args:
        tool_name: The MCP tool being called.
        args: Arguments the agent wants to pass to the tool.
        agent_id: Identity of the requesting agent.
        tenant_id: Tenant scope.
        request_id: Unique ID for this request (auto-generated).
        created_at: Unix timestamp of creation.
        expires_at: Unix timestamp when the request expires.
        metadata: Optional context (reason, risk level, etc.).
    """

    tool_name: str
    args: dict[str, Any]
    agent_id: str
    tenant_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + _REQUEST_TTL_SECONDS)
    metadata: dict[str, Any] = field(default_factory=dict)
    status: ApprovalStatus = ApprovalStatus.PENDING

    def to_json(self) -> str:
        """Serialize for Redis storage."""
        return json.dumps(
            {
                "tool_name": self.tool_name,
                "args": self.args,
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "request_id": self.request_id,
                "created_at": self.created_at,
                "expires_at": self.expires_at,
                "metadata": self.metadata,
                "status": self.status.value,
            }
        )

    @classmethod
    def from_json(cls, data: str) -> ApprovalRequest:
        """Deserialize from Redis storage."""
        obj = json.loads(data)
        obj["status"] = ApprovalStatus(obj["status"])
        return cls(**obj)

    def is_expired(self) -> bool:
        """Return True if the approval window has passed."""
        return time.time() > self.expires_at


@dataclass
class ApprovalDecision:
    """A human's decision on a pending approval request."""

    request_id: str
    status: ApprovalStatus
    decided_by: str
    decided_at: float = field(default_factory=time.time)
    rejection_reason: str = ""


class HITLQueue:
    """Redis-backed queue for approval requests.

    Args:
        redis_url: Redis connection URL.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379") -> None:
        self._redis_url = redis_url
        self._client: aioredis.Redis | None = None

    async def _get_client(self) -> aioredis.Redis:
        if self._client is None:
            self._client = await aioredis.from_url(self._redis_url, decode_responses=True)
        return self._client

    def _queue_key(self, tenant_id: str) -> str:
        return f"{_QUEUE_KEY_PREFIX}:{tenant_id}"

    def _decision_key(self, request_id: str) -> str:
        return f"{_DECISION_KEY_PREFIX}:{request_id}"

    async def enqueue(self, request: ApprovalRequest) -> str:
        """Push an approval request onto the tenant's pending queue.

        Args:
            request: The approval request to enqueue.

        Returns:
            The ``request_id`` for polling.
        """
        client = await self._get_client()
        await client.lpush(self._queue_key(request.tenant_id), request.to_json())  # type: ignore[misc]
        # Also store by request_id for direct lookup
        await client.setex(
            f"mcp:hitl:req:{request.request_id}",
            _REQUEST_TTL_SECONDS,
            request.to_json(),
        )
        return request.request_id

    async def pending(self, tenant_id: str) -> list[ApprovalRequest]:
        """Return all pending requests for a tenant (for the approval UI).

        Args:
            tenant_id: The tenant whose queue to inspect.

        Returns:
            List of :class:`ApprovalRequest` objects.
        """
        client = await self._get_client()
        raw_items: list[str] = await client.lrange(  # type: ignore[misc]
            self._queue_key(tenant_id), 0, -1
        )
        requests = []
        for raw in raw_items:
            try:
                req = ApprovalRequest.from_json(raw)
                if not req.is_expired():
                    requests.append(req)
            except (json.JSONDecodeError, KeyError):
                continue
        return requests

    async def decide(self, decision: ApprovalDecision) -> None:
        """Record a human decision and notify waiting agents.

        Args:
            decision: The approval or rejection decision.
        """
        client = await self._get_client()
        decision_data = json.dumps(
            {
                "request_id": decision.request_id,
                "status": decision.status.value,
                "decided_by": decision.decided_by,
                "decided_at": decision.decided_at,
                "rejection_reason": decision.rejection_reason,
            }
        )
        # Publish via Redis pub/sub so awaiting agents are notified immediately
        await client.publish(self._decision_key(decision.request_id), decision_data)
        # Also persist for polling fallback
        await client.setex(
            self._decision_key(decision.request_id),
            _REQUEST_TTL_SECONDS,
            decision_data,
        )

    async def poll_decision(
        self, request_id: str, timeout: float = _DEFAULT_TIMEOUT_SECONDS
    ) -> ApprovalDecision:
        """Block until a decision arrives or the request expires.

        Uses Redis pub/sub for push notification with polling as fallback.

        Args:
            request_id: The ID of the approval request to watch.
            timeout: Maximum seconds to wait.

        Returns:
            The :class:`ApprovalDecision` once received.

        Raises:
            TimeoutError: If no decision arrives within ``timeout`` seconds.
        """
        client = await self._get_client()
        channel = self._decision_key(request_id)

        # Subscribe to the decision channel for instant notification
        pubsub = client.pubsub()
        await pubsub.subscribe(channel)

        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                # Check for message (non-blocking)
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=_POLL_INTERVAL
                )
                if message and message["type"] == "message":
                    data = json.loads(message["data"])
                    return ApprovalDecision(
                        request_id=data["request_id"],
                        status=ApprovalStatus(data["status"]),
                        decided_by=data["decided_by"],
                        decided_at=data["decided_at"],
                        rejection_reason=data.get("rejection_reason", ""),
                    )

                # Fallback: check persisted key
                raw = await client.get(channel)
                if raw:
                    data = json.loads(raw)
                    return ApprovalDecision(
                        request_id=data["request_id"],
                        status=ApprovalStatus(data["status"]),
                        decided_by=data["decided_by"],
                        decided_at=data["decided_at"],
                        rejection_reason=data.get("rejection_reason", ""),
                    )

                await asyncio.sleep(_POLL_INTERVAL)
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()  # type: ignore[no-untyped-call]

        msg = f"No decision received for request '{request_id}' within {timeout}s"
        raise TimeoutError(msg)

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._client:
            await self._client.aclose()
            self._client = None


class HITLGateway:
    """Intercept critical tool calls and route them through the HITL queue.

    Non-critical tools execute immediately. Critical tools pause until a human
    approves or rejects the request.

    Args:
        queue: The :class:`HITLQueue` backend.
        critical_tools: Set of tool names that require human approval.
        approval_timeout: Seconds to wait for a human decision.

    Example::

        gw = HITLGateway(
            queue=HITLQueue(),
            critical_tools={"delete_file", "run_payment"},
        )
        result = await gw.call_tool("delete_file", {"path": "/data"}, "agent-1", "acme")
    """

    def __init__(
        self,
        queue: HITLQueue,
        critical_tools: set[str] | None = None,
        approval_timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._queue = queue
        self._critical_tools = critical_tools or set()
        self._approval_timeout = approval_timeout

    def is_critical(self, tool_name: str) -> bool:
        """Return True if this tool requires human approval."""
        return tool_name in self._critical_tools

    async def call_tool(
        self,
        tool_name: str,
        args: dict[str, Any],
        agent_id: str,
        tenant_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Call a tool, waiting for approval if it's critical.

        Args:
            tool_name: Name of the MCP tool.
            args: Tool arguments.
            agent_id: Requesting agent's identity.
            tenant_id: Tenant scope.
            metadata: Optional context (e.g. reason, risk assessment).

        Returns:
            ``{"status": "approved", "request_id": "..."}`` on approval, or
            ``{"status": "rejected", "reason": "...", "request_id": "..."}`` on rejection.

        Raises:
            TimeoutError: If no human decision arrives within ``approval_timeout``.
        """
        if not self.is_critical(tool_name):
            # Fast path: non-critical tools execute immediately
            return {"status": "approved", "immediate": True, "tool": tool_name}

        # Create and enqueue approval request
        request = ApprovalRequest(
            tool_name=tool_name,
            args=args,
            agent_id=agent_id,
            tenant_id=tenant_id,
            metadata=metadata or {},
        )
        request_id = await self._queue.enqueue(request)

        # Block until human decides
        decision = await self._queue.poll_decision(request_id, timeout=self._approval_timeout)

        if decision.status == ApprovalStatus.APPROVED:
            return {"status": "approved", "request_id": request_id, "tool": tool_name}

        return {
            "status": "rejected",
            "request_id": request_id,
            "reason": decision.rejection_reason,
            "decided_by": decision.decided_by,
        }
