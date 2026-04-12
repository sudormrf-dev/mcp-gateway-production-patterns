# mcp-gateway-production-patterns

## Purpose
Production security patterns for multi-tenant MCP servers: Zero-Trust, HITL, federation, sandboxing.

## Architecture
- `patterns/federation.py` — Redis auto-discovery, FederatedNode, FederationRouter
- `patterns/zero_trust_gateway.py` — ZeroTrustGateway, OAuthTokenInjector, InMemoryTokenStore
- `patterns/human_in_the_loop.py` — HITLGateway, HITLQueue, ApprovalRequest
- `patterns/tool_sandboxing.py` — ToolSandbox, MultiTenantSandbox, SandboxLimits
- `patterns/secret_vaulting.py` — VaultSecretProvider, SOPSSecretProvider, SecretInjector

## Conventions
- Python 3.11+ with full type hints
- ruff + mypy --strict
- pytest-asyncio for async tests
- All patterns are pure library code (no side effects on import)

## Key Patterns
- Tokens cached 15 min (InMemoryTokenStore); use Redis in multi-worker
- Critical tools gated by HITLGateway before execution
- Subprocess sandbox: resource.setrlimit preexec_fn, no cgroupspy (v1 only)
- SecretInjector: Vault primary → SOPS fallback → env vars
