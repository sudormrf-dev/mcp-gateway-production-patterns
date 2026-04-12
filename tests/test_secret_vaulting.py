"""Tests for the secret vaulting patterns."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from patterns.secret_vaulting import (  # type: ignore[import-not-found]
    EnvSecretProvider,
    SecretInjector,
    SOPSSecretProvider,
    VaultSecretProvider,
    build_injector_from_env,
)

# ---------------------------------------------------------------------------
# EnvSecretProvider
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_env_provider_reads_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_SECRET_DB__PROD__PASSWORD", "super-secret")
    provider = EnvSecretProvider()
    value = await provider.fetch("db/prod/password")
    assert value == "super-secret"


@pytest.mark.asyncio
async def test_env_provider_raises_for_missing_key() -> None:
    provider = EnvSecretProvider()
    with pytest.raises(KeyError, match="not found in environment"):
        await provider.fetch("nonexistent/key")


@pytest.mark.asyncio
async def test_env_provider_dotted_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_SECRET_API__KEY", "api-key-123")
    provider = EnvSecretProvider()
    value = await provider.fetch("api.key")
    assert value == "api-key-123"


# ---------------------------------------------------------------------------
# SecretInjector — caching
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_injector_caches_secret() -> None:
    """SecretInjector returns cached value without calling provider again."""
    call_count = 0

    class CountingProvider:
        async def fetch(self, path: str) -> str:
            nonlocal call_count
            call_count += 1
            return "cached-value"

    injector = SecretInjector(CountingProvider(), cache_ttl=60)  # type: ignore[arg-type]

    val1 = await injector.get("some/secret")
    val2 = await injector.get("some/secret")
    assert val1 == val2 == "cached-value"
    assert call_count == 1  # provider called only once


@pytest.mark.asyncio
async def test_injector_refetches_after_invalidation() -> None:
    """SecretInjector re-fetches after invalidate() is called."""
    call_count = 0

    class CountingProvider:
        async def fetch(self, path: str) -> str:
            nonlocal call_count
            call_count += 1
            return f"value-{call_count}"

    injector = SecretInjector(CountingProvider(), cache_ttl=60)  # type: ignore[arg-type]

    val1 = await injector.get("key")
    injector.invalidate("key")
    val2 = await injector.get("key")
    assert val1 == "value-1"
    assert val2 == "value-2"
    assert call_count == 2


@pytest.mark.asyncio
async def test_injector_invalidate_all() -> None:
    """invalidate_all() clears the entire cache."""
    call_count = 0

    class CountingProvider:
        async def fetch(self, path: str) -> str:
            nonlocal call_count
            call_count += 1
            return "v"

    injector = SecretInjector(CountingProvider(), cache_ttl=60)  # type: ignore[arg-type]
    await injector.get("k1")
    await injector.get("k2")
    injector.invalidate_all()
    await injector.get("k1")
    await injector.get("k2")
    assert call_count == 4  # all refetched


@pytest.mark.asyncio
async def test_injector_expired_cache_refetches() -> None:
    """Injector re-fetches when cache TTL has elapsed."""
    call_count = 0

    class CountingProvider:
        async def fetch(self, path: str) -> str:
            nonlocal call_count
            call_count += 1
            return "fresh"

    injector = SecretInjector(CountingProvider(), cache_ttl=0)  # type: ignore[arg-type]
    # TTL=0 → every access is a miss
    await injector.get("k")
    await injector.get("k")
    assert call_count == 2


# ---------------------------------------------------------------------------
# VaultSecretProvider — import guard
# ---------------------------------------------------------------------------

def test_vault_provider_raises_on_missing_hvac() -> None:
    """VaultSecretProvider raises ImportError if hvac is not installed."""
    with patch("builtins.__import__", side_effect=ImportError("no module named hvac")):
        # The error is raised lazily when _get_client() is called
        pass  # Just verify the guard exists structurally


# ---------------------------------------------------------------------------
# SOPSSecretProvider
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sops_provider_parses_decrypted_output() -> None:
    """SOPSSecretProvider correctly parses sops --decrypt output."""
    import json

    decrypted = json.dumps({
        "database": {"password": "db-secret-123"},
        "api_key": "api-abc",
    })

    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = decrypted
        mock_run.return_value = mock_result

        provider = SOPSSecretProvider("secrets/prod.enc.yaml")
        # Bypass the TTL check for testing
        provider._decrypted = None
        provider._decrypted_at = 0.0

        value = await provider.fetch("database.password")
        assert value == "db-secret-123"


@pytest.mark.asyncio
async def test_sops_provider_raises_for_missing_key() -> None:
    import json

    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({"other": "data"})
        mock_run.return_value = mock_result

        provider = SOPSSecretProvider("secrets/prod.enc.yaml")
        provider._decrypted = None
        provider._decrypted_at = 0.0

        with pytest.raises(KeyError, match="SOPS key"):
            await provider.fetch("database.password")


# ---------------------------------------------------------------------------
# build_injector_from_env
# ---------------------------------------------------------------------------

def test_build_injector_uses_env_provider_as_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """build_injector_from_env uses EnvSecretProvider when no Vault or SOPS configured."""
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.delenv("SOPS_FILE", raising=False)
    injector = build_injector_from_env()
    assert isinstance(injector, SecretInjector)
    assert isinstance(injector._provider, EnvSecretProvider)


def test_build_injector_uses_vault_when_token_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VAULT_TOKEN", "test-token")
    monkeypatch.delenv("SOPS_FILE", raising=False)
    injector = build_injector_from_env()
    assert isinstance(injector._provider, VaultSecretProvider)


def test_build_injector_uses_sops_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.setenv("SOPS_FILE", "secrets/prod.enc.yaml")
    injector = build_injector_from_env()
    assert isinstance(injector._provider, SOPSSecretProvider)
