"""Dynamic secret injection via HashiCorp Vault and SOPS.

MCP tools often need credentials (DB passwords, API keys). These must never
be hardcoded or passed as plaintext in tool arguments. This module provides
a unified secret injection layer that pulls from Vault or SOPS-encrypted
files at runtime with in-process caching and automatic rotation.

Patterns:
    1. VaultSecretProvider — HashiCorp Vault KV v2 via hvac
    2. SOPSSecretProvider — SOPS-encrypted YAML/JSON files
    3. SecretInjector — unified facade used by tool code

Usage::

    provider = VaultSecretProvider(
        addr="https://vault.example.com",
        token=os.environ["VAULT_TOKEN"],
    )
    injector = SecretInjector(provider)
    db_url = await injector.get("db/prod/url")
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

_SECRET_CACHE_TTL_SECONDS: int = 300  # 5 minutes
_VAULT_KV_MOUNT: str = "secret"


@dataclass
class CachedSecret:
    """A secret value with an expiry timestamp."""

    value: str
    expires_at: float

    def is_valid(self) -> bool:
        """Return True if the cached value is still fresh."""
        return time.time() < self.expires_at


class SecretProvider(ABC):
    """Abstract interface for secret backends."""

    @abstractmethod
    async def fetch(self, path: str) -> str:
        """Fetch the secret at ``path``.

        Args:
            path: Backend-specific path (e.g. ``"db/prod/password"``).

        Returns:
            Secret value as a string.

        Raises:
            KeyError: If the secret does not exist.
            RuntimeError: On backend errors.
        """


class VaultSecretProvider(SecretProvider):
    """Fetch secrets from HashiCorp Vault KV v2.

    Args:
        addr: Vault server address (e.g. ``"https://vault.example.com"``).
        token: Vault token (typically from ``VAULT_TOKEN`` env var).
        mount_point: KV mount path (default: ``"secret"``).
        namespace: Vault namespace for HCP Vault or Vault Enterprise.

    Example::

        provider = VaultSecretProvider(
            addr="https://vault.example.com",
            token=os.environ["VAULT_TOKEN"],
        )
        password = await provider.fetch("database/prod/password")
    """

    def __init__(
        self,
        addr: str | None = None,
        token: str | None = None,
        mount_point: str = _VAULT_KV_MOUNT,
        namespace: str | None = None,
    ) -> None:
        self._addr = addr or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        self._token = token or os.environ.get("VAULT_TOKEN", "")
        self._mount_point = mount_point
        self._namespace = namespace
        self._client: Any = None

    def _get_client(self) -> Any:
        """Lazily initialise hvac client."""
        if self._client is None:
            try:
                import hvac  # type: ignore[import-not-found]  # noqa: PLC0415
            except ImportError as exc:
                msg = "hvac not installed: pip install hvac"
                raise ImportError(msg) from exc

            kwargs: dict[str, Any] = {"url": self._addr, "token": self._token}
            if self._namespace:
                kwargs["namespace"] = self._namespace
            self._client = hvac.Client(**kwargs)

        return self._client

    async def fetch(self, path: str) -> str:
        """Fetch a KV v2 secret from Vault.

        The ``path`` should be the key path within the mount (e.g. ``"db/prod"``).
        A ``/data`` suffix is added automatically by hvac for KV v2.

        Args:
            path: Key path within the KV mount.

        Returns:
            Secret value (string).

        Raises:
            KeyError: If the secret or key is not found.
            RuntimeError: On Vault errors.
        """
        client = self._get_client()
        # path format: "parent/child" → key is last segment, mount_path is prefix
        parts = path.rsplit("/", 1)
        if len(parts) == 2:
            mount_relative_path, key = parts
        else:
            mount_relative_path, key = "", parts[0]

        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=mount_relative_path or path,
                mount_point=self._mount_point,
            )
        except Exception as exc:
            msg = f"Vault error reading '{path}': {exc}"
            raise RuntimeError(msg) from exc

        data: dict[str, str] = response.get("data", {}).get("data", {})
        if key not in data:
            msg = f"Secret key '{key}' not found at Vault path '{path}'"
            raise KeyError(msg)

        return data[key]


class SOPSSecretProvider(SecretProvider):
    """Decrypt SOPS-encrypted YAML/JSON files and return values.

    SOPS is an encrypted file format that keeps secrets in version control
    safely. The SOPS binary must be installed and keys available in the
    environment (GPG, AWS KMS, age, etc.).

    Args:
        file_path: Path to the SOPS-encrypted file.
        sops_binary: Path to the ``sops`` binary (default: ``"sops"``).

    Example::

        provider = SOPSSecretProvider("secrets/prod.enc.yaml")
        password = await provider.fetch("database.password")
    """

    def __init__(
        self,
        file_path: str,
        sops_binary: str = "sops",
    ) -> None:
        self._file_path = file_path
        self._sops = sops_binary
        self._decrypted: dict[str, Any] | None = None
        self._decrypted_at: float = 0.0

    def _decrypt(self) -> dict[str, Any]:
        """Run sops --decrypt and parse the output."""
        if (
            self._decrypted is not None
            and time.time() - self._decrypted_at < _SECRET_CACHE_TTL_SECONDS
        ):
            return self._decrypted

        result = subprocess.run(  # noqa: S603
            [self._sops, "--decrypt", "--output-type", "json", self._file_path],
            capture_output=True,
            text=True,
            check=True,
        )
        self._decrypted = json.loads(result.stdout)
        self._decrypted_at = time.time()
        return self._decrypted

    async def fetch(self, path: str) -> str:
        """Fetch a value from the decrypted SOPS file.

        Args:
            path: Dot-separated key path (e.g. ``"database.password"``).

        Returns:
            Secret value as a string.

        Raises:
            KeyError: If the path does not exist in the decrypted file.
            subprocess.CalledProcessError: If SOPS decryption fails.
        """
        data = self._decrypt()
        keys = path.split(".")
        current: Any = data
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                msg = f"SOPS key '{path}' not found (failed at '{key}')"
                raise KeyError(msg)
            current = current[key]
        return str(current)


class EnvSecretProvider(SecretProvider):
    """Read secrets from environment variables (dev / CI fallback).

    Path ``"db/password"`` maps to env var ``MCP_SECRET_DB__PASSWORD``
    (slashes → double underscores, uppercase).
    """

    async def fetch(self, path: str) -> str:
        env_key = "MCP_SECRET_" + path.replace("/", "__").replace(".", "__").upper()
        value = os.environ.get(env_key)
        if value is None:
            msg = f"Secret '{path}' not found in environment (expected {env_key})"
            raise KeyError(msg)
        return value


@dataclass
class _CacheEntry:
    value: str
    expires_at: float

    def is_valid(self) -> bool:
        return time.time() < self.expires_at


class SecretInjector:
    """Unified facade for secret access with in-process TTL cache.

    Wraps any :class:`SecretProvider` with a time-based cache to avoid
    hammering Vault or decrypting SOPS files on every tool call.

    Args:
        provider: The backing secret source.
        cache_ttl: Seconds to cache a fetched secret (default: 5 minutes).

    Example::

        injector = SecretInjector(VaultSecretProvider())
        db_url = await injector.get("database/prod/url")
    """

    def __init__(
        self,
        provider: SecretProvider,
        cache_ttl: int = _SECRET_CACHE_TTL_SECONDS,
    ) -> None:
        self._provider = provider
        self._cache_ttl = cache_ttl
        self._cache: dict[str, _CacheEntry] = {}

    async def get(self, path: str) -> str:
        """Fetch a secret, using the cache if available.

        Args:
            path: Secret path passed to the underlying provider.

        Returns:
            The secret value as a string.
        """
        entry = self._cache.get(path)
        if entry and entry.is_valid():
            return entry.value

        value = await self._provider.fetch(path)
        self._cache[path] = _CacheEntry(
            value=value,
            expires_at=time.time() + self._cache_ttl,
        )
        return value

    def invalidate(self, path: str) -> None:
        """Remove a specific secret from the cache (force re-fetch on next access).

        Args:
            path: The secret path to invalidate.
        """
        self._cache.pop(path, None)

    def invalidate_all(self) -> None:
        """Clear the entire secret cache."""
        self._cache.clear()


def build_injector_from_env() -> SecretInjector:
    """Build a :class:`SecretInjector` configured from environment variables.

    Precedence: Vault (if ``VAULT_TOKEN`` set) → SOPS (if ``SOPS_FILE`` set)
    → environment variables (fallback).

    Returns:
        A ready-to-use :class:`SecretInjector`.
    """
    if os.environ.get("VAULT_TOKEN"):
        provider: SecretProvider = VaultSecretProvider()
    elif os.environ.get("SOPS_FILE"):
        provider = SOPSSecretProvider(os.environ["SOPS_FILE"])
    else:
        provider = EnvSecretProvider()

    return SecretInjector(provider)
