from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from audit_log_service.canonical_json import parse_json
from audit_log_service.configuration import AuditConfiguration, ConfigurationError

READ_ROLES = frozenset({"reader", "auditor", "admin"})
AUDITOR_ROLES = frozenset({"auditor", "admin"})
ADMIN_ROLES = frozenset({"admin"})
WRITE_ROLES = frozenset({"writer", "admin"})

_MAX_KEY_BYTES = 4096

# SHA-256 digests of the public sample credentials documented for dev only.
_DEVELOPMENT_PRINCIPALS: dict[str, tuple[str, frozenset[str]]] = {
    "dev-writer": (
        "469a1f393460157d3dfb2d2210e03fc40d30869efd06e9e6b4d85a34f4ceb802",
        frozenset({"writer"}),
    ),
    "dev-reader": (
        "c0662461952624f51ddb16a15d818f2d0f98897d88acc6089c6062e51c84315d",
        frozenset({"reader"}),
    ),
    "dev-auditor": (
        "97e970584eec0376b698e47aab5d6c57375032d102e948505979c84d3025c912",
        frozenset({"auditor"}),
    ),
    "dev-admin": (
        "33d791b3399bc60ca2ac26ac5aba3ba02efda2052576091bab53ced197463fda",
        frozenset({"admin", "writer", "reader", "auditor"}),
    ),
}


@dataclass(frozen=True)
class Principal:
    name: str
    roles: frozenset[str]

    def has_any(self, required: frozenset[str]) -> bool:
        return not self.roles.isdisjoint(required)


@dataclass(frozen=True)
class _Entry:
    name: str
    key_hash: bytes
    roles: frozenset[str]


class ApiKeyAuthenticator:
    def __init__(self, configuration: AuditConfiguration) -> None:
        if configuration.api_keys_file is None:
            if configuration.environment != "dev":
                raise ConfigurationError("Production requires an API-key file")
            entries = [
                _Entry(name, bytes.fromhex(digest), roles)
                for name, (digest, roles) in _DEVELOPMENT_PRINCIPALS.items()
            ]
        else:
            entries = self._load(configuration)
        self._entries = tuple(entries)
        self._cursor_key = _derive_cursor_key(self._entries)

    @staticmethod
    def _load(configuration: AuditConfiguration) -> list[_Entry]:
        configuration.validate_api_keys()
        assert configuration.api_keys_file is not None
        parsed = parse_json(
            configuration.api_keys_file.read_bytes(), max_bytes=64 * 1024
        )
        assert isinstance(parsed, dict)
        entries: list[_Entry] = []
        seen: set[str] = set()
        for name, entry in parsed.items():
            assert isinstance(entry, dict)
            key_hash = entry["keyHash"]
            roles = entry["roles"]
            assert isinstance(key_hash, str) and isinstance(roles, list)
            if key_hash in seen:
                raise ConfigurationError(
                    "API-key principals must have unique key hashes"
                )
            seen.add(key_hash)
            entries.append(
                _Entry(
                    name,
                    bytes.fromhex(key_hash),
                    frozenset(str(role) for role in roles),
                )
            )
        return entries

    @property
    def cursor_signing_key(self) -> bytes:
        return self._cursor_key

    def authenticate(self, presented: str | None) -> Principal | None:
        if presented is None or not presented.strip():
            return None
        try:
            raw = presented.encode("utf-8")
        except UnicodeEncodeError:
            return None
        if len(raw) > _MAX_KEY_BYTES:
            return None
        candidate = hashlib.sha256(raw).digest()
        match: _Entry | None = None
        matches = 0
        # Every entry is compared so timing does not reveal which one matched.
        for entry in self._entries:
            if hmac.compare_digest(candidate, entry.key_hash):
                match = entry
                matches += 1
        if match is None or matches != 1:
            return None
        return Principal(match.name, match.roles)


def _derive_cursor_key(entries: tuple[_Entry, ...]) -> bytes:
    material = "audit-log/query-cursor/v1"
    for entry in sorted(entries, key=lambda item: item.name):
        material += f"\x00{entry.name}\x00{entry.key_hash.hex()}"
    return hashlib.sha256(material.encode("utf-8")).digest()
