from __future__ import annotations

import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from audit_log_service.canonical_json import JsonValue, parse_json
from audit_log_service.signing import CheckpointSigner, SigningKeyError

_HEX_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED_ROLES = {"writer", "reader", "auditor", "admin"}
_MAX_RETENTION_DAYS = 500_000
_MAX_API_KEY_FILE_BYTES = 64 * 1024


class ConfigurationError(ValueError):
    """Raised when application configuration violates the service contract."""


@dataclass(frozen=True)
class AuditConfiguration:
    environment: str
    ledger_id: str
    retention_days: float
    checkpoint_interval: int
    request_limit_bytes: int
    payload_limit_bytes: int
    max_depth: int
    max_leaves: int
    signing_private_key: Path
    signing_public_key: Path
    api_keys_file: Path | None
    db_path: Path = Path("audit-data/audit.db")
    export_max_records: int = 1000
    export_max_bytes: int = 8 * 1024 * 1024
    export_dir: Path = Path("audit-data/exports")
    export_chunk_max_records: int = 1000
    export_chunk_max_bytes: int = 8 * 1024 * 1024
    export_set_max_records: int = 1_000_000
    export_set_ttl_seconds: int = 86_400
    cleanup_max_attempts: int = 3
    cleanup_busy_timeout_ms: int = 1000
    archive_dir: Path = Path("audit-data/archives")
    archive_max_records: int = 1000
    archive_max_bytes: int = 8 * 1024 * 1024

    @classmethod
    def from_environment(
        cls, values: Mapping[str, str] | None = None
    ) -> AuditConfiguration:
        env = os.environ if values is None else values
        environment = _get(env, "AUDIT_ENV", "dev")
        if environment not in {"dev", "prod"}:
            raise ConfigurationError("AUDIT_ENV must be 'dev' or 'prod'")

        ledger_id = _get(env, "AUDIT_LEDGER_ID", "development-ledger")
        try:
            ledger_id_bytes = ledger_id.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ConfigurationError(
                "AUDIT_LEDGER_ID must contain valid Unicode"
            ) from exc
        if not ledger_id.strip() or len(ledger_id_bytes) > 256:
            raise ConfigurationError("AUDIT_LEDGER_ID must be 1 to 256 UTF-8 bytes")

        retention_text = _get(env, "AUDIT_RETENTION_DAYS", "2555")
        try:
            retention_days = float(retention_text)
        except ValueError as exc:
            raise ConfigurationError("AUDIT_RETENTION_DAYS must be a number") from exc
        if (
            not math.isfinite(retention_days)
            or retention_days <= 0
            or retention_days > _MAX_RETENTION_DAYS
            or (environment == "prod" and retention_days < 1)
        ):
            raise ConfigurationError("AUDIT_RETENTION_DAYS is outside safe bounds")

        checkpoint_interval = _positive_int(env, "AUDIT_CHECKPOINT_INTERVAL", 100)
        request_limit = _positive_int(env, "AUDIT_REQUEST_LIMIT_BYTES", 256 * 1024)
        payload_limit = _positive_int(env, "AUDIT_PAYLOAD_LIMIT_BYTES", 64 * 1024)
        max_depth = _positive_int(env, "AUDIT_MAX_DEPTH", 10)
        max_leaves = _positive_int(env, "AUDIT_MAX_LEAVES", 500)
        _bounded("AUDIT_CHECKPOINT_INTERVAL", checkpoint_interval, 1_000_000)
        _bounded("AUDIT_REQUEST_LIMIT_BYTES", request_limit, 1024 * 1024)
        _bounded("AUDIT_PAYLOAD_LIMIT_BYTES", payload_limit, request_limit)
        _bounded("AUDIT_MAX_DEPTH", max_depth, 10)
        _bounded("AUDIT_MAX_LEAVES", max_leaves, 500)

        export_max_records = _positive_int(env, "AUDIT_EXPORT_MAX_RECORDS", 1000)
        export_max_bytes = _positive_int(env, "AUDIT_EXPORT_MAX_BYTES", 8 * 1024**2)
        chunk_max_records = _positive_int(env, "AUDIT_EXPORT_CHUNK_MAX_RECORDS", 1000)
        chunk_max_bytes = _positive_int(
            env, "AUDIT_EXPORT_CHUNK_MAX_BYTES", 8 * 1024**2
        )
        set_max_records = _positive_int(env, "AUDIT_EXPORT_SET_MAX_RECORDS", 1_000_000)
        set_ttl = _positive_int(env, "AUDIT_EXPORT_SET_TTL_SECONDS", 86_400)
        _bounded("AUDIT_EXPORT_MAX_RECORDS", export_max_records, 100_000)
        _bounded("AUDIT_EXPORT_MAX_BYTES", export_max_bytes, 64 * 1024**2)
        _bounded("AUDIT_EXPORT_CHUNK_MAX_RECORDS", chunk_max_records, 100_000)
        _bounded("AUDIT_EXPORT_CHUNK_MAX_BYTES", chunk_max_bytes, 64 * 1024**2)
        _bounded("AUDIT_EXPORT_SET_MAX_RECORDS", set_max_records, 10_000_000)
        if not 60 <= set_ttl <= 2_592_000:
            raise ConfigurationError("AUDIT_EXPORT_SET_TTL_SECONDS is outside bounds")
        db_path = Path(_get(env, "AUDIT_DB_PATH", "audit-data/audit.db"))
        export_dir_value = env.get("AUDIT_EXPORT_DIR")
        if export_dir_value is not None and not export_dir_value.strip():
            raise ConfigurationError("AUDIT_EXPORT_DIR must be non-empty when set")
        export_dir = (
            Path(export_dir_value)
            if export_dir_value is not None
            else db_path.parent / "exports"
        )

        cleanup_attempts = _positive_int(env, "AUDIT_CLEANUP_MAX_ATTEMPTS", 3)
        cleanup_timeout = _positive_int(env, "AUDIT_CLEANUP_BUSY_TIMEOUT_MS", 1000)
        _bounded("AUDIT_CLEANUP_MAX_ATTEMPTS", cleanup_attempts, 10)
        _bounded("AUDIT_CLEANUP_BUSY_TIMEOUT_MS", cleanup_timeout, 30_000)
        archive_max_records = _positive_int(env, "AUDIT_ARCHIVE_MAX_RECORDS", 1000)
        archive_max_bytes = _positive_int(env, "AUDIT_ARCHIVE_MAX_BYTES", 8 * 1024**2)
        _bounded("AUDIT_ARCHIVE_MAX_RECORDS", archive_max_records, 100_000)
        _bounded("AUDIT_ARCHIVE_MAX_BYTES", archive_max_bytes, 64 * 1024**2)
        if archive_max_bytes < 65_536:
            raise ConfigurationError("AUDIT_ARCHIVE_MAX_BYTES must be at least 65536")
        archive_dir_value = env.get("AUDIT_ARCHIVE_DIR")
        if archive_dir_value is not None and not archive_dir_value.strip():
            raise ConfigurationError("AUDIT_ARCHIVE_DIR must be non-empty when set")
        archive_dir = (
            Path(archive_dir_value)
            if archive_dir_value is not None
            else db_path.parent / "archives"
        )

        api_keys_value = env.get("AUDIT_API_KEYS_FILE")
        api_keys_file = Path(api_keys_value) if api_keys_value else None
        if environment == "prod" and api_keys_file is None:
            raise ConfigurationError("Production requires AUDIT_API_KEYS_FILE")
        return cls(
            environment=environment,
            ledger_id=ledger_id,
            retention_days=retention_days,
            checkpoint_interval=checkpoint_interval,
            request_limit_bytes=request_limit,
            payload_limit_bytes=payload_limit,
            max_depth=max_depth,
            max_leaves=max_leaves,
            signing_private_key=Path(
                _get(env, "AUDIT_SIGNING_PRIVATE_KEY", "audit-data/signing-private.pem")
            ),
            signing_public_key=Path(
                _get(env, "AUDIT_SIGNING_PUBLIC_KEY", "audit-data/signing-public.b64")
            ),
            api_keys_file=api_keys_file,
            db_path=db_path,
            export_max_records=export_max_records,
            export_max_bytes=export_max_bytes,
            export_dir=export_dir,
            export_chunk_max_records=chunk_max_records,
            export_chunk_max_bytes=chunk_max_bytes,
            export_set_max_records=set_max_records,
            export_set_ttl_seconds=set_ttl,
            cleanup_max_attempts=cleanup_attempts,
            cleanup_busy_timeout_ms=cleanup_timeout,
            archive_dir=archive_dir,
            archive_max_records=archive_max_records,
            archive_max_bytes=archive_max_bytes,
        )

    def load_signer(self) -> CheckpointSigner:
        self.validate_api_keys()
        try:
            return CheckpointSigner.from_files(
                self.signing_private_key,
                self.signing_public_key,
                environment=self.environment,
            )
        except (OSError, SigningKeyError) as exc:
            raise ConfigurationError("Unable to load configured signing keys") from exc

    def validate_api_keys(self) -> None:
        if self.api_keys_file is None:
            if self.environment == "prod":
                raise ConfigurationError("Production requires AUDIT_API_KEYS_FILE")
            return
        try:
            with self.api_keys_file.open("rb") as api_key_stream:
                raw = api_key_stream.read(_MAX_API_KEY_FILE_BYTES + 1)
        except OSError as exc:
            raise ConfigurationError("Unable to read configured API-key file") from exc
        if not raw or len(raw) > _MAX_API_KEY_FILE_BYTES:
            raise ConfigurationError("API-key file is empty or exceeds 64 KiB")
        try:
            parsed = parse_json(raw, max_bytes=_MAX_API_KEY_FILE_BYTES)
        except ValueError as exc:
            raise ConfigurationError(
                "API-key file must contain valid strict JSON"
            ) from exc
        _validate_api_keys(parsed)


def _get(values: Mapping[str, str], name: str, default: str) -> str:
    return values[name] if name in values else default


def _positive_int(values: Mapping[str, str], name: str, default: int) -> int:
    raw = values.get(name, str(default))
    try:
        result = int(raw, 10)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a positive integer") from exc
    if result <= 0:
        raise ConfigurationError(f"{name} must be a positive integer")
    return result


def _bounded(name: str, value: int, maximum: int) -> None:
    if value > maximum:
        raise ConfigurationError(f"{name} exceeds its supported maximum")


def _validate_api_keys(value: JsonValue) -> None:
    if not isinstance(value, dict) or not value or len(value) > 10_000:
        raise ConfigurationError("API-key file must be a non-empty principal object")
    for principal, entry in value.items():
        if not principal.strip() or len(principal) > 128 or not isinstance(entry, dict):
            raise ConfigurationError("API-key file contains an invalid principal")
        if set(entry) != {"keyHash", "roles"}:
            raise ConfigurationError(
                "API-key entries require exactly keyHash and roles"
            )
        key_hash = entry["keyHash"]
        roles = entry["roles"]
        if not isinstance(key_hash, str) or not _HEX_HASH.fullmatch(key_hash):
            raise ConfigurationError(
                "API-key entries must contain lowercase SHA-256 hashes"
            )
        if (
            not isinstance(roles, list)
            or not roles
            or any(
                not isinstance(role, str) or role not in _ALLOWED_ROLES
                for role in roles
            )
            or len(set(roles)) != len(roles)
        ):
            raise ConfigurationError("API-key entries contain invalid roles")
