from __future__ import annotations

from pathlib import Path

from audit_log_service.configuration import AuditConfiguration
from audit_log_service.ledger import AppendService, parse_append_request
from audit_log_service.store import SqliteStore


def environment(db_path: str, key_dir: str, interval: str) -> dict[str, str]:
    return {
        "AUDIT_ENV": "dev",
        "AUDIT_LEDGER_ID": "python-test-ledger",
        "AUDIT_DB_PATH": db_path,
        "AUDIT_SIGNING_PRIVATE_KEY": str(Path(key_dir) / "private.pem"),
        "AUDIT_SIGNING_PUBLIC_KEY": str(Path(key_dir) / "public.b64"),
        "AUDIT_CHECKPOINT_INTERVAL": interval,
    }


def append_many(
    db_path: str, key_dir: str, interval: str, label: str, count: int
) -> list[int]:
    """Runs in a separate process: its own store, signer and connections."""
    config = AuditConfiguration.from_environment(
        environment(db_path, key_dir, interval)
    )
    service = AppendService(
        SqliteStore(config.db_path, config.ledger_id), config, config.load_signer()
    )
    seqs = []
    for index in range(count):
        request = parse_append_request(
            {
                "eventType": "LOAD",
                "actorId": label,
                "resourceType": "DOCUMENT",
                "resourceId": f"{label}-{index}",
                "payload": {"index": index},
            },
            config,
        )
        seqs.append(int(service.append(request, f"writer-{label}")["seq"]))
    return seqs
