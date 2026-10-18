"""Cross-service API parity: the same scenario against the Java and Python services.

The Java jar is launched as a separate process with its own database file. The test
is skipped (never faked) when Java or the built jar is unavailable. Nondeterministic
fields are normalized; everything else must be identical.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2 as httpx
import pytest
from conftest import ADMIN, AUDITOR, READER, WRITER, make_config
from starlette.testclient import TestClient

from audit_log_service.app import create_app
from audit_log_service.verifier.bundle import Options, verify_bundle

JAR = (
    Path(__file__).resolve().parents[2]
    / "java"
    / "target"
    / "audit-log-service-0.1.0-SNAPSHOT.jar"
)
LEDGER = "parity-ledger"
WINDOW = {"from": "2024-01-01T00:00:00Z", "to": "2030-01-01T00:00:00Z"}

# Values that differ run to run (random ids, salts, clocks, hashes of salted data).
_VOLATILE = frozenset(
    {
        "eventId",
        "reportId",
        "bundleId",
        "reportEventId",
        "timestamp",
        "createdAt",
        "verifiedAt",
        "exportedAt",
        "contentHash",
        "prevHash",
        "chainHash",
        "recordsDigest",
        "signature",
        "checkpointSignature",
        "publicKey",
        "keyId",
        "checkpointKeyId",
        "salt",
        "durationMs",
        "headHash",
    }
)


def _shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_shape(item) for item in value]
    return "<commitment>"


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "<volatile>"
                if key in _VOLATILE
                else _shape(item)
                if key == "payloadCommitments"
                else normalize(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def _first_diff(a: Any, b: Any, path: str = "") -> str:
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            if a.get(key) != b.get(key):
                return _first_diff(a.get(key), b.get(key), f"{path}/{key}")
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for index, (x, y) in enumerate(zip(a, b, strict=True)):
            if x != y:
                return _first_diff(x, y, f"{path}/{index}")
    return f"{path}: java={a!r} python={b!r}"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@pytest.fixture
def java_client(tmp_path: Path) -> Iterator[httpx.Client]:
    if shutil.which("java") is None or not JAR.is_file():
        pytest.skip("Java runtime or the built jar is unavailable")
    port = _free_port()
    directory = tmp_path / "java"
    directory.mkdir()
    env = {
        "AUDIT_ENV": "dev",
        "AUDIT_LEDGER_ID": LEDGER,
        "AUDIT_DB_PATH": str(directory / "audit.db"),
        "AUDIT_SIGNING_PRIVATE_KEY": str(directory / "keys" / "private.pem"),
        "AUDIT_SIGNING_PUBLIC_KEY": str(directory / "keys" / "public.b64"),
        "AUDIT_ARCHIVE_DIR": str(directory / "archives"),
        "AUDIT_EXPORT_DIR": str(directory / "exports"),
    }
    import os

    log = (directory / "java.log").open("wb")
    (directory / "tmp").mkdir()
    process = subprocess.Popen(  # noqa: S603
        [  # noqa: S607
            "java",
            f"-Djava.io.tmpdir={directory / 'tmp'}",
            "-jar",
            str(JAR),
            f"--server.port={port}",
        ],
        env={**os.environ, **env},
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=60)
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail(
                    "Java service exited: "
                    + (directory / "java.log").read_text()[-2000:]
                )
            try:
                if client.get("/health").status_code == 200:
                    break
            except httpx.TransportError:
                time.sleep(0.5)
        else:
            pytest.fail("Java service did not become healthy in time")
        yield client
    finally:
        client.close()
        process.terminate()
        try:
            process.wait(20)
        except subprocess.TimeoutExpired:
            process.kill()
        log.close()


@pytest.fixture
def python_client(tmp_path: Path) -> TestClient:
    config = make_config(tmp_path, AUDIT_LEDGER_ID=LEDGER)
    return TestClient(create_app(config), raise_server_exceptions=False)


def _access(actor: str, account: str, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "dataCategory": "BALANCES",
        "accessType": "VIEW",
        "accessPurpose": "SERVICING",
        "channel": "INTERNAL_APP",
        "outcome": "GRANTED",
        "sessionId": "s-1",
    }
    payload.update(overrides)
    return {
        "eventType": "ACCOUNT_DATA_ACCESS",
        "actorId": actor,
        "resourceType": "CLIENT_ACCOUNT",
        "resourceId": account,
        "payload": payload,
    }


def _scenario(client: Any) -> dict[str, Any]:
    """Run the shared scenario and return every response, normalized."""
    seen: dict[str, Any] = {}

    def record(name: str, response: Any) -> Any:
        body = response.json() if response.content else None
        if response.status_code >= 400 and body:
            # Messages are free text; the contract fixes only status and code.
            body = {"error": {"code": body["error"]["code"]}}
        seen[name] = {"status": response.status_code, "body": normalize(body)}
        return body

    events = [
        _access("alice", "acct-1"),
        _access("alice", "acct-1"),
        _access("alice", "acct-1", outcome="DENIED", denialReason="no entitlement"),
        _access("alice", "acct-1", accessPurpose="OTHER", justification="follow-up"),
        _access("bob", "acct-1", dataCategory="PROFILE", accessType="SEARCH"),
        _access("alice", "acct-2"),
    ]
    created = [client.post("/audit/events", json=e, headers=WRITER) for e in events]
    assert [r.status_code for r in created] == [201] * len(events)
    for index, bad in enumerate(
        [
            _access("alice", "acct-1", outcome="MAYBE"),
            _access("alice", "acct-1", accessPurpose="OTHER"),
            _access("alice", "acct-1", outcome="DENIED"),
            {**_access("alice", "acct-1"), "resourceType": "DOCUMENT"},
        ]
    ):
        record(
            f"invalid-event-{index}",
            client.post("/audit/events", json=bad, headers=WRITER),
        )

    redacted = client.post(
        "/audit/admin/redactions",
        json={
            "eventId": created[1].json()["eventId"],
            "paths": ["/outcome"],
            "reason": "privacy",
            "ticketId": "T-1",
        },
        headers=ADMIN,
    )
    assert redacted.status_code == 201

    url = "/compliance/account-access-report"
    record("report-no-key", client.get(url, params={"accountId": "acct-1", **WINDOW}))
    record(
        "report-reader",
        client.get(url, params={"accountId": "acct-1", **WINDOW}, headers=READER),
    )
    record(
        "report-both-subjects",
        client.get(
            url,
            params={"accountId": "a", "actorId": "b", **WINDOW},
            headers=AUDITOR,
        ),
    )
    record(
        "report-missing-period",
        client.get(url, params={"accountId": "acct-1"}, headers=AUDITOR),
    )
    record(
        "report-reversed",
        client.get(
            url,
            params={"accountId": "a", "from": WINDOW["to"], "to": WINDOW["from"]},
            headers=AUDITOR,
        ),
    )
    seen["account-report"] = {}
    account = client.get(url, params={"accountId": "acct-1", **WINDOW}, headers=AUDITOR)
    assert account.status_code == 200, account.text
    seen["account-report"] = {"status": 200, "body": normalize(account.json())}
    seen["raw-account-report"] = account.json()
    actor = client.get(url, params={"actorId": "alice", **WINDOW}, headers=AUDITOR)
    seen["actor-report"] = {
        "status": actor.status_code,
        "body": normalize(actor.json()),
    }
    seen["public-key"] = client.get("/audit/public-key").json()["publicKey"]
    return seen


def test_account_report_parity_between_java_and_python(
    java_client: httpx.Client, python_client: TestClient
) -> None:
    java = _scenario(java_client)
    python = _scenario(python_client)

    for name in java:
        if name in {"raw-account-report", "public-key"}:
            continue
        assert java[name] == python[name], (
            f"{name} differs: {_first_diff(java[name], python[name])}"
        )

    # Each service's signed evidence verifies offline against its own pinned key.
    import json

    for result in (java, python):
        evidence = json.dumps(result["raw-account-report"]["evidence"]).encode()
        verdict = verify_bundle(evidence, Options(pinned_key=result["public-key"]))
        assert verdict.status == "VERIFIED", verdict
    # Cross-pinning must fail: the other service's key is not the signer.
    java_evidence = json.dumps(java["raw-account-report"]["evidence"]).encode()
    crossed = verify_bundle(java_evidence, Options(pinned_key=python["public-key"]))
    assert crossed.status != "VERIFIED"
