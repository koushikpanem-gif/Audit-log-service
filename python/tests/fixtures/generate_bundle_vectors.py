"""Generate frozen golden bundle fixtures for audit-export-bundle/v1.

TEST ONLY. Uses the RFC 8032 section 7.1 TEST 1 key, which is public and must never be
used in production. Salts are deterministic here for reproducibility; real writes use
fresh random salts. This script is independent of the Java implementation: it uses only
the Python primitives plus the cryptography package.

    python tests/fixtures/generate_bundle_vectors.py          # (re)write fixtures
    python tests/fixtures/generate_bundle_vectors.py --check  # fail if files differ
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_log_service.canonical_json import canonicalize
from audit_log_service.payload_commitments import _commit_payload
from audit_log_service.v1_hashes import (
    chain_hash,
    content_hash,
    content_object,
    genesis_hash,
)

HERE = Path(__file__).resolve().parent
OUT = HERE / "bundle_vectors"
EXAMPLE = (
    HERE.parents[2] / "docs" / "schemas" / "examples" / "minimal-valid-bundle.json"
)

RFC8032_SECRET = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
RFC8032_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
RFC8032_SIGNATURE = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb88215"
    "90a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)

KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(RFC8032_SECRET))
RAW_PUBLIC = KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
PUBLIC_B64 = base64.b64encode(RAW_PUBLIC).decode()
KEY_ID = hashlib.sha256(RAW_PUBLIC).hexdigest()[:16]
PEM = KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)

assert RAW_PUBLIC.hex() == RFC8032_PUBLIC
assert KEY.sign(b"").hex() == RFC8032_SIGNATURE


def sign(message: dict[str, Any]) -> str:
    return base64.b64encode(KEY.sign(canonicalize(message))).decode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ts(second: int) -> str:
    return f"2030-01-01T00:00:{second:02d}.000000Z"


class Ledger:
    def __init__(self, ledger_id: str) -> None:
        self.ledger_id = ledger_id
        self.genesis = genesis_hash(ledger_id)
        self.events: list[dict[str, Any]] = []
        self.counter = 0

    def salts(self, size: int) -> bytes:
        self.counter += 1
        return hashlib.sha256(f"golden-salt-{self.counter}".encode()).digest()[:size]

    def append(self, **fields: Any) -> dict[str, Any]:
        seq = len(self.events) + 1
        prev = self.events[-1]["chainHash"] if self.events else self.genesis
        result = _commit_payload(fields["payload"], self.salts)
        content = content_object(
            seq=seq,
            event_id=f"00000000-0000-4000-8000-{seq:012d}",
            event_type=fields["eventType"],
            actor_id=fields["actorId"],
            resource_type=fields["resourceType"],
            resource_id=fields["resourceId"],
            occurred_at=fields.get("occurredAt"),
            timestamp=ts(seq),
            source=fields["source"],
            payload=result.commitments,
        )
        c_hash = content_hash(content)
        event = {
            "seq": seq,
            "eventId": f"00000000-0000-4000-8000-{seq:012d}",
            "eventType": fields["eventType"],
            "actorId": fields["actorId"],
            "resourceType": fields["resourceType"],
            "resourceId": fields["resourceId"],
            "occurredAt": fields.get("occurredAt"),
            "timestamp": ts(seq),
            "source": fields["source"],
            "hashVersion": 1,
            "payloadCommitments": result.commitments,
            "disclosedLeaves": {
                pointer: {"salt": leaf.salt.hex(), "value": leaf.value}
                for pointer, leaf in result.leaves.items()
            },
            "contentHash": c_hash,
            "prevHash": prev,
            "chainHash": chain_hash(prev, c_hash),
        }
        self.events.append(event)
        return event


def selection(actor: str | None) -> dict[str, Any]:
    return {
        "actorId": actor,
        "resourceType": None,
        "resourceId": None,
        "eventType": None,
        "from": None,
        "to": None,
        "seqFrom": None,
        "seqTo": None,
    }


def build_bundle(
    ledger: Ledger,
    actor: str | None,
    chosen: list[int],
    through_seq: int,
    bundle_id: str,
    drop_leaves: list[tuple[int, str]],
) -> dict[str, Any]:
    records = [json.loads(json.dumps(ledger.events[seq - 1])) for seq in chosen]
    for seq, pointer in drop_leaves:
        del next(r for r in records if r["seq"] == seq)["disclosedLeaves"][pointer]
    records_digest = sha(canonicalize(records))
    sel = selection(actor)
    meta = ledger.append(
        eventType="BUNDLE_EXPORTED",
        actorId="golden-auditor",
        resourceType="AUDIT_BUNDLE",
        resourceId=bundle_id,
        source="system",
        payload={
            "bundleId": bundle_id,
            "purpose": "EXPORT",
            "throughSeq": through_seq,
            "recordCount": len(records),
            "recordsDigest": records_digest,
            "selectionDigest": sha(canonicalize(sel)),
            "requestedBy": "golden-auditor",
        },
    )
    message = {
        "type": "audit-checkpoint/v1",
        "ledgerId": ledger.ledger_id,
        "seq": meta["seq"],
        "chainHash": meta["chainHash"],
        "createdAt": meta["timestamp"],
    }
    body: dict[str, Any] = {
        "format": "audit-export-bundle/v1",
        "bundleId": bundle_id,
        "purpose": "EXPORT",
        "ledgerId": ledger.ledger_id,
        "hashAlgorithm": "SHA-256",
        "hashVersion": 1,
        "genesisHash": ledger.genesis,
        "signatureAlgorithm": "Ed25519",
        "exportedAt": meta["timestamp"],
        "exportedBy": "golden-auditor",
        "selection": sel,
        "completeness": {
            "scope": "MATCHING_RETAINED_LIVE_RECORDS",
            "throughSeq": through_seq,
            "archivedRecordsExcluded": True,
            "upstreamCoverage": "NOT_PROVEN",
            "assurance": "SIGNED_ASSERTION",
        },
        "recordCount": len(records),
        "recordsDigest": records_digest,
        "records": records,
        "headCheckpoint": {
            "seq": meta["seq"],
            "chainHash": meta["chainHash"],
            "createdAt": meta["timestamp"],
            "keyId": KEY_ID,
            "signature": sign(message),
        },
        "signer": {"keyId": KEY_ID, "publicKey": PUBLIC_B64},
    }
    body["signature"] = sign(body)
    return body


def make_gapped() -> dict[str, Any]:
    ledger = Ledger("golden-test-ledger")
    ledger.append(
        eventType="NOTE",
        actorId="alice",
        resourceType="DOC",
        resourceId="d1",
        source="api:golden",
        payload={"note": "first", "n": 1},
    )
    ledger.append(
        eventType="NOTE",
        actorId="bob",
        resourceType="DOC",
        resourceId="d2",
        source="api:golden",
        payload={"note": "other"},
    )
    ledger.append(
        eventType="NOTE",
        actorId="alice",
        resourceType="DOC",
        resourceId="d3",
        source="api:golden",
        payload={"secret": "s3", "nested": {"k": [1, None, "x/y~z"]}},
    )
    return build_bundle(ledger, "alice", [1, 3], 3, "golden-bundle-gapped", [])


def make_partial() -> dict[str, Any]:
    ledger = Ledger("golden-test-ledger")
    ledger.append(
        eventType="NOTE",
        actorId="alice",
        resourceType="DOC",
        resourceId="d1",
        source="api:golden",
        payload={"note": "first", "n": 1},
    )
    ledger.append(
        eventType="NOTE",
        actorId="bob",
        resourceType="DOC",
        resourceId="d2",
        source="api:golden",
        payload={"note": "other"},
    )
    ledger.append(
        eventType="NOTE",
        actorId="alice",
        resourceType="DOC",
        resourceId="d3",
        source="api:golden",
        payload={"secret": "s3", "nested": {"k": [1, None, "x/y~z"]}},
    )
    return build_bundle(
        ledger, "alice", [1, 3], 3, "golden-bundle-partial", [(3, "/secret")]
    )


def make_empty() -> dict[str, Any]:
    ledger = Ledger("golden-empty-ledger")
    return build_bundle(ledger, "nobody", [], 0, "golden-bundle-empty", [])


def render(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def outputs() -> dict[Path, str]:
    empty = render(make_empty())
    return {
        OUT / "gapped.json": render(make_gapped()),
        OUT / "partial.json": render(make_partial()),
        OUT / "empty.json": empty,
        OUT / "test_key_private.pem": PEM.decode(),
        OUT / "test_key_public.b64": PUBLIC_B64 + "\n",
        OUT / "vectors.json": render(
            {
                "rfc8032Test1": {
                    "secret": RFC8032_SECRET,
                    "public": RFC8032_PUBLIC,
                    "messageEmpty": True,
                    "signatureHex": RFC8032_SIGNATURE,
                },
                "keyId": KEY_ID,
                "publicKeyBase64": PUBLIC_B64,
            }
        ),
        EXAMPLE: empty,
    }


def main() -> int:
    files = outputs()
    if "--check" in sys.argv:
        stale = [
            str(p)
            for p, text in files.items()
            if not p.exists() or p.read_bytes().decode().replace("\r\n", "\n") != text
        ]
        if stale:
            print("Stale fixtures:", *stale, sep="\n  ")
            return 1
        return 0
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
