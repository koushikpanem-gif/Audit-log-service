"""Generate Python-signed edge-case bundle and export-set fixtures.

TEST ONLY: uses the public RFC 8032 TEST 1 key from generate_bundle_vectors.py and
deterministic salts. The ledger covers Unicode, doubles, null, empty containers and a
redacted (undisclosed) leaf. Java verifies these files in PythonSignedFixtureTests.

    python tests/fixtures/generate_verifier_vectors.py          # (re)write
    python tests/fixtures/generate_verifier_vectors.py --check  # fail if stale
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_bundle_vectors import (  # noqa: E402
    KEY_ID,
    PUBLIC_B64,
    Ledger,
    selection,
    sha,
    sign,
)

from audit_log_service.canonical_json import canonicalize  # noqa: E402

HERE = Path(__file__).resolve().parent
OUT = HERE / "python_signed"
LEDGER_ID = "interop-ledger-é"
SET_ID = "interop-set-1"
TAIL = "2030-01-02T00:00:00.000000Z"

UNICODE_PAYLOAD: dict[str, Any] = {
    "text": "Zoë € 𝄞 \u2028 tab\t",
    "nothing": None,
    "double": 0.1,
    "big": 1e21,
    "negZero": -0.0,
    "tiny": 1e-7,
    "safeMax": 9007199254740991,
    "emptyObject": {},
    "emptyArray": [],
    "k/~": {"a": [{}, [], None, 1.5, "x"]},
}


def build_ledger() -> Ledger:
    ledger = Ledger(LEDGER_ID)
    base = {"resourceType": "DOC", "source": "api:interop", "eventType": "NOTE"}
    ledger.append(actorId="alice", resourceId="d1", payload=UNICODE_PAYLOAD, **base)
    ledger.append(actorId="bob", resourceId="d2", payload={"n": 1}, **base)
    ledger.append(actorId="alice", resourceId="d3", payload={"secret": "s"}, **base)
    ledger.append(actorId="alice", resourceId="d4", payload={"k": [None]}, **base)
    ledger.append(actorId="bob", resourceId="d5", payload={}, **base)
    return ledger


def checkpoint(meta: dict[str, Any], ledger: Ledger) -> dict[str, Any]:
    message = {
        "type": "audit-checkpoint/v1",
        "ledgerId": ledger.ledger_id,
        "seq": meta["seq"],
        "chainHash": meta["chainHash"],
        "createdAt": meta["timestamp"],
    }
    return {
        "seq": meta["seq"],
        "chainHash": meta["chainHash"],
        "createdAt": meta["timestamp"],
        "keyId": KEY_ID,
        "signature": sign(message),
    }


def chosen_records(ledger: Ledger) -> list[dict[str, Any]]:
    records = [json.loads(json.dumps(ledger.events[i])) for i in (0, 2, 3)]
    del records[1]["disclosedLeaves"]["/secret"]
    return records


def meta_event(ledger: Ledger, kind: str, ident: str) -> dict[str, Any]:
    return ledger.append(
        eventType="BUNDLE_EXPORTED",
        actorId="interop-auditor",
        resourceType="AUDIT_BUNDLE",
        resourceId=ident,
        source="system",
        payload={"bundleId": ident, "kind": kind},
    )


def make_bundle() -> dict[str, Any]:
    ledger = build_ledger()
    records = chosen_records(ledger)
    meta = meta_event(ledger, "bundle", "interop-bundle")
    body: dict[str, Any] = {
        "format": "audit-export-bundle/v1",
        "bundleId": "interop-bundle",
        "purpose": "EXPORT",
        "ledgerId": LEDGER_ID,
        "hashAlgorithm": "SHA-256",
        "hashVersion": 1,
        "genesisHash": ledger.genesis,
        "signatureAlgorithm": "Ed25519",
        "exportedAt": meta["timestamp"],
        "exportedBy": "interop-auditor",
        "selection": selection("alice"),
        "completeness": completeness(5),
        "recordCount": len(records),
        "recordsDigest": sha(canonicalize(records)),
        "records": records,
        "headCheckpoint": checkpoint(meta, ledger),
        "signer": {"keyId": KEY_ID, "publicKey": PUBLIC_B64},
    }
    body["signature"] = sign(body)
    return body


def completeness(through: int) -> dict[str, Any]:
    return {
        "scope": "MATCHING_RETAINED_LIVE_RECORDS",
        "throughSeq": through,
        "archivedRecordsExcluded": True,
        "upstreamCoverage": "NOT_PROVEN",
        "assurance": "SIGNED_ASSERTION",
    }


def make_export_set() -> dict[str, bytes]:
    ledger = build_ledger()
    records = chosen_records(ledger)
    head = ledger.events[4]
    meta = meta_event(ledger, "set", SET_ID)
    files: dict[str, bytes] = {}
    entries = []
    for index, part in enumerate([records[:2], records[2:]]):
        data = canonicalize(
            {
                "format": "audit-export-chunk/v1",
                "exportSetId": SET_ID,
                "index": index,
                "records": part,
            }
        )
        name = f"chunk-{index:06d}.json"
        files[name] = data
        entries.append(
            {
                "index": index,
                "name": name,
                "recordCount": len(part),
                "firstSeq": part[0]["seq"],
                "lastSeq": part[-1]["seq"],
                "bytes": len(data),
                "sha256": sha(data),
            }
        )
    manifest: dict[str, Any] = {
        "format": "audit-export-set-manifest/v1",
        "exportSetId": SET_ID,
        "purpose": "EXPORT",
        "ledgerId": LEDGER_ID,
        "hashAlgorithm": "SHA-256",
        "hashVersion": 1,
        "genesisHash": ledger.genesis,
        "signatureAlgorithm": "Ed25519",
        "createdAt": meta["timestamp"],
        "expiresAt": TAIL,
        "exportedBy": "interop-auditor",
        "selection": selection("alice"),
        "completeness": completeness(5),
        "selectionHead": {"seq": 5, "chainHash": head["chainHash"]},
        "headCheckpoint": checkpoint(meta, ledger),
        "totalRecords": 3,
        "chunkCount": 2,
        "chunkLimits": {"maxRecords": 2, "maxBytes": 1048576},
        "chunks": entries,
        "chunksDigest": sha(canonicalize(entries)),
        "exclusions": {
            "archivedRecords": "EXCLUDED",
            "nonMatchingRecords": "EXCLUDED",
            "recordsAfterSelectionHead": "EXCLUDED",
            "upstreamCoverage": "NOT_PROVEN",
        },
        "signer": {"keyId": KEY_ID, "publicKey": PUBLIC_B64},
    }
    manifest["signature"] = sign(manifest)
    files["manifest.json"] = canonicalize(manifest)
    return files


def outputs() -> dict[Path, bytes]:
    result = {OUT / "bundle.json": canonicalize(make_bundle())}
    for name, data in make_export_set().items():
        result[OUT / "export_set" / name] = data
    return result


def main() -> int:
    files = outputs()
    if "--check" in sys.argv:
        stale = [
            str(p)
            for p, data in files.items()
            if not p.exists() or p.read_bytes() != data
        ]
        if stale:
            print("Stale fixtures:", *stale, sep="\n  ")
            return 1
        return 0
    for path, data in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
