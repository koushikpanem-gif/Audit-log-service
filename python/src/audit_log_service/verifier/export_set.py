"""Offline verification of audit-export-set-manifest/v1 with its chunk files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from audit_log_service.verifier.bundle import (
    INVALID,
    Diagnostics,
    InputError,
    Options,
    RecordChecker,
    Result,
    check_header,
    check_selection,
    check_trust_and_signature,
    exact_keys,
    finish,
    genesis,
    is_hex64,
    is_int,
    is_text,
    is_ts,
    parse_input,
    sha256_hex,
    validate_options,
)
from audit_log_service.verifier.jcs import JsonError, canonicalize, parse_strict

DEFAULT_MAX_RECORDS = 10_000_000
MAX_CHUNKS = 100_000
MANIFEST_FIELDS = frozenset(
    "format exportSetId purpose ledgerId hashAlgorithm hashVersion genesisHash "
    "signatureAlgorithm createdAt expiresAt exportedBy selection completeness "
    "selectionHead headCheckpoint totalRecords chunkCount chunkLimits chunks "
    "chunksDigest exclusions signer signature".split()
)
CHUNK_ENTRY_FIELDS = frozenset(
    "index name recordCount firstSeq lastSeq bytes sha256".split()
)
EXCLUSIONS = {
    "archivedRecords": "EXCLUDED",
    "nonMatchingRecords": "EXCLUDED",
    "recordsAfterSelectionHead": "EXCLUDED",
    "upstreamCoverage": "NOT_PROVEN",
}
_CHUNK_NAME = re.compile(r"chunk-[0-9]{6}\.json\Z")


def _check_manifest_fields(m: dict[str, Any], options: Options, d: Diagnostics) -> bool:
    ok = check_header(m, "audit-export-set-manifest/v1", "createdAt", d)
    if not is_text(m["exportSetId"]):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "exportSetId must be non-empty text",
            pointer="/exportSetId",
        )
        ok = False
    if m["purpose"] != "EXPORT":
        d.add(
            "BUNDLE_SCHEMA_INVALID", "Export sets are EXPORT only", pointer="/purpose"
        )
        ok = False
    ok &= check_selection(m["selection"], m["purpose"], d)
    if not is_ts(m["expiresAt"]) or (
        is_ts(m["createdAt"]) and m["expiresAt"] <= m["createdAt"]
    ):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "expiresAt must be a timestamp after createdAt",
            pointer="/expiresAt",
        )
        ok = False
    head = m["selectionHead"]
    if not (
        exact_keys(head, frozenset({"seq", "chainHash"}))
        and is_int(head["seq"])
        and is_hex64(head["chainHash"])
    ):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "selectionHead is malformed",
            pointer="/selectionHead",
        )
        ok = False
    limits = m["chunkLimits"]
    if not (
        exact_keys(limits, frozenset({"maxRecords", "maxBytes"}))
        and is_int(limits["maxRecords"], 1)
        and is_int(limits["maxBytes"], 1)
    ):
        d.add(
            "BUNDLE_SCHEMA_INVALID", "chunkLimits is malformed", pointer="/chunkLimits"
        )
        ok = False
    for name in ("totalRecords", "chunkCount"):
        if not is_int(m[name]):
            d.add(
                "BUNDLE_SCHEMA_INVALID",
                f"{name} must be a safe integer",
                pointer=f"/{name}",
            )
            ok = False
    if not is_hex64(m["chunksDigest"]):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "chunksDigest must be 64 lowercase hex",
            pointer="/chunksDigest",
        )
        ok = False
    if m["exclusions"] != EXCLUSIONS:
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "exclusions must state the standard export-set scope",
            pointer="/exclusions",
        )
        ok = False
    chunks = m["chunks"]
    if not isinstance(chunks, list):
        d.add("BUNDLE_SCHEMA_INVALID", "chunks must be an array", pointer="/chunks")
        return False
    if len(chunks) > MAX_CHUNKS:
        d.add("RESOURCE_LIMIT_EXCEEDED", "Too many chunks", pointer="/chunks")
        return False
    for position, entry in enumerate(chunks):
        if not (
            exact_keys(entry, CHUNK_ENTRY_FIELDS)
            and is_int(entry["index"])
            and isinstance(entry["name"], str)
            and is_int(entry["recordCount"])
            and is_int(entry["firstSeq"], 0)
            and is_int(entry["lastSeq"], 0)
            and is_int(entry["bytes"], 1)
            and is_hex64(entry["sha256"])
        ):
            d.add(
                "BUNDLE_SCHEMA_INVALID",
                "Chunk entry is malformed",
                pointer=f"/chunks/{position}",
            )
            ok = False
    if ok and m["totalRecords"] > options.max_records:
        d.add(
            "RESOURCE_LIMIT_EXCEEDED",
            "totalRecords exceeds the verifier limit",
            pointer="/totalRecords",
        )
        ok = False
    return ok


def _read_chunk(
    directory: Path,
    entry: dict[str, Any],
    position: int,
    limits: dict[str, Any],
    options: Options,
    d: Diagnostics,
) -> bytes | None:
    pointer = f"/chunks/{position}"
    name = entry["name"]
    if not _CHUNK_NAME.match(name):
        d.add(
            "CHUNK_NAME_UNSAFE", "Chunk name is not chunk-NNNNNN.json", pointer=pointer
        )
        return None
    if entry["index"] != position or name != f"chunk-{position:06d}.json":
        d.add(
            "CHUNK_ORDER_INVALID",
            "Chunk index or name is out of order",
            pointer=pointer,
        )
    declared = entry["bytes"]
    if declared > limits["maxBytes"] or declared > options.max_bytes:
        d.add("RESOURCE_LIMIT_EXCEEDED", "Chunk exceeds a byte limit", pointer=pointer)
        return None
    path = directory / name
    try:
        if (
            path.is_symlink()
            or not path.is_file()
            or path.resolve().parent != directory.resolve()
        ):
            d.add(
                "CHUNK_MISSING",
                "Chunk file is missing or not a regular file",
                pointer=pointer,
            )
            return None
        with path.open("rb") as handle:
            data: bytes = handle.read(declared + 1)
    except OSError:
        d.add("CHUNK_MISSING", "Chunk file could not be read", pointer=pointer)
        return None
    if len(data) != declared or sha256_hex(data) != entry["sha256"]:
        d.add(
            "CHUNK_DIGEST_MISMATCH",
            "Chunk size or digest differs from the manifest",
            pointer=pointer,
        )
        return None
    return data


def verify_export_set(manifest_path: Path, options: Options | None = None) -> Result:
    options = options or Options()
    validate_options(options)
    try:
        with manifest_path.open("rb") as handle:
            raw = handle.read(options.max_bytes + 1)
    except OSError as error:
        raise InputError("Manifest file could not be read") from error
    directory = manifest_path.parent
    d = Diagnostics()
    m = parse_input(raw, options, d)
    if m is None:
        return finish(d, options, False, None, None, 0, 0)
    if set(m) != MANIFEST_FIELDS:
        d.add("BUNDLE_SCHEMA_INVALID", "Manifest must have exactly the v1 fields")
        return finish(d, options, False, m, None, 0, 0)
    if not _check_manifest_fields(m, options, d):
        return finish(d, options, False, m, None, 0, 0)
    trusted, key_id = check_trust_and_signature(m, options, d)
    chunks = m["chunks"]
    head = m["selectionHead"]
    if head["seq"] != m["completeness"]["throughSeq"]:
        d.add(
            "CHECKPOINT_MISMATCH",
            "selectionHead differs from completeness.throughSeq",
            pointer="/selectionHead/seq",
        )
    if head["seq"] >= m["headCheckpoint"]["seq"]:
        d.add(
            "CHECKPOINT_MISMATCH",
            "Checkpoint must be later than the selection head",
            pointer="/headCheckpoint/seq",
        )
    if head["seq"] == 0 and head["chainHash"] != genesis(m["ledgerId"]):
        d.add(
            "GENESIS_MISMATCH",
            "Empty selection head must be genesis",
            pointer="/selectionHead/chainHash",
        )
    if sum(c["recordCount"] for c in chunks) != m["totalRecords"]:
        d.add(
            "TOTAL_COUNT_MISMATCH",
            "totalRecords differs from the chunk counts",
            pointer="/totalRecords",
        )
    if m["chunkCount"] != len(chunks):
        d.add(
            "CHUNK_COUNT_MISMATCH",
            "chunkCount differs from the chunk list",
            pointer="/chunkCount",
        )
    if sha256_hex(canonicalize(chunks)) != m["chunksDigest"]:
        d.add(
            "CHUNKS_DIGEST_MISMATCH",
            "chunksDigest does not match the chunk list",
            pointer="/chunksDigest",
        )
    checker = RecordChecker(m["ledgerId"], m["selection"], head["seq"], head, d)
    # Records must not exceed the selection head, so it doubles as the head bound.
    checker.head = {"seq": head["seq"], "chainHash": head["chainHash"]}
    names: set[str] = set()
    seen = 0
    for position, entry in enumerate(chunks):
        if entry["name"] in names:
            d.add(
                "CHUNK_ORDER_INVALID",
                "Duplicate chunk name",
                pointer=f"/chunks/{position}",
            )
            continue
        names.add(entry["name"])
        data = _read_chunk(directory, entry, position, m["chunkLimits"], options, d)
        if data is None:
            continue
        seen += _check_chunk(data, entry, position, m, checker, options, d)
    if not d.total and seen != m["totalRecords"]:
        d.add(
            "TOTAL_COUNT_MISMATCH",
            "Records read differ from totalRecords",
            pointer="/totalRecords",
        )
    try:
        for found in sorted(directory.glob("chunk-*.json")):
            if found.name not in names:
                d.add(
                    "CHUNK_UNEXPECTED",
                    "Unlisted chunk file in the set directory",
                    pointer=found.name,
                )
    except OSError:
        d.add("CHUNK_MISSING", "Set directory could not be listed")
    return finish(d, options, trusted, m, key_id, seen, checker.undisclosed)


def _check_chunk(
    data: bytes,
    entry: dict[str, Any],
    position: int,
    manifest: dict[str, Any],
    checker: RecordChecker,
    options: Options,
    d: Diagnostics,
) -> int:
    pointer = f"/chunks/{position}"
    try:
        chunk = parse_strict(data)
    except JsonError as error:
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            f"Chunk is not valid JSON: {error}",
            pointer=pointer,
        )
        return 0
    if not exact_keys(
        chunk, frozenset({"format", "exportSetId", "index", "records"})
    ) or not isinstance(chunk["records"], list):
        d.add("BUNDLE_SCHEMA_INVALID", "Chunk has the wrong fields", pointer=pointer)
        return 0
    if chunk["format"] != "audit-export-chunk/v1":
        d.add("UNSUPPORTED_FORMAT", "Unsupported chunk format", pointer=pointer)
        return 0
    if (
        chunk["exportSetId"] != manifest["exportSetId"]
        or chunk["index"] != entry["index"]
    ):
        d.add(
            "CHUNK_ORDER_INVALID",
            "Chunk belongs to another set or position",
            pointer=pointer,
        )
        return 0
    records = chunk["records"]
    if len(records) != entry["recordCount"]:
        d.add(
            "CHUNK_COUNT_MISMATCH",
            "Chunk record count differs from the manifest",
            pointer=pointer,
        )
    if (
        records
        and isinstance(records[0], dict)
        and isinstance(records[-1], dict)
        and (
            records[0].get("seq") != entry["firstSeq"]
            or records[-1].get("seq") != entry["lastSeq"]
        )
    ):
        d.add(
            "CHUNK_ORDER_INVALID",
            "Chunk sequence range differs from the manifest",
            pointer=pointer,
        )
    if len(records) > manifest["chunkLimits"]["maxRecords"]:
        d.add(
            "RESOURCE_LIMIT_EXCEEDED", "Chunk exceeds the record limit", pointer=pointer
        )
        return 0
    base = checker.count
    for index, record in enumerate(records):
        checker.check(record, base + index)
    return len(records)


__all__ = ["DEFAULT_MAX_RECORDS", "INVALID", "verify_export_set"]
