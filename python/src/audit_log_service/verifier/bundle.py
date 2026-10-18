"""Offline verification of audit-export-bundle/v1 evidence (independent).

Imports nothing from the Java service or the Starlette service. Findings are
collected, not raised: the first 100 in discovery order are kept, total is exact.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from audit_log_service.verifier.jcs import (
    MAX_SAFE_INTEGER,
    DepthError,
    JsonError,
    canonicalize,
    parse_strict,
)

DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_RECORDS = 100_000
MAX_LEAVES_PER_RECORD = 500
MAX_DIAGNOSTICS = 100

VERIFIED = "VERIFIED"
UNTRUSTED = "INTEGRITY_VALID_ORIGIN_UNTRUSTED"
INVALID = "INVALID"

BUNDLE_FIELDS = frozenset(
    "format bundleId purpose ledgerId hashAlgorithm hashVersion genesisHash "
    "signatureAlgorithm exportedAt exportedBy selection completeness recordCount "
    "recordsDigest records headCheckpoint signer signature".split()
)
RECORD_FIELDS = frozenset(
    "seq eventId eventType actorId resourceType resourceId occurredAt timestamp "
    "source hashVersion payloadCommitments disclosedLeaves contentHash prevHash "
    "chainHash".split()
)
SELECTION_FIELDS = frozenset(
    "actorId resourceType resourceId eventType from to seqFrom seqTo".split()
)
PURPOSES = frozenset({"EXPORT", "RETENTION_ARCHIVE", "COMPLIANCE_REPORT"})
STANDARD_NOTICE = (
    "A valid result proves signer identity (when the key is pinned) and internal "
    "consistency only. It does not prove the source ledger was intact, that omitted "
    "records do not exist, or that redactions were authorized."
)

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")


class InputError(Exception):
    """Bad arguments or unreadable input: CLI exit code 2."""


@dataclass(frozen=True)
class Options:
    pinned_key: str | None = None
    allow_self_asserted: bool = False
    max_bytes: int = DEFAULT_MAX_BYTES
    max_records: int = DEFAULT_MAX_RECORDS


@dataclass
class Diagnostics:
    items: list[dict[str, Any]] = field(default_factory=list)
    total: int = 0

    def add(
        self, code: str, message: str, seq: int | None = None, pointer: str = ""
    ) -> None:
        self.total += 1
        if len(self.items) < MAX_DIAGNOSTICS:
            self.items.append(
                {"code": code, "seq": seq, "pointer": pointer, "message": message}
            )


@dataclass
class Result:
    status: str
    origin_trusted: bool
    ledger_id: str | None
    bundle_id: str | None
    key_id: str | None
    record_count: int
    undisclosed_leaf_count: int
    diagnostics: list[dict[str, Any]]
    total_diagnostic_count: int
    notices: list[str]

    @property
    def valid(self) -> bool:
        return self.status != INVALID

    @property
    def diagnostics_truncated(self) -> bool:
        return self.total_diagnostic_count > len(self.diagnostics)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def domain_hash(domain: str, *parts: bytes) -> str:
    return sha256_hex(domain.encode() + b"\x00" + b"".join(parts))


def genesis(ledger_id: str) -> str:
    return domain_hash("audit-log/genesis/v1", ledger_id.encode("utf-8"))


def leaf_hash(salt_hex: str, pointer: str, value: Any) -> str:
    return domain_hash(
        "audit-log/leaf/v1",
        bytes.fromhex(salt_hex) + b"\x00" + pointer.encode() + b"\x00",
        canonicalize(value),
    )


def key_id_for(raw_public: bytes) -> str:
    return sha256_hex(raw_public)[:16]


def decode_b64(text: Any, length: int) -> bytes | None:
    """Canonical standard Base64 of exactly length bytes, else None."""
    if not isinstance(text, str):
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != length or base64.b64encode(raw).decode() != text:
        return None
    return raw


def is_int(value: Any, low: int = 0, high: int = MAX_SAFE_INTEGER) -> bool:
    return (
        isinstance(value, int) and not isinstance(value, bool) and low <= value <= high
    )


def is_text(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def is_hex64(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.match(value) is not None


def is_ts(value: Any) -> bool:
    if not isinstance(value, str) or not _TS.match(value):
        return False
    try:
        datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return False
    return True


def verify_signature(raw_public: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(raw_public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def exact_keys(obj: Any, keys: frozenset[str]) -> bool:
    return isinstance(obj, dict) and set(obj) == keys


def check_selection(sel: Any, purpose: Any, d: Diagnostics) -> bool:
    ok = True

    def bad(message: str) -> None:
        nonlocal ok
        ok = False
        d.add("BUNDLE_SCHEMA_INVALID", message, pointer="/selection")

    if not exact_keys(sel, SELECTION_FIELDS):
        bad("selection must have exactly the eight selection fields")
        return False
    for name in ("actorId", "resourceType", "resourceId", "eventType"):
        v = sel[name]
        if v is not None and (not is_text(v) or len(v.encode()) > 1024):
            bad(f"selection.{name} must be null or non-empty text")
    for name in ("from", "to"):
        if sel[name] is not None and not is_ts(sel[name]):
            bad(f"selection.{name} must be null or a canonical timestamp")
    if is_ts(sel["from"]) and is_ts(sel["to"]) and sel["from"] > sel["to"]:
        bad("selection.from is after selection.to")
    for name in ("seqFrom", "seqTo"):
        if sel[name] is not None and not is_int(sel[name], 1):
            bad(f"selection.{name} must be null or a positive safe integer")
    if (
        is_int(sel["seqFrom"], 1)
        and is_int(sel["seqTo"], 1)
        and sel["seqFrom"] > sel["seqTo"]
    ):
        bad("selection.seqFrom is after selection.seqTo")
    has_seq = sel["seqFrom"] is not None or sel["seqTo"] is not None
    filters = any(
        sel[n] is not None
        for n in ("actorId", "resourceType", "resourceId", "eventType", "from", "to")
    )
    if purpose == "EXPORT" and (
        (sel["actorId"] is None and sel["resourceId"] is None) or has_seq
    ):
        bad("EXPORT needs actorId or resourceId and no sequence bounds")
    if purpose == "RETENTION_ARCHIVE" and (filters or not has_seq):
        bad("RETENTION_ARCHIVE uses sequence bounds and no ordinary filters")
    return ok


def check_completeness(c: Any, d: Diagnostics) -> bool:
    keys = frozenset(
        {
            "scope",
            "throughSeq",
            "archivedRecordsExcluded",
            "upstreamCoverage",
            "assurance",
        }
    )
    if not (
        exact_keys(c, keys)
        and c["scope"] == "MATCHING_RETAINED_LIVE_RECORDS"
        and is_int(c["throughSeq"])
        and c["archivedRecordsExcluded"] is True
        and c["upstreamCoverage"] == "NOT_PROVEN"
        and c["assurance"] == "SIGNED_ASSERTION"
    ):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "completeness is malformed",
            pointer="/completeness",
        )
        return False
    return True


def check_head_checkpoint(c: Any, d: Diagnostics) -> bool:
    keys = frozenset({"seq", "chainHash", "createdAt", "keyId", "signature"})
    if not (
        exact_keys(c, keys)
        and is_int(c["seq"], 1)
        and is_hex64(c["chainHash"])
        and is_ts(c["createdAt"])
        and isinstance(c["keyId"], str)
        and _HEX16.match(c["keyId"])
        and decode_b64(c["signature"], 64) is not None
    ):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "headCheckpoint is malformed",
            pointer="/headCheckpoint",
        )
        return False
    return True


def check_signer(s: Any, d: Diagnostics) -> bool:
    if not (
        exact_keys(s, frozenset({"keyId", "publicKey"}))
        and isinstance(s["keyId"], str)
        and _HEX16.match(s["keyId"])
        and decode_b64(s["publicKey"], 32) is not None
    ):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "signer must hold a key id and a canonical Base64 raw 32-byte public key",
            pointer="/signer",
        )
        return False
    return True


def check_header(
    body: dict[str, Any], fmt: str, time_field: str, d: Diagnostics
) -> bool:
    """Checks shared by bundle and manifest. Returns False if structure is unusable."""
    ok = True
    if body.get("format") != fmt:
        d.add("UNSUPPORTED_FORMAT", "Unsupported format", pointer="/format")
        return False
    for name in ("ledgerId", "exportedBy"):
        if not is_text(body.get(name)):
            d.add(
                "BUNDLE_SCHEMA_INVALID",
                f"{name} must be non-empty text",
                pointer=f"/{name}",
            )
            ok = False
    if not is_ts(body.get(time_field)):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            f"{time_field} must be a canonical timestamp",
            pointer=f"/{time_field}",
        )
        ok = False
    if (
        body.get("hashAlgorithm") != "SHA-256"
        or body.get("signatureAlgorithm") != "Ed25519"
    ):
        d.add(
            "UNSUPPORTED_ALGORITHM", "Unsupported algorithm", pointer="/hashAlgorithm"
        )
        ok = False
    if not is_int(body.get("hashVersion"), -MAX_SAFE_INTEGER):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "hashVersion must be an integer",
            pointer="/hashVersion",
        )
        ok = False
    elif body["hashVersion"] != 1:
        d.add(
            "UNSUPPORTED_ALGORITHM", "Unsupported hash version", pointer="/hashVersion"
        )
        ok = False
    if not is_hex64(body.get("genesisHash")):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "genesisHash must be 64 lowercase hex",
            pointer="/genesisHash",
        )
        ok = False
    ok &= check_completeness(body.get("completeness"), d)
    ok &= check_head_checkpoint(body.get("headCheckpoint"), d)
    ok &= check_signer(body.get("signer"), d)
    if decode_b64(body.get("signature"), 64) is None:
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "signature must be canonical Base64 of 64 bytes",
            pointer="/signature",
        )
        ok = False
    return ok


def check_trust_and_signature(
    body: dict[str, Any], options: Options, d: Diagnostics
) -> tuple[bool, str]:
    """Pinning, key id, body signature, genesis and checkpoint signature."""
    signer = body["signer"]
    raw = decode_b64(signer["publicKey"], 32)
    assert raw is not None
    key_usable = True
    if key_id_for(raw) != signer["keyId"]:
        d.add(
            "KEY_ID_MISMATCH",
            "signer.keyId does not match the public key",
            pointer="/signer/keyId",
        )
        key_usable = False
    pinned = decode_b64(options.pinned_key, 32) if options.pinned_key else None
    trusted = False
    if pinned is not None:
        if hmac.compare_digest(pinned, raw):
            trusted = True
        else:
            d.add(
                "SIGNER_KEY_MISMATCH",
                "Signer key differs from the pinned key",
                pointer="/signer/publicKey",
            )
            key_usable = False
    elif not options.allow_self_asserted:
        d.add(
            "TRUSTED_KEY_REQUIRED",
            "A pinned key or --allow-self-asserted is required",
            pointer="/signer",
        )
    if key_usable:
        unsigned = {k: v for k, v in body.items() if k != "signature"}
        signature = decode_b64(body["signature"], 64)
        assert signature is not None
        if not verify_signature(raw, signature, canonicalize(unsigned)):
            d.add(
                "BUNDLE_SIGNATURE_INVALID",
                "Body signature is invalid",
                pointer="/signature",
            )
    if body["genesisHash"] != genesis(body["ledgerId"]):
        d.add(
            "GENESIS_MISMATCH",
            "genesisHash does not match the ledger id",
            pointer="/genesisHash",
        )
    head = body["headCheckpoint"]
    if head["keyId"] != signer["keyId"]:
        d.add(
            "KEY_ID_MISMATCH",
            "Checkpoint key differs from the signer",
            pointer="/headCheckpoint/keyId",
        )
    elif key_usable:
        message = {
            "type": "audit-checkpoint/v1",
            "ledgerId": body["ledgerId"],
            "seq": head["seq"],
            "chainHash": head["chainHash"],
            "createdAt": head["createdAt"],
        }
        csig = decode_b64(head["signature"], 64)
        assert csig is not None
        if not verify_signature(raw, csig, canonicalize(message)):
            d.add(
                "CHECKPOINT_SIGNATURE_INVALID",
                "Checkpoint signature is invalid",
                pointer="/headCheckpoint/signature",
            )
    return trusted, signer["keyId"]


def _walk(tree: Any, pointer: str, out: dict[str, str]) -> bool:
    """Collect pointer -> commitment; False on a non-commitment scalar."""
    stack: list[tuple[Any, str]] = [(tree, pointer)]
    while stack:
        node, path = stack.pop()
        if isinstance(node, dict):
            for key, child in node.items():
                escaped = key.replace("~", "~0").replace("/", "~1")
                stack.append((child, f"{path}/{escaped}"))
        elif isinstance(node, list):
            for index, child in enumerate(node):
                stack.append((child, f"{path}/{index}"))
        elif is_hex64(node):
            out[path] = node
        else:
            return False
    return True


class RecordChecker:
    """Validates records; chain state persists across export-set chunks."""

    def __init__(
        self,
        ledger_id: str,
        selection: dict[str, Any],
        through_seq: int,
        head: dict[str, Any],
        d: Diagnostics,
    ) -> None:
        self.ledger_id = ledger_id
        self.genesis = genesis(ledger_id)
        self.selection = selection
        self.through_seq = through_seq
        self.head = head
        self.d = d
        self.prev_seq: int | None = None
        self.prev_chain: str | None = None
        self.undisclosed = 0
        self.count = 0

    def _shape_ok(self, r: Any, index: int) -> bool:
        pointer = f"/records/{index}"
        if not exact_keys(r, RECORD_FIELDS):
            self.d.add(
                "BUNDLE_SCHEMA_INVALID", "Record has the wrong fields", pointer=pointer
            )
            return False
        good = (
            is_int(r["seq"], 1)
            and all(
                is_text(r[n])
                for n in (
                    "eventId",
                    "eventType",
                    "actorId",
                    "resourceType",
                    "resourceId",
                    "source",
                )
            )
            and is_ts(r["timestamp"])
            and (r["occurredAt"] is None or is_ts(r["occurredAt"]))
            and is_int(r["hashVersion"], -MAX_SAFE_INTEGER)
            and all(is_hex64(r[n]) for n in ("contentHash", "prevHash", "chainHash"))
            and isinstance(r["payloadCommitments"], dict)
            and isinstance(r["disclosedLeaves"], dict)
        )
        if not good:
            self.d.add(
                "BUNDLE_SCHEMA_INVALID", "Record field is malformed", pointer=pointer
            )
            return False
        if r["hashVersion"] != 1:
            self.d.add(
                "UNSUPPORTED_ALGORITHM",
                "Unsupported record hash version",
                r["seq"],
                pointer,
            )
            return False
        return True

    def _matches(self, r: dict[str, Any]) -> bool:
        s = self.selection
        for name in ("actorId", "resourceType", "resourceId", "eventType"):
            if s[name] is not None and r[name] != s[name]:
                return False
        if s["from"] is not None and r["timestamp"] < s["from"]:
            return False
        if s["to"] is not None and r["timestamp"] > s["to"]:
            return False
        if s["seqFrom"] is not None and r["seq"] < s["seqFrom"]:
            return False
        return s["seqTo"] is None or r["seq"] <= s["seqTo"]

    def _leaves(self, r: dict[str, Any], seq: int, pointer: str) -> None:
        expected: dict[str, str] = {}
        if not _walk(r["payloadCommitments"], "", expected):
            self.d.add(
                "BUNDLE_SCHEMA_INVALID",
                "Commitment tree holds a non-commitment",
                seq,
                pointer,
            )
            return
        if (
            len(expected) > MAX_LEAVES_PER_RECORD
            or len(r["disclosedLeaves"]) > MAX_LEAVES_PER_RECORD
        ):
            self.d.add(
                "RESOURCE_LIMIT_EXCEEDED", "Too many leaves in a record", seq, pointer
            )
            return
        matched = 0
        for leaf_pointer, leaf in r["disclosedLeaves"].items():
            where = f"{pointer}/disclosedLeaves/{leaf_pointer}"
            commitment = expected.get(leaf_pointer)
            if (
                commitment is None
                or not exact_keys(leaf, frozenset({"salt", "value"}))
                or not isinstance(leaf["salt"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", leaf["salt"])
                or isinstance(leaf["value"], (dict, list))
            ):
                self.d.add(
                    "LEAF_COMMITMENT_MISMATCH",
                    "Disclosed leaf does not fit the commitment tree",
                    seq,
                    where,
                )
                continue
            if leaf_hash(leaf["salt"], leaf_pointer, leaf["value"]) != commitment:
                self.d.add(
                    "LEAF_COMMITMENT_MISMATCH",
                    "Disclosed leaf does not match its commitment",
                    seq,
                    where,
                )
            else:
                matched += 1
        self.undisclosed += len(expected) - matched

    def check(self, r: Any, index: int) -> None:
        pointer = f"/records/{index}"
        self.count += 1
        if not self._shape_ok(r, index):
            self.prev_seq = self.prev_chain = None
            return
        seq = r["seq"]
        if self.prev_seq is not None and seq <= self.prev_seq:
            self.d.add(
                "RECORD_ORDER_INVALID", "seq is not strictly increasing", seq, pointer
            )
        if seq > self.through_seq or seq > self.head["seq"]:
            self.d.add(
                "RECORD_OUT_OF_RANGE",
                "Record is newer than the declared head",
                seq,
                pointer,
            )
        elif seq == self.head["seq"] and r["chainHash"] != self.head["chainHash"]:
            self.d.add(
                "CHECKPOINT_MISMATCH",
                "Head record differs from the checkpoint",
                seq,
                pointer,
            )
        if not self._matches(r):
            self.d.add(
                "SELECTION_MISMATCH",
                "Record does not match the selection",
                seq,
                pointer,
            )
        self._leaves(r, seq, pointer)
        content = {
            "v": 1,
            "seq": seq,
            "eventId": r["eventId"],
            "eventType": r["eventType"],
            "actorId": r["actorId"],
            "resourceType": r["resourceType"],
            "resourceId": r["resourceId"],
            "occurredAt": r["occurredAt"],
            "recordedAt": r["timestamp"],
            "source": r["source"],
            "payload": r["payloadCommitments"],
        }
        try:
            content_hash = domain_hash("audit-log/content/v1", canonicalize(content))
        except JsonError:
            self.d.add(
                "BUNDLE_SCHEMA_INVALID", "Record cannot be canonicalized", seq, pointer
            )
            self.prev_seq = self.prev_chain = None
            return
        if content_hash != r["contentHash"]:
            self.d.add(
                "CONTENT_HASH_MISMATCH",
                "contentHash does not match the record",
                seq,
                pointer,
            )
        chain = domain_hash(
            "audit-log/chain/v1",
            bytes.fromhex(r["prevHash"]) + bytes.fromhex(r["contentHash"]),
        )
        if chain != r["chainHash"]:
            self.d.add(
                "CHAIN_HASH_MISMATCH",
                "chainHash does not match prevHash and contentHash",
                seq,
                pointer,
            )
        if seq == 1 and r["prevHash"] != self.genesis:
            self.d.add(
                "GENESIS_MISMATCH", "Record 1 does not start at genesis", seq, pointer
            )
        if (
            self.prev_seq is not None
            and seq == self.prev_seq + 1
            and r["prevHash"] != self.prev_chain
        ):
            self.d.add(
                "CHAIN_LINK_BROKEN",
                "prevHash does not match the previous record",
                seq,
                pointer,
            )
        self.prev_seq = seq
        self.prev_chain = r["chainHash"]


def parse_input(raw: bytes, options: Options, d: Diagnostics) -> dict[str, Any] | None:
    if len(raw) > options.max_bytes:
        d.add("RESOURCE_LIMIT_EXCEEDED", "Input exceeds the byte limit")
        return None
    if not raw:
        d.add("BUNDLE_SCHEMA_INVALID", "Input is empty")
        return None
    try:
        value = parse_strict(raw)
    except DepthError:
        d.add("RESOURCE_LIMIT_EXCEEDED", "JSON nesting is too deep")
        return None
    except JsonError as error:
        d.add("BUNDLE_SCHEMA_INVALID", str(error))
        return None
    if not isinstance(value, dict):
        d.add("BUNDLE_SCHEMA_INVALID", "Root must be a JSON object")
        return None
    return value


def validate_options(options: Options) -> None:
    if options.pinned_key is not None and options.allow_self_asserted:
        raise InputError("A pinned key and allow-self-asserted are mutually exclusive")
    if options.pinned_key is not None and decode_b64(options.pinned_key, 32) is None:
        raise InputError(
            "Pinned key must be canonical Base64 of 32 raw public-key bytes"
        )
    if options.max_bytes < 1 or options.max_records < 1:
        raise InputError("Limits must be positive")


def finish(
    d: Diagnostics,
    options: Options,
    trusted: bool,
    body: dict[str, Any] | None,
    key_id: str | None,
    records: int,
    undisclosed: int,
) -> Result:
    notices = [STANDARD_NOTICE]
    if d.total:
        status = INVALID
    elif trusted:
        status = VERIFIED
    else:
        status = UNTRUSTED
        notices.append(
            "UNTRUSTED ORIGIN: the signer key came from the evidence itself."
        )
    body = body or {}
    ledger = body.get("ledgerId")
    bundle = body.get("bundleId") or body.get("exportSetId")
    return Result(
        status,
        trusted and status == VERIFIED,
        ledger if isinstance(ledger, str) else None,
        bundle if isinstance(bundle, str) else None,
        key_id,
        records,
        undisclosed,
        d.items,
        d.total,
        notices,
    )


def verify_bundle(raw: bytes, options: Options | None = None) -> Result:
    options = options or Options()
    validate_options(options)
    d = Diagnostics()
    body = parse_input(raw, options, d)
    if body is None:
        return finish(d, options, False, None, None, 0, 0)
    if set(body) != BUNDLE_FIELDS:
        d.add("BUNDLE_SCHEMA_INVALID", "Bundle must have exactly the v1 fields")
        return finish(d, options, False, body, None, 0, 0)
    ok = check_header(body, "audit-export-bundle/v1", "exportedAt", d)
    if not is_text(body["bundleId"]):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "bundleId must be non-empty text",
            pointer="/bundleId",
        )
        ok = False
    if body["purpose"] not in PURPOSES:
        d.add("BUNDLE_SCHEMA_INVALID", "Unknown purpose", pointer="/purpose")
        ok = False
    ok &= check_selection(body["selection"], body["purpose"], d)
    if not is_hex64(body["recordsDigest"]):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "recordsDigest must be 64 lowercase hex",
            pointer="/recordsDigest",
        )
        ok = False
    if not is_int(body["recordCount"]):
        d.add(
            "BUNDLE_SCHEMA_INVALID",
            "recordCount must be a safe integer",
            pointer="/recordCount",
        )
        ok = False
    records = body["records"]
    if not isinstance(records, list):
        d.add("BUNDLE_SCHEMA_INVALID", "records must be an array", pointer="/records")
        ok = False
    elif len(records) > options.max_records:
        d.add("RESOURCE_LIMIT_EXCEEDED", "Too many records", pointer="/records")
        ok = False
    if not ok:
        return finish(d, options, False, body, None, 0, 0)
    trusted, key_id = check_trust_and_signature(body, options, d)
    if body["recordCount"] != len(records):
        d.add(
            "RECORD_COUNT_MISMATCH",
            "recordCount differs from the records array",
            pointer="/recordCount",
        )
    if sha256_hex(canonicalize(records)) != body["recordsDigest"]:
        d.add(
            "RECORDS_DIGEST_MISMATCH",
            "recordsDigest does not match the records",
            pointer="/recordsDigest",
        )
    head = body["headCheckpoint"]
    through = body["completeness"]["throughSeq"]
    if head["seq"] < through:
        d.add(
            "CHECKPOINT_MISMATCH",
            "Checkpoint is older than throughSeq",
            pointer="/headCheckpoint/seq",
        )
    checker = RecordChecker(body["ledgerId"], body["selection"], through, head, d)
    for index, record in enumerate(records):
        checker.check(record, index)
    return finish(d, options, trusted, body, key_id, len(records), checker.undisclosed)
