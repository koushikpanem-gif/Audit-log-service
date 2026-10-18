"""Internal-auditor account-access report, generated from one write snapshot."""

from __future__ import annotations

import hashlib
import uuid
from collections import Counter
from collections.abc import Callable
from typing import Any, cast

from audit_log_service import account_access
from audit_log_service.canonical_json import MAX_DOCUMENT_DEPTH, canonicalize
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.errors import ApiError, invalid
from audit_log_service.export_bundle import (
    ExportBundleService,
    Selection,
    iter_records,
    parse_selection,
)
from audit_log_service.ledger import AppendService
from audit_log_service.ledger_verifier import LedgerVerifier
from audit_log_service.store import SqliteStore

REPORT_RECORD_CAP = 10_000
UNKNOWN_REDACTED = "UNKNOWN_REDACTED"
UNKNOWN_INVALID = "UNKNOWN_INVALID"
_PERIOD_BASIS = "recordedAt, inclusive UTC"
_TRUSTED = "VERIFIED: ledger integrity checks passed at the verified data head"
_UNTRUSTED = (
    "NOT TRUSTWORTHY: ledger integrity verification failed; the evidence "
    "signature does not repair an invalid ledger"
)
_EXCLUSIONS = [
    "ARCHIVED: events moved to retention archives are excluded; run the archive "
    "audit for them",
    "LIVE_ONLY: only retained-live events at or before the verified data head "
    "are reported",
    "UPSTREAM: events never received from upstream systems cannot be detected by "
    "this ledger",
    "NO_REGULATOR_PORTAL: internal auditor report only; not a legal opinion or "
    "regulator filing",
]
_DIMENSIONS = ("dataCategory", "accessPurpose", "outcome", "accessType")


def _dimension(record: dict[str, Any], field: str) -> str:
    leaf = record["disclosedLeaves"].get("/" + field)
    if leaf is None:
        return UNKNOWN_REDACTED
    value = leaf["value"]
    if isinstance(value, str) and value in account_access.allowed_values(field):
        return value
    return UNKNOWN_INVALID


def _sorted(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


class AccountAccessReportService:
    def __init__(
        self,
        store: SqliteStore,
        configuration: AuditConfiguration,
        verifier: LedgerVerifier,
        appender: AppendService,
        bundles: ExportBundleService,
        record_cap: int = REPORT_RECORD_CAP,
    ) -> None:
        if not 1 <= record_cap <= REPORT_RECORD_CAP:
            raise ValueError("record_cap must be between 1 and 10000")
        self._store = store
        self._configuration = configuration
        self._verifier = verifier
        self._appender = appender
        self._bundles = bundles
        self._cap = record_cap
        # Test seams: invoked inside the write transaction after each phase.
        self.after_verify: Callable[[], None] | None = None
        self.after_select: Callable[[], None] | None = None

    def generate(
        self,
        account_id: str | None,
        actor_id: str | None,
        start: str | None,
        end: str | None,
        requested_by: str,
    ) -> dict[str, Any]:
        if (account_id is None) == (actor_id is None):
            raise invalid("Provide exactly one of accountId or actorId")
        if start is None or end is None:
            raise invalid("from and to are required")
        selection = parse_selection(
            {
                "actorId": actor_id,
                "resourceType": account_access.RESOURCE_TYPE if account_id else None,
                "resourceId": account_id,
                "eventType": account_access.EVENT_TYPE,
                "from": start,
                "to": end,
            },
            require_actor_or_resource=True,
        )
        limits = self._configuration
        records: list[dict[str, Any]] = []
        total_bytes = 0
        with self._store.write_transaction() as connection:
            verification = self._verifier.verify_connection(connection)
            verified_seq = int(verification["headSeq"])
            if self.after_verify:
                self.after_verify()
            for record in iter_records(connection, selection, verified_seq):
                if len(records) >= self._cap:
                    raise self._limit(self._cap, "records")
                total_bytes += (
                    len(canonicalize(record, max_depth=MAX_DOCUMENT_DEPTH)) + 1
                )
                if total_bytes > limits.export_max_bytes:
                    raise self._limit(limits.export_max_bytes, "bytes")
                records.append(record)
            if self.after_select:
                self.after_select()
            records_digest = hashlib.sha256(
                canonicalize(cast(Any, records), max_depth=MAX_DOCUMENT_DEPTH)
            ).hexdigest()
            report_id = str(uuid.uuid4())
            event = self._appender.append_system_event(
                connection,
                "COMPLIANCE_REPORT_GENERATED",
                requested_by,
                "COMPLIANCE_REPORT",
                report_id,
                {
                    "reportId": report_id,
                    "purpose": "COMPLIANCE_REPORT",
                    "subjectType": "ACCOUNT" if account_id else "ACTOR",
                    "selectionDigest": selection.digest(),
                    "from": selection.values["from"],
                    "to": selection.values["to"],
                    "recordCount": len(records),
                    "recordsDigest": records_digest,
                    "verifiedDataHeadSeq": verified_seq,
                    "verifiedDataHeadHash": verification["headHash"],
                    "integrityIntact": bool(verification["intact"]),
                    "requestedBy": requested_by,
                },
            )
            checkpoint = self._appender.store_checkpoint(
                connection, event["seq"], event["chainHash"], event["timestamp"]
            )
            evidence = self._bundles.signed_bundle(
                "COMPLIANCE_REPORT",
                report_id,
                selection,
                verified_seq,
                records,
                records_digest,
                event["timestamp"],
                checkpoint,
                requested_by,
            )
            if (
                len(canonicalize(cast(Any, evidence), max_depth=MAX_DOCUMENT_DEPTH))
                > limits.export_max_bytes
            ):
                raise self._limit(limits.export_max_bytes, "bytes")
        return self._report(
            report_id,
            requested_by,
            selection,
            account_id,
            actor_id,
            verification,
            verified_seq,
            records,
            event,
            checkpoint,
            evidence,
        )

    def _limit(self, limit: int, unit: str) -> ApiError:
        return ApiError(
            422,
            "REPORT_LIMIT_EXCEEDED",
            f"The report exceeds the synchronous limit of {limit} {unit}; "
            "narrow the period or subject",
            [{"limit": unit, "value": limit}],
        )

    def _report(
        self,
        report_id: str,
        requested_by: str,
        selection: Selection,
        account_id: str | None,
        actor_id: str | None,
        verification: dict[str, Any],
        verified_seq: int,
        records: list[dict[str, Any]],
        event: dict[str, Any],
        checkpoint: dict[str, Any],
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        groups: Counter[tuple[str, ...]] = Counter()
        by_outcome: Counter[str] = Counter()
        by_purpose: Counter[str] = Counter()
        by_category: Counter[str] = Counter()
        by_type: Counter[str] = Counter()
        by_actor: Counter[str] = Counter()
        exceptions: list[dict[str, Any]] = []
        unknown = 0
        for record in records:
            category, purpose, outcome, access = (
                _dimension(record, name) for name in _DIMENSIONS
            )
            groups[(record["actorId"], category, purpose, outcome, access)] += 1
            by_outcome[outcome] += 1
            by_purpose[purpose] += 1
            by_category[category] += 1
            by_type[access] += 1
            by_actor[record["actorId"]] += 1
            reasons = []
            if outcome == "DENIED":
                reasons.append("DENIED")
            if purpose == "OTHER":
                reasons.append("PURPOSE_OTHER")
            if any(
                value.startswith("UNKNOWN_")
                for value in (category, purpose, outcome, access)
            ):
                reasons.append("UNKNOWN_GROUPING_FIELD")
                unknown += 1
            if reasons:
                exceptions.append(
                    {
                        "seq": record["seq"],
                        "eventId": record["eventId"],
                        "timestamp": record["timestamp"],
                        "actorId": record["actorId"],
                        "accountId": record["resourceId"],
                        "dataCategory": category,
                        "accessType": access,
                        "accessPurpose": purpose,
                        "outcome": outcome,
                        "reasons": reasons,
                    }
                )
        violations = [
            {
                "type": item.get("type"),
                "seq": item.get("seq"),
                "pointer": item.get("pointer"),
                "message": item.get("message"),
            }
            for item in verification["violations"]
        ]
        first = violations[0] if violations else None
        intact = bool(verification["intact"])
        return {
            "reportId": report_id,
            "requestedBy": requested_by,
            "ledgerId": self._configuration.ledger_id,
            "scope": {
                "subjectType": "ACCOUNT" if account_id else "ACTOR",
                "accountId": account_id,
                "actorId": actor_id,
                "eventType": account_access.EVENT_TYPE,
                "from": selection.values["from"],
                "to": selection.values["to"],
                "periodBasis": _PERIOD_BASIS,
            },
            "verifiedDataHead": {
                "seq": verified_seq,
                "chainHash": verification["headHash"],
                "verifiedAt": verification["verifiedAt"],
            },
            "postReportHead": {
                "seq": checkpoint["seq"],
                "chainHash": checkpoint["chainHash"],
                "createdAt": checkpoint["createdAt"],
                "checkpointKeyId": checkpoint["keyId"],
                "checkpointSignature": checkpoint["signature"],
                "reportEventId": event["eventId"],
            },
            "integrity": {
                "intact": intact,
                "checkedRecords": verification["checkedRecords"],
                "archivedRecords": verification["archivedRecords"],
                "redactedFields": verification["redactedFields"],
                "checkpointsVerified": verification["checkpointsVerified"],
                "totalViolationCount": verification["totalViolationCount"],
                "violationsTruncated": verification["violationsTruncated"],
                "firstViolation": first,
                "violations": violations,
            },
            "trustworthy": intact,
            "trustLabel": _TRUSTED if intact else _UNTRUSTED,
            "counts": {
                "matchedEvents": len(records),
                "unknownRedactedEvents": unknown,
                "exceptionRows": len(exceptions),
                "byOutcome": _sorted(by_outcome),
                "byAccessPurpose": _sorted(by_purpose),
                "byDataCategory": _sorted(by_category),
                "byAccessType": _sorted(by_type),
                "byActor": _sorted(by_actor),
            },
            "groups": [
                {
                    "actorId": key[0],
                    "dataCategory": key[1],
                    "accessPurpose": key[2],
                    "outcome": key[3],
                    "accessType": key[4],
                    "count": groups[key],
                }
                for key in sorted(groups, key=lambda k: "|".join(k))
            ],
            "exceptions": exceptions,
            "exclusions": list(_EXCLUSIONS),
            "recordCap": self._cap,
            "evidence": evidence,
        }
