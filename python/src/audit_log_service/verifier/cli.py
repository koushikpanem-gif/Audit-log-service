"""Command line for the offline verifier.

Exit codes: 0 verified or explicitly untrusted-valid, 1 evidence invalid, 2 usage.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO

from audit_log_service.verifier.bundle import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_RECORDS,
    INVALID,
    UNTRUSTED,
    VERIFIED,
    InputError,
    Options,
    Result,
    verify_bundle,
)
from audit_log_service.verifier.export_set import (
    DEFAULT_MAX_RECORDS as SET_MAX_RECORDS,
)
from audit_log_service.verifier.export_set import verify_export_set

EXIT_VALID, EXIT_INVALID, EXIT_USAGE = 0, 1, 2


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise InputError(message)


def _print(result: Result, out: TextIO) -> None:
    out.write(result.status + "\n")
    if result.status == UNTRUSTED:
        out.write(
            "*** WARNING: ORIGIN NOT TRUSTED - the signer key came from the evidence "
            "itself. This only shows internal consistency, not who produced it. ***\n"
        )
    out.write(f"originTrusted: {str(result.origin_trusted).lower()}\n")
    out.write(f"ledgerId: {result.ledger_id}\nbundleId: {result.bundle_id}\n")
    out.write(f"keyId: {result.key_id}\nrecordCount: {result.record_count}\n")
    out.write(f"undisclosedLeafCount: {result.undisclosed_leaf_count}\n")
    out.write(f"totalDiagnosticCount: {result.total_diagnostic_count}\n")
    for item in result.diagnostics:
        out.write(
            f"diagnostic: {item['code']} seq={item['seq']} "
            f"pointer={item['pointer']} message={item['message']}\n"
        )
    if result.diagnostics_truncated:
        out.write("diagnosticsTruncated: true\n")
    for notice in result.notices:
        out.write(f"notice: {notice}\n")


def run(argv: list[str], out: TextIO, err: TextIO) -> int:
    parser = _Parser(prog="audit-verify", add_help=False)
    parser.add_argument("--bundle")
    parser.add_argument("--manifest")
    parser.add_argument("--pinned-key")
    parser.add_argument("--pinned-key-file")
    parser.add_argument("--allow-self-asserted", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--max-records", type=int)
    try:
        args = parser.parse_args(argv)
        if (args.bundle is None) == (args.manifest is None):
            raise InputError("Exactly one of --bundle and --manifest is required")
        if args.pinned_key and args.pinned_key_file:
            raise InputError("Use only one of --pinned-key and --pinned-key-file")
        pinned = args.pinned_key
        if args.pinned_key_file:
            try:
                pinned = Path(args.pinned_key_file).read_text(encoding="utf-8").strip()
            except (OSError, UnicodeDecodeError) as error:
                raise InputError("Pinned key file could not be read") from error
        max_records = args.max_records or (
            SET_MAX_RECORDS if args.manifest else DEFAULT_MAX_RECORDS
        )
        options = Options(pinned, args.allow_self_asserted, args.max_bytes, max_records)
        if args.manifest:
            result = verify_export_set(Path(args.manifest), options)
        else:
            try:
                with Path(args.bundle).open("rb") as handle:
                    data = handle.read(options.max_bytes + 1)
            except OSError as error:
                raise InputError("Input file could not be read") from error
            result = verify_bundle(data, options)
    except InputError as error:
        err.write(f"ERROR: {error}\n")
        return EXIT_USAGE
    _print(result, out)
    return EXIT_INVALID if result.status == INVALID else EXIT_VALID


def main() -> None:
    sys.exit(run(sys.argv[1:], sys.stdout, sys.stderr))


__all__ = ["EXIT_INVALID", "EXIT_USAGE", "EXIT_VALID", "VERIFIED", "main", "run"]
