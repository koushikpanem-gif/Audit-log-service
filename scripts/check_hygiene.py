"""Fail if tracked files contain secrets or build/runtime artifacts.

Scans `git ls-files` only (untracked and ignored files are not shipped). The one
allowlisted private key is the clearly labelled non-production golden test key.
Exit status: 0 clean, 1 findings, 2 usage/environment error.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Tracked path -> reason it may contain key material.
ALLOWLIST = {
    "docs/test-vectors/ed25519-checkpoint-v1.json": "labelled non-production test key",
    "java/src/test/resources/golden/bundle_vectors/test_key_private.pem": "RFC 8032 non-production test key",
}

FORBIDDEN_NAME = re.compile(
    r"(\.db|\.db-wal|\.db-shm|\.sqlite3?|\.pem|\.key|\.p12|\.pfx|\.jks|\.log|\.pyc)$"
    r"|(^|/)(\.env(\..*)?|api-keys[^/]*\.json)$"
    r"|(^|/)(target|\.venv|__pycache__|node_modules|archives|exports)/"
)
SECRET_PATTERNS = {
    "private key block": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\r\n]{40,}"),
    "GitHub token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|github_pat_[A-Za-z0-9_]{50,}"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic secret assignment": re.compile(
        r"(?i)\b(?:password|secret|api[_-]?key|token)\b\s*[:=]\s*[\"'][A-Za-z0-9+/_\-]{24,}[\"']"
    ),
}
MAX_SCAN_BYTES = 2_000_000


def tracked_files() -> list[str]:
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(ROOT), "ls-files", "-z"],  # noqa: S607
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit("hygiene: git ls-files failed")
    return [name for name in result.stdout.decode("utf-8").split("\0") if name]


def scan() -> list[str]:
    findings: list[str] = []
    for name in tracked_files():
        path = ROOT / name
        if not path.is_file():
            continue
        if FORBIDDEN_NAME.search(name) and name not in ALLOWLIST:
            findings.append(f"{name}: forbidden artifact or secret-bearing file name")
            continue
        if path.stat().st_size > MAX_SCAN_BYTES:
            continue
        text = path.read_bytes().decode("utf-8", errors="ignore")
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text) and name not in ALLOWLIST:
                findings.append(f"{name}: possible {label}")
    return findings


def main() -> int:
    try:
        findings = scan()
    except (OSError, SystemExit) as error:
        print(f"hygiene: {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"HYGIENE VIOLATION {finding}")
    if findings:
        return 1
    print("hygiene: no tracked secrets or artifacts found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
