#!/usr/bin/env bash
# Demo of scenarios A/B/C, offline pinned verification and tamper detection (Unix).
#
# UNTESTED: written alongside scripts/demo.ps1 (which was run against both services on
# Windows) but never executed, because no bash was available in the authoring environment.
# Review and run it on Linux/macOS before relying on it.
#
# Usage: scripts/demo.sh [python|java] [port] [workdir]
# Needs curl and python3 (jq is NOT required). Uses only synthetic data and dev API keys.
set -euo pipefail

SERVICE="${1:-python}"
PORT="${2:-18080}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${3:-$(mktemp -d)}"
HOME_DIR="$WORK/audit-demo-$$"
PY="$ROOT/python/.venv/bin/python"
[ -x "$PY" ] || PY="python3"
JAR="$ROOT/java/target/audit-log-service-0.1.0-SNAPSHOT.jar"
BASE="http://127.0.0.1:$PORT"
mkdir -p "$HOME_DIR/tmp"

export AUDIT_ENV=dev AUDIT_LEDGER_ID=synthetic-demo-ledger
export AUDIT_DB_PATH="$HOME_DIR/audit.db"
export AUDIT_SIGNING_PRIVATE_KEY="$HOME_DIR/keys/private.pem"
export AUDIT_SIGNING_PUBLIC_KEY="$HOME_DIR/keys/public.b64"
export AUDIT_ARCHIVE_DIR="$HOME_DIR/archives" AUDIT_EXPORT_DIR="$HOME_DIR/exports"

PID=""
start_service() {
  if [ "$SERVICE" = "java" ]; then
    [ -f "$JAR" ] || { echo "Build the jar first: mvn -f java/pom.xml package" >&2; exit 2; }
    java "-Djava.io.tmpdir=$HOME_DIR/tmp" -jar "$JAR" "--server.port=$PORT" \
      >"$HOME_DIR/service.out" 2>"$HOME_DIR/service.err" &
  else
    (cd "$ROOT/python" && exec "$PY" -m uvicorn audit_log_service.app:create_app --factory \
      --host 127.0.0.1 --port "$PORT") >"$HOME_DIR/service.out" 2>"$HOME_DIR/service.err" &
  fi
  PID=$!
  for _ in $(seq 1 240); do
    kill -0 "$PID" 2>/dev/null || { echo "service exited; see $HOME_DIR/service.err" >&2; exit 1; }
    curl -fs "$BASE/health" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "service did not become healthy" >&2; exit 1
}
stop_service() { [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true; PID=""; }
trap stop_service EXIT

api() { # method path key [json]
  if [ $# -ge 4 ]; then
    curl -fs -X "$1" -H "X-API-Key: $3" -H 'Content-Type: application/json' -d "$4" "$BASE$2"
  else
    curl -fs -X "$1" -H "X-API-Key: $3" "$BASE$2"
  fi
}
jget() { "$PY" -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

echo "== Starting $SERVICE service (home: $HOME_DIR)"
start_service
PINNED="$(curl -fs "$BASE/audit/public-key" | jget 'd["publicKey"]')"
echo "Pinned public key: $PINNED"

echo; echo "== Scenario A: append / query / verify"
for i in 1 2 3 4 5; do
  api POST /audit/events dev-writer-only \
    "{\"eventType\":\"DOCUMENT_VIEWED\",\"actorId\":\"alice\",\"resourceType\":\"DOCUMENT\",\"resourceId\":\"doc-$i\",\"payload\":{\"note\":\"secret-$i\"}}" >/dev/null
done
api GET '/audit/events?limit=2' dev-reader-only | jget '[i["seq"] for i in d["items"]]'
api GET /audit/verify dev-auditor-only | jget '"intact=%s headSeq=%s" % (d["intact"], d["headSeq"])'

echo; echo "== Scenario B: redact, export, offline verify"
FIRST="$(api GET '/audit/events?limit=1&order=asc' dev-reader-only | jget 'd["items"][0]["eventId"]')"
api POST /audit/admin/redactions dev-admin-only \
  "{\"eventId\":\"$FIRST\",\"paths\":[\"/note\"],\"reason\":\"demo\",\"ticketId\":\"DEMO-1\"}" \
  | jget '"cleanupStatus=" + d["cleanupStatus"]'
api GET '/audit/export?actorId=alice' dev-auditor-only >"$HOME_DIR/bundle.json"
set +e
(cd "$ROOT/python" && "$PY" -m audit_log_service.verifier --bundle "$HOME_DIR/bundle.json" --pinned-key "$PINNED")
echo "offline verify with pinned key -> exit $? (0 = verified)"
set -e

echo; echo "== Scenario C: account access report"
for outcome in '"outcome":"GRANTED"' '"outcome":"DENIED","denialReason":"no entitlement"'; do
  api POST /audit/events dev-writer-only \
    "{\"eventType\":\"ACCOUNT_DATA_ACCESS\",\"actorId\":\"bob\",\"resourceType\":\"CLIENT_ACCOUNT\",\"resourceId\":\"acct-1\",\"payload\":{\"dataCategory\":\"BALANCES\",\"accessType\":\"VIEW\",\"accessPurpose\":\"SERVICING\",\"channel\":\"API\",$outcome}}" >/dev/null
done
YEAR="$(date +%Y)"
api GET "/compliance/account-access-report?accountId=acct-1&from=$((YEAR-1))-01-01T00:00:00Z&to=$((YEAR+1))-01-01T00:00:00Z" dev-auditor-only \
  | jget '"trustworthy=%s" % d["trustworthy"]'

echo; echo "== Tamper: stop service, edit the SQLite file, restart"
stop_service
"$PY" "$ROOT/scripts/synthetic_tamper.py" "$HOME_DIR/audit.db" edit-field --seq 3 --i-understand-this-is-synthetic-data
start_service
RESULT="$(api GET /audit/verify dev-auditor-only)"
echo "$RESULT" | jget '"intact=%s violations=%s" % (d["intact"], [(v["type"], v["seq"]) for v in d["violations"]])'
echo "$RESULT" | jget 'd["intact"]' | grep -q False || { echo "tampering was NOT detected" >&2; exit 1; }
echo; echo "Demo complete. Synthetic data left in $HOME_DIR"
