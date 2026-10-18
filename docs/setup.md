# Setup (Windows and Unix)

Two independent services run against separate databases, keys and ledgers: Java
(port 8080) and Python (port 8000). Prerequisites: JDK 21, Maven 3.9+, Python
3.11+. Docker/Compose is optional (see [Containers](#containers)).

## Development (sample API keys, dev signing key auto-created)

Windows PowerShell:

```powershell
mvn -B -f java\pom.xml verify
java -jar java\target\audit-log-service-0.1.0-SNAPSHOT.jar --server.port=8080

py -3.11 -m venv python\.venv
python\.venv\Scripts\python.exe -m pip install -e "python[dev]"
Set-Location python
.\.venv\Scripts\python.exe -m uvicorn audit_log_service.app:create_app --factory --port 8000
```

Unix shell:

```sh
mvn -B -f java/pom.xml verify
java -jar java/target/audit-log-service-0.1.0-SNAPSHOT.jar --server.port=8080

python3.11 -m venv python/.venv
python/.venv/bin/python -m pip install -e "python[dev]"
cd python && .venv/bin/python -m uvicorn audit_log_service.app:create_app --factory --port 8000
```

Dev sample keys (public, never for shared use): `dev-writer-only`,
`dev-reader-only`, `dev-auditor-only`, `dev-admin-only`. In dev the signing key
is created exclusively under `audit-data/` on first start and never overwritten.
On Windows, key creation applies an ACL via `icacls`; if the sandbox/profile
blocks that, set `AUDIT_SIGNING_*` paths to a directory you own.

## Production (fails closed)

`AUDIT_ENV=prod` requires all of: `AUDIT_API_KEYS_FILE` (hashes only), an
existing valid signing key pair, and `AUDIT_RETENTION_DAYS` >= 1. Missing or
invalid material makes the process exit non-zero; keys are never created in
prod and dev sample keys are rejected. This is proven for both services by real
process tests (`python/tests/test_e2e_prod_failclosed.py`).

Provision material once per service (private key is written with `O_EXCL`,
mode 0600; API keys are printed once and only their SHA-256 hashes are stored):

```sh
python scripts/provision_keys.py --output-dir deploy/keys/java
python scripts/provision_keys.py --output-dir deploy/keys/python
```

`deploy/` is git-ignored. On Windows restrict the directory ACL to the service
account (`icacls deploy\keys /inheritance:r /grant:r "$env:USERNAME:(OI)(CI)F"`).
Store printed API keys in a secret manager; this prototype has no KMS/HSM.

Run production-mode locally (example, Java):

```sh
AUDIT_ENV=prod AUDIT_API_KEYS_FILE=deploy/keys/java/api-keys.json \
AUDIT_SIGNING_PRIVATE_KEY=deploy/keys/java/signing-private.pem \
AUDIT_SIGNING_PUBLIC_KEY=deploy/keys/java/signing-public.b64 \
java -jar java/target/audit-log-service-0.1.0-SNAPSHOT.jar
```

## Containers

`java/Dockerfile` and `python/Dockerfile` build separate non-root (UID 10001)
images from the repository root; `compose.yaml` runs both with separate named
volumes for data, archives and exports, a read-only keys mount, a read-only
root filesystem, dropped capabilities and loopback-only ports.

```sh
mvn -B -f java/pom.xml verify          # produces the jar the Java image copies
docker compose build
docker compose up
```

Base images are pinned by tag and registry digest (read from Docker Hub on
2026-10-18). **The images and compose file were not built or run in the
authoring environment (Docker unavailable); the CI `images` job builds them,
checks the UID and checks prod fails closed without keys.** Treat them as
unverified until that job is green. Volume ownership: named volumes inherit
UID 10001 from the image; for bind mounts `chown 10001` the directories.

## Operations: exports, redaction cleanup, archives

Examples use the dev admin key against a local service (use `curl.exe` in Windows PowerShell; replace the port for the other service).

```sh
# Small export: one signed bundle, or 422 EXPORT_LIMIT_EXCEEDED when over the limits
curl -s -H "X-API-Key: dev-auditor-only" "http://127.0.0.1:8080/audit/export?actorId=alice" -o bundle.json
curl -s http://127.0.0.1:8080/audit/public-key        # take the key from a source you trust, not from the bundle
python -m audit_log_service.verifier --bundle bundle.json --pinned-key <base64>

# Large export: create a set, poll until READY, download the manifest and chunks, verify the directory offline
curl -s -X POST -H "X-API-Key: dev-auditor-only" "http://127.0.0.1:8080/audit/export-sets?actorId=alice"
curl -s -H "X-API-Key: dev-auditor-only" http://127.0.0.1:8080/audit/export-sets/<id>
python -m audit_log_service.verifier --manifest set-dir/manifest.json --pinned-key <base64>

# Redaction cleanup: PENDING means the delete committed but the WAL truncate was busy
curl -s -H "X-API-Key: dev-admin-only" http://127.0.0.1:8080/audit/admin/redaction-cleanups
curl -s -X POST -H "X-API-Key: dev-admin-only" http://127.0.0.1:8080/audit/admin/redaction-cleanups/retry

# Archive: dry run first; audit the archive files afterwards
curl -s -X POST -H "X-API-Key: dev-admin-only" -H "Content-Type: application/json" -d '{"dryRun":true}' http://127.0.0.1:8080/audit/admin/archive
curl -s -H "X-API-Key: dev-auditor-only" http://127.0.0.1:8080/audit/archive-audit
```

The export-set manifest verifier usage and exit codes are in [export-sets.md](./export-sets.md) and [python-verifier.md](./python-verifier.md).
Cleanup of generated files: remove the `audit-data/` directory (database, keys, archives, exports) only for a throwaway dev ledger;
never delete archive files referenced by a committed archive job.

## Trust and privacy limits

Read [threat-model.md](./threat-model.md) and [ENGINEERING_SUMMARY.md](../ENGINEERING_SUMMARY.md) before relying on this
service. In short: tamper-evident only with surviving trusted checkpoints; no external witness, KMS or WORM; no physical-erasure
guarantee after redaction or archiving; archived records leave normal query, export and reports; Scenario C rests on unconfirmed assumptions.

## Minimal offline verifier

The base Python install is only the verifier and needs only `cryptography`:

```sh
pip install ./python
python -m audit_log_service.verifier --bundle bundle.json --pinned-key <base64>
```

The service needs `pip install "./python[service]"` (Starlette, Pydantic,
Uvicorn, rfc8785). Exit codes: 0 verified, 1 evidence invalid, 2 input/usage.
