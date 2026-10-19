# Setup (Windows and Unix)

A single Java service (port 8080) with its own database, keys and ledger. Prerequisites: JDK 21, Maven 3.9+. Python 3 is needed only for the helper scripts (`scripts/provision_keys.py`, `scripts/check_hygiene.py`). Docker/Compose is optional (see [Containers](#containers)).

## Development (sample API keys, dev signing key auto-created)

Windows PowerShell:

```powershell
mvn -B -f java\pom.xml verify
java -jar java\target\audit-log-service-0.1.0-SNAPSHOT.jar --server.port=8080
```

Unix shell:

```sh
mvn -B -f java/pom.xml verify
java -jar java/target/audit-log-service-0.1.0-SNAPSHOT.jar --server.port=8080
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
prod and dev sample keys are rejected. This is exercised by the Java tests and the CI `images` job.

Provision material once (private key is written with `O_EXCL`,
mode 0600; API keys are printed once and only their SHA-256 hashes are stored):

```sh
python scripts/provision_keys.py --output-dir deploy/keys/java
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

`java/Dockerfile` builds a non-root (UID 10001) image from the repository root; `compose.yaml` runs it with named`nvolumes for data, archives and exports, a read-only keys mount, a read-only
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

Examples use the dev admin key against a local service (use `curl.exe` in Windows PowerShell).

```sh
# Small export: one signed bundle, or 422 EXPORT_LIMIT_EXCEEDED when over the limits
curl -s -H "X-API-Key: dev-auditor-only" "http://127.0.0.1:8080/audit/export?actorId=alice" -o bundle.json
curl -s http://127.0.0.1:8080/audit/public-key        # take the key from a source you trust, not from the bundle
java -cp java/target/classes com.auditlog.verifier.BundleVerifierCli --bundle bundle.json --pinned-key <base64>

# Large export: create a set, poll until READY, download the manifest and chunks, verify the directory offline
curl -s -X POST -H "X-API-Key: dev-auditor-only" "http://127.0.0.1:8080/audit/export-sets?actorId=alice"
curl -s -H "X-API-Key: dev-auditor-only" http://127.0.0.1:8080/audit/export-sets/<id>
java -cp java/target/classes com.auditlog.verifier.BundleVerifierCli --manifest set-dir/manifest.json --pinned-key <base64>

# Redaction cleanup: PENDING means the delete committed but the WAL truncate was busy
curl -s -H "X-API-Key: dev-admin-only" http://127.0.0.1:8080/audit/admin/redaction-cleanups
curl -s -X POST -H "X-API-Key: dev-admin-only" http://127.0.0.1:8080/audit/admin/redaction-cleanups/retry

# Archive: dry run first; audit the archive files afterwards
curl -s -X POST -H "X-API-Key: dev-admin-only" -H "Content-Type: application/json" -d '{"dryRun":true}' http://127.0.0.1:8080/audit/admin/archive
curl -s -H "X-API-Key: dev-auditor-only" http://127.0.0.1:8080/audit/archive-audit
```

The export-set manifest verifier usage and exit codes are in [export-sets.md](./export-sets.md).
Cleanup of generated files: remove the `audit-data/` directory (database, keys, archives, exports) only for a throwaway dev ledger;
never delete archive files referenced by a committed archive job.

## Trust and privacy limits

Read [threat-model.md](./threat-model.md) and [ENGINEERING_SUMMARY.md](../ENGINEERING_SUMMARY.md) before relying on this
service. In short: tamper-evident only with surviving trusted checkpoints; no external witness, KMS or WORM; no physical-erasure
guarantee after redaction or archiving; archived records leave normal query, export and reports; Scenario C rests on unconfirmed assumptions.

## Offline verifier

The verifier (com.auditlog.verifier.BundleVerifierCli) needs only the compiled classes plus the Java dependencies used for crypto. Exit codes: 0 verified, 1 evidence invalid, 2 input/usage.
