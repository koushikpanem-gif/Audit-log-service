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

## Minimal offline verifier

The base Python install is only the verifier and needs only `cryptography`:

```sh
pip install ./python
python -m audit_log_service.verifier --bundle bundle.json --pinned-key <base64>
```

The service needs `pip install "./python[service]"` (Starlette, Pydantic,
Uvicorn, rfc8785). Exit codes: 0 verified, 1 evidence invalid, 2 input/usage.
