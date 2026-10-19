# Audit Log Service

A tamper-evident audit-log service implemented twice against one contract: a Java 21 /
Spring Boot 3 service (`java/`) and a Python / Starlette service (`python/`) with an
independent offline verifier. It covers Scenario A (append, query, verify), Scenario B
(redaction, retention archive, verifiable bulk export) and Scenario C (an internal
account-access report, built on **unconfirmed assumptions**; no stakeholder has answered).

This is a prototype for engineer review. It is tamper-**evident**, not tamper-proof: it has no
external witness, KMS or WORM storage, and redaction gives no physical-erasure guarantee. Nothing
has been signed off. The root [`ATTESTATION.md`](./ATTESTATION.md) holds the engineer's personal
attestation text required by the assignment; the engineering review record in
[`docs/attestation-template.md`](./docs/attestation-template.md)
is for the engineer to complete.

Start with [`ENGINEERING_SUMMARY.md`](./ENGINEERING_SUMMARY.md), then:

| Topic | Document |
|---|---|
| Architecture and trust boundaries | [`docs/architecture.md`](./docs/architecture.md) |
| API, roles, errors, schemas | [`docs/api.md`](./docs/api.md) |
| Windows/Unix setup, production, containers | [`docs/setup.md`](./docs/setup.md) |
| Requirements and traceability | [`docs/requirements-mapping.md`](./docs/requirements-mapping.md) |
| Scenario C questions and assumptions | [`docs/scenario-c.md`](./docs/scenario-c.md) |
| Live-defense notes and extension rehearsal | [`docs/live-defense.md`](./docs/live-defense.md) |
| Threat model, verification, redaction, archives, exports | [`docs/threat-model.md`](./docs/threat-model.md), [`docs/verification.md`](./docs/verification.md), [`docs/redaction.md`](./docs/redaction.md), [`docs/retention-archive.md`](./docs/retention-archive.md), [`docs/export-bundles.md`](./docs/export-bundles.md), [`docs/export-sets.md`](./docs/export-sets.md) |
| AI use | [`AI_USAGE_LOG.md`](./AI_USAGE_LOG.md) |

The build brief (the engineer's detailed requirements, which add a stack and protocol beyond the assignment PDF) is in [`docs/BUILD_REQUIREMENTS.txt`](./docs/BUILD_REQUIREMENTS.txt). Dependency
pins and their sources are in [`docs/dependency-versions.md`](./docs/dependency-versions.md).

## Repository layout

- `java/` — Java 21 / Spring Boot 3 Maven service and tests.
- `python/` — Python >=3.11 Starlette service in a `src/` layout and tests.
- `python/src/audit_log_service/verifier/` — the independent offline verifier (no service imports).
- `docs/` — requirements, ADRs, schemas, test vectors, security and operations documentation.
- `scripts/` — `provision_keys.py`, `synthetic_tamper.py` (synthetic data only), `check_hygiene.py`,
  `benchmark.py`, `demo.ps1` (run on Windows) and `demo.sh` (never executed).
- `.github/workflows/` — CI (never run by a runner; see [`docs/quality-gates.md`](./docs/quality-gates.md)).

The assignment PDF is kept locally in `project-doc/` and is not tracked.

Exports: `GET /audit/export` returns one signed small v1 bundle (limits `AUDIT_EXPORT_MAX_RECORDS`,
default 1000, and `AUDIT_EXPORT_MAX_BYTES`, default 8 MiB; larger selections get 422, never a
truncated result). Larger selections use `POST /audit/export-sets`, which produces chunks and a
signed manifest from one snapshot. Both are verified offline with a pinned key.

Checkpoint key/configuration contracts and limits are documented in
[`docs/configuration-and-signing.md`](./docs/configuration-and-signing.md).
Do not use the clearly marked test-only Ed25519 fixture outside tests.
SQLite schema and transaction decisions are recorded in
[`docs/adr/0003-storage-and-transaction-model.md`](./docs/adr/0003-storage-and-transaction-model.md).

## Quick start: run locally in dev mode

Dev mode is the default (`AUDIT_ENV=dev`). On first start each service creates its own SQLite database and Ed25519
signing key under `audit-data/` (relative to the directory you start it from; git-ignored). No configuration or key files
are needed. Production mode is stricter and is described in [`docs/setup.md`](./docs/setup.md).

**Prerequisites:** JDK 21, Maven 3.9+, Python 3.11 or newer. The Java service and the Python service are independent;
run either or both.

### 1. Java service (port 8080)

From the repository root (PowerShell or Unix shell):

```sh
mvn -f java/pom.xml spring-boot:run
```

On Windows PowerShell use `mvn -f java\pom.xml spring-boot:run`. To use another port, add
`-Dspring-boot.run.arguments=--server.port=8081`. Alternatively, build once and run the jar:

```sh
mvn -f java/pom.xml -DskipTests package
java -jar java/target/audit-log-service-0.1.0-SNAPSHOT.jar
```

Check: `http://localhost:8080/health` returns `{"status":"UP"}`. API docs: `http://localhost:8080/docs`; OpenAPI:
`/openapi.json`.

### 2. Python service (port 8000)

Windows PowerShell:

```powershell
Set-Location python
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m audit_log_service
```

Unix shell:

```sh
cd python
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m audit_log_service
```

Check: `http://localhost:8000/health`. Its database is `python/audit-data/audit.db`, separate from the Java one.

### 3. Try it

Dev sample API keys (public, development only): `dev-writer-only`, `dev-reader-only`, `dev-auditor-only`, `dev-admin-only`
(the admin key has every role). Send one as the `X-API-Key` header.

```sh
curl -X POST http://localhost:8080/audit/events -H "X-API-Key: dev-writer-only" -H "Content-Type: application/json" \
  -d '{"eventType":"USER_LOGIN","actorId":"alice","resourceType":"session","resourceId":"s-1","payload":{"ip":"10.0.0.1"}}'
curl -H "X-API-Key: dev-reader-only" "http://localhost:8080/audit/events?actorId=alice"
curl -H "X-API-Key: dev-auditor-only" http://localhost:8080/audit/verify
```

Use port 8000 for the Python service. On Windows PowerShell, call `curl.exe` (not the `curl` alias) or use `Invoke-RestMethod`.
`scripts/demo.ps1` runs a scripted Scenario A/B/C walkthrough with tampering against both services.

### 4. Reset to a clean state

Stop the service, then delete the `audit-data/` folder it created (or just `audit.db`, `audit.db-wal`, `audit.db-shm`).
Do not delete rows by hand: triggers block row deletion by design.

### Troubleshooting

- **Port in use:** change the Java port as above; Python's port is fixed at 8000 in `python/src/audit_log_service/__main__.py`
  (or run `python -m uvicorn audit_log_service.app:create_app --factory --port 8001`).
- **`401`:** missing or wrong `X-API-Key`. **`403`:** the key's role cannot use that endpoint (see [`docs/api.md`](./docs/api.md)).
- **Different working directory = different database:** the DB path is relative to where you start the service.

## Local checks

### Windows PowerShell

```powershell
mvn -f java\pom.xml verify
Set-Location python
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src
python -m pytest
```

To launch the services, see the Quick start above. Health endpoints: Java `http://localhost:8080/health`
(OpenAPI `/openapi.json`, docs UI `/docs`), Python `http://localhost:8000/health`.

### Unix shell

```sh
mvn -f java/pom.xml verify
cd python
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy src
python -m pytest
```

To launch the services, see the Quick start above.

The current machine's installed Python may differ from 3.11; the CI workflow
uses Python 3.11. The Spring Boot 3.5 line is my stack choice (not an assignment
requirement), but its open-source support ended on 2026-06-30. See the dependency record and
resolve support requirements before production use.

## Quality gates, setup and packaging

- Setup for Windows/Unix, production fail-closed rules, key provisioning
  (`scripts/provision_keys.py`), containers and the minimal verifier install:
  [`docs/setup.md`](./docs/setup.md).
- CI gates, coverage thresholds, dated suppressions and blocked checks:
  [`docs/quality-gates.md`](./docs/quality-gates.md). `scripts/check_hygiene.py`
  scans tracked files for secrets and artifacts.
- The Java build produces an executable Spring Boot jar
  (`java/target/audit-log-service-0.1.0-SNAPSHOT.jar`); `java/Dockerfile`,
  `python/Dockerfile` and `compose.yaml` define separate non-root images
  (unbuilt in the authoring environment).
- Measured throughput/latency, single-writer and full-scan costs, and simulated
  disk-full/slow-I/O/busy/backpressure behaviour: [`docs/performance.md`](./docs/performance.md)
  (`scripts/benchmark.py`; results in `docs/benchmarks/`). Single-machine
  measurements; no targets are claimed.
