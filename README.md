# Audit Log Service

A tamper-evident audit-log service implemented twice against one contract: a Java 21 /
Spring Boot 3 service (`java/`) and a Python / Starlette service (`python/`) with an
independent offline verifier. It covers Scenario A (append, query, verify), Scenario B
(redaction, retention archive, verifiable bulk export) and Scenario C (an internal
account-access report, built on **unconfirmed assumptions**; no stakeholder has answered).

This is a prototype for engineer review. It is tamper-**evident**, not tamper-proof: it has no
external witness, KMS or WORM storage, and redaction gives no physical-erasure guarantee. Nothing
has been signed off; the attestation in [`docs/attestation-template.md`](./docs/attestation-template.md)
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

The requirements are in [`docs/BUILD_REQUIREMENTS.txt`](./docs/BUILD_REQUIREMENTS.txt). Dependency
pins and their sources are in [`docs/dependency-versions.md`](./docs/dependency-versions.md).

## Repository layout

- `java/` — Java 21 / Spring Boot 3 Maven service and tests.
- `python/` — Python >=3.11 Starlette service in a `src/` layout and tests.
- `python/src/audit_log_service/verifier/` — the independent offline verifier (no service imports).
- `docs/` — requirements, ADRs, schemas, test vectors, security and operations documentation.
- `scripts/` — `provision_keys.py`, `synthetic_tamper.py` (synthetic data only), `check_hygiene.py`,
  `benchmark.py`, `demo.ps1` (run on Windows) and `demo.sh` (never executed).
- `.github/workflows/` — CI (never run by a runner; see [`docs/quality-gates.md`](./docs/quality-gates.md)).

The root-level `pom.xml` and `src/` are a pre-existing starter. They are kept
unchanged and are not used by the new `java/` or `python/` builds.

Exports: `GET /audit/export` returns one signed small v1 bundle (limits `AUDIT_EXPORT_MAX_RECORDS`,
default 1000, and `AUDIT_EXPORT_MAX_BYTES`, default 8 MiB; larger selections get 422, never a
truncated result). Larger selections use `POST /audit/export-sets`, which produces chunks and a
signed manifest from one snapshot. Both are verified offline with a pinned key.

Checkpoint key/configuration contracts and limits are documented in
[`docs/configuration-and-signing.md`](./docs/configuration-and-signing.md).
Do not use the clearly marked test-only Ed25519 fixture outside tests.
SQLite schema and transaction decisions are recorded in
[`docs/adr/0003-storage-and-transaction-model.md`](./docs/adr/0003-storage-and-transaction-model.md).

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

To launch the Java service, run `mvn -f java\pom.xml spring-boot:run` from the
repository root; its health endpoint is `http://localhost:8080/health`, with
OpenAPI at `/openapi.json` and the docs UI at `/docs`. To launch Python, in a
separate terminal run `Set-Location python` and `python -m audit_log_service`;
its health endpoint is `http://localhost:8000/health`.

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

To launch Java, run `mvn -f java/pom.xml spring-boot:run` from the repository
root; its health endpoint is `http://localhost:8080/health`, with OpenAPI at
`/openapi.json` and the docs UI at `/docs`. To launch Python in a separate
terminal, run `cd python` and `python -m audit_log_service`; its health
endpoint is `http://localhost:8000/health`.

The current machine's installed Python may differ from 3.11; the CI workflow
uses Python 3.11. The Spring Boot 3.5 line is retained to match the assignment,
but its open-source support ended on 2026-06-30. See the dependency record and
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
