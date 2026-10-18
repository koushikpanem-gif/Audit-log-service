# Audit Log Service

This repository is being implemented in numbered actions. The Java and Python
scaffolds include health endpoints, strict JCS/v1 hashing, salted payload
commitments, Action 05's Ed25519 checkpoint signer/configuration helpers, and
Action 06's versioned SQLite schema and JDBC transaction repository. Ledger
append/query, persistent checkpointing, redaction, export, verification, and
compliance-report behavior remain pending later actions.

The requirements and acceptance mapping are in
[`docs/BUILD_REQUIREMENTS.txt`](./docs/BUILD_REQUIREMENTS.txt) and
[`docs/requirements-mapping.md`](./docs/requirements-mapping.md).
Scenario C remains provisional; see
[`docs/scenario-c.md`](./docs/scenario-c.md). Dependency pins and their sources
are recorded in [`docs/dependency-versions.md`](./docs/dependency-versions.md).

## Repository layout

- `java/` — Java 21 / Spring Boot 3 Maven skeleton.
- `python/` — Python >=3.11 Starlette service in a `src/` layout.
- `python/src/audit_log_service/verifier/` — reserved for the independent
  offline verifier; verification logic is not implemented yet.
- `docs/` — requirements, ADRs, security, and operations documentation.
- `scripts/` — operational scripts; currently `synthetic_tamper.py`, a
  synthetic-data-only tamper tool (see `docs/verification.md`).
- `.github/workflows/` — CI for the two skeletons.

The root-level `pom.xml` and `src/` are a pre-existing starter. They are kept
unchanged and are not used by the new `java/` or `python/` builds.

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
