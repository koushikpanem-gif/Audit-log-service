# AI usage and decision log

This log records only work and checks actually performed in Action 01. It does
not substitute for engineer review or approval.

## Action 01 — requirements and ownership

- **Scope:** Documentation baseline, requirements traceability, provisional
  Scenario C clarification, threat model, ADRs, attestation template, and
  secret-safe ignore rules. No ledger implementation was requested or added.
- **Workspace finding:** The user authorized proceeding in the current
  non-empty workspace. The existing root Spring Boot starter was preserved;
  its layout/version mismatch with the assignment was recorded for engineer
  review.
- **AI decisions:** Preserved the full supplied build specification in
  `docs/BUILD_REQUIREMENTS.txt`; organized acceptance criteria under shared,
  A, B, C, and quality IDs; marked Scenario C answers as unresolved and the
  proposed statement/assumptions as provisional; grouped the specified
  architectural choices into ADRs; documented trust limitations and made the
  attestation explicitly unsigned. Added ignore rules for local credentials,
  keys, SQLite state, and generated archive/export artifacts while retaining
  the existing ignore rules.
- **Human decisions:** None recorded. No stakeholder answers, engineer
  approval, personal identity, or attestation were invented.
- **Validation performed:** `git init` succeeded. A PowerShell comparison of
  the normalized attachment text and `docs/BUILD_REQUIREMENTS.txt` passed
  exactly after correcting two omissions in the initial transcription. A
  required-file check passed for all 16 requested documents. An acceptance-ID
  check passed for all 42 IDs (the first check expression incorrectly rejected
  the spaces in Markdown table cells; the corrected whitespace-tolerant check
  passed). Required secret/database/generated-artifact ignore patterns were
  confirmed. Changed documentation was reviewed directly. Java/Python
  behavioral tests were not run: this action changes no implementation code,
  and the shared protocol checks are deferred until both services exist.
- **Git/commit:** The workspace was not previously a Git repository, so local
  Git was initialized. `git config --get user.name` and
  `git config --get user.email` returned no configured identity. No identity
  was invented and no commit was attempted; the authorized commit is blocked.
  Existing starter files remain untouched and are not part of the action's
  staged documentation changes.

## Exact check outcomes

- `git init` — passed; initialized a local repository.
- PowerShell normalized text comparison between the read-only attachment and
  `docs/BUILD_REQUIREMENTS.txt` — passed; exact content match.
- PowerShell required-file check — passed; 16/16 requested documents exist.
- PowerShell whitespace-tolerant acceptance-ID check — passed; 42/42 IDs are
  present in the mapping.
- PowerShell `.gitignore` rule check — passed; private-key/API-key, SQLite,
  archive, export and artifact patterns are present.
- `git add .gitignore README.md AI_USAGE_LOG.md docs` — passed; staged only the
  17 files belonging to this action. Git emitted a non-fatal Windows line
  ending notice that `.gitignore` LF will be converted to CRLF.
- `git diff --cached --check` — passed; no staged whitespace errors.
- `git status --short` — the 17 action files are staged; the pre-existing
  starter files remain untracked and unstaged.
- `git config --get user.name` — no output (not configured).
- `git config --get user.email` — no output (not configured).
- Java `mvn verify` / Python `pytest`, `ruff`, `mypy` — not run; no Java/Python
  implementation was changed or added in this documentation-only action.
- Commit `docs: define requirements and ownership` — not created; blocked by
  missing configured Git identity. Commit hash: none.

## Action 02 — Java and Python service scaffolds

- **Scope:** Java 21 / Spring Boot 3 Maven skeleton with health endpoint,
  configured OpenAPI UI/document endpoints and framework-independent package
  boundaries; Python >=3.11 Starlette `src/` package with a health endpoint and
  its own test; exact direct dependency pins; basic Java/Python CI; local
  Windows and Unix setup commands. No audit behavior is implemented.
- **Workspace finding:** Git is now on `main` tracking `origin/main`, and
  Action 01 is present in the branch history. Existing root `pom.xml`, `src/`,
  wrapper, build output and project PDF are untracked pre-existing files; they
  were preserved and excluded from this action.
- **Version decisions:** The latest stable Boot 3.5 patch in Maven Central
  metadata was 3.5.16; Spring Boot 3.5 open-source support ended 2026-06-30.
  Used it to honor the explicit Boot 3 requirement, and documented the support
  risk for engineer review. Direct Python runtime/dev dependencies are pinned
  exactly in `python/pyproject.toml`; rationale and official source links are
  in `docs/dependency-versions.md`.
- **AI decisions:** Added only health, package/build boundaries, API-doc
  routing, independent verifier namespace, smoke tests and CI. No ledger
  routes, schema, application cryptography, persistence or business behavior
  were added. Existing root starter files were not migrated or modified.
- **Human decisions:** No new stakeholder answer, support contract, or approval
  was assumed.
- **Validation performed:** `mvn -B -f java\\pom.xml verify` passed using
  Java 21.0.12.1 and Maven 3.10.0; all 3 Java health/OpenAPI tests passed.
  Maven emitted a non-fatal Byte Buddy dynamic-agent warning. The local Python
  virtual environment was created with Python 3.15.0 (Python 3.11 was not
  installed locally). After installing the exact pinned dependencies,
  `ruff check .`, `ruff format --check .`, `mypy src`, `python -m pytest`, and
  `python -m pip check` all passed; 1 Python health test passed. The first Ruff
  run found an import-format issue, which was corrected with Ruff's automatic
  fix. The first Python test run exposed Starlette's deprecation warning for
  HTTPX; the test extra was changed to Starlette's recommended pinned HTTPX2
  transport, and the final test run passed without that warning. A generated
  editable-install `.egg-info` directory was removed and added to `.gitignore`
  so build metadata is not committed. CI itself was not run remotely.
- **Git/commit:** Staged files were reviewed with the specified local commit
  message `build: scaffold Java and Python services`. No push is authorized.

### Exact Action 02 commands and results

- `mvn -B -f java\pom.xml verify` — passed; Java tests 3/3.
- `python -m venv .venv` (from `python/`) — passed with Python 3.15.0.
- `.\.venv\Scripts\python.exe -m pip install -e '.[dev]'` (from `python/`)
  — passed for the exact declared pins. Pip emitted a non-blocking warning
  that it could not check for a newer pip version.
- `.\.venv\Scripts\python.exe -m pip uninstall -y httpx` (from `python/`)
  — passed; removed the stale test-client dependency after switching to HTTPX2.
- Initial `ruff check .` — failed on I001 import formatting in
  `src/audit_log_service/__main__.py`.
- `ruff check --fix src\audit_log_service\__main__.py` — passed and applied
  the formatting fix.
- Initial `python -m pytest` — 1 passed with Starlette's HTTPX deprecation
  warning; after installing HTTPX2 and removing stale HTTPX, final tests passed
  without that warning.
- `ruff check .` — passed on final scaffold.
- `ruff format --check .` — passed; 5 files already formatted.
- `mypy src` — passed; no issues in 4 source files.
- `python -m pytest` — passed; 1 test.
- `python -m pip check` — passed; no broken requirements.
- `rg` search for `org\.springframework` in Java `core`, `domain`, `store`,
  `service`, `verify`, and `verifier` packages — no matches.
- `git diff --check` and `git diff --cached --check` — passed.
- Remote GitHub Actions CI — not run; no push or publication was performed.
- **Git/commit:** Git identity is configured now. The action authorizes one
  local commit after checks pass; no push is authorized.
