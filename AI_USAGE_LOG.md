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
