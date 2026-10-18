# Adversarial and cross-process validation (Action 21)

Both services are started as real operating-system processes (the Java jar via `java -jar`,
the Python service via `uvicorn`), each on its own synthetic SQLite database, and driven only
over HTTP plus raw SQLite access. Test keys are synthetic dev keys.

## Where it lives

| Item | Path |
| --- | --- |
| Process harness | `python/tests/e2e_support.py` |
| Multi-process HTTP append worker | `python/tests/e2e_http_worker.py` |
| Tests (pytest marker `e2e`) | `python/tests/test_e2e_http.py` |
| Windows demo (run on both services) | `scripts/demo.ps1` |
| Unix demo (**not executed**, see limits) | `scripts/demo.sh` |
| Synthetic tamper tool (existing) | `scripts/synthetic_tamper.py` |

Run: `python -m pytest tests/test_e2e_http.py` from `python/`. Java parameters need
`mvn -f java/pom.xml package` first; without the jar they are skipped, not faked.

## What is covered, per service (Java and Python)

- Scenarios A/B/C end to end: append, query paging, verify, on-demand checkpoint, export, redaction,
  chunked export set downloaded and verified offline from its manifest, account-access report.
- Offline verification with the pinned key (exit 0), a wrong pinned key (exit 1), self-asserted mode
  (exit 0, origin untrusted) and no key (exit 1, `TRUSTED_KEY_REQUIRED`).
- Real archive over HTTP on a back-dated synthetic ledger, archive audit, restart, repeat archive.
- Four concurrent client processes appending over HTTP; two server processes sharing one database file.
- Abrupt process kill and restart: sequence continues, public key unchanged, checkpoints persist.
- Busy-WAL redaction cleanup (a held reader snapshot): `PENDING`, then `COMPLETE` after retry.
- Rejected writes (reserved type, caller source, caller timestamp, missing target) leave no gap.
- Report appends exactly one system event and keeps the ledger intact.
- Empty ledger is intact at seq 0 and refuses a checkpoint with 409.

## Cross-process tamper matrix

A ledger is built offline by the Python library, copied, tampered with raw SQL (guard triggers dropped,
as a database administrator could), and then opened by **both** services. For every case the test asserts the
expected violation type is reported, `intact` is false, and the Java and Python `(type, seq)` sets are
identical. This also proves each service can open a database and key files written by the other
implementation.

Cases: content edit, chain-hash edit, previous-hash edit, genesis mismatch, sequence gap, leaf value edit,
unknown hash version, unauthorized redaction, unauthorized archive, bad checkpoint signature, tail truncation
with a surviving checkpoint, forged signed checkpoint (mismatch), malformed redaction authorization, retention
policy violation. Positive controls: a valid redaction authorization and a valid archive authorization stay intact.
All 13 violation types are asserted by the per-service verifier suites (surveyed, not re-counted here); this matrix re-asserts the cases listed above over real HTTP.

## Findings fixed in this action

- Java had no `POST /audit/admin/checkpoints`; the unmapped route answered 500. Implemented, with a Java MockMvc test.
- Not a product defect, but recorded: `AUDIT_RETENTION_DAYS` below 1 is accepted by configuration yet the archive policy rounds it up
  to whole days (minimum 1) in the Python service, so real-time fractional retention cannot be used for archive tests. Archive tests back-date
  the synthetic ledger instead.
- Observation, not changed: Java's generic exception handlers return a safe 500 body but log nothing, which made this defect hard
  to diagnose from the process log.

## Limits (honest)

- Archive crash stages are not controllable over HTTP. They stay covered by the in-process `SimulatedCrashError` tests in each service.
- Windows `Popen.kill()` is TerminateProcess; there is no graceful-shutdown path, so every restart is a crash restart.
- `scripts/demo.sh` was never executed (no bash available). Treat it as untested.
- Directory creation under the user temp directory failed for the Python key file in the authoring sandbox (ACL inheritance); the demo
  accepts `-WorkDir` for that reason. Not reproduced elsewhere.
- No benchmarks or load targets are claimed here.
