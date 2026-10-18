# Performance, limits and failure behaviour

Action 23 evidence for requirement Q-04. These are **measurements of one
synthetic workload on one machine**, not targets, SLOs or capacity claims. No
CI job gates on timing.

## How to reproduce

```powershell
mvn -B -f java\pom.xml package -DskipTests        # builds the jar the benchmark launches
python\.venv\Scripts\python.exe scripts\benchmark.py --output docs\benchmarks\my-run.json
```

`scripts/benchmark.py` (standard library only) starts each service as an operator
would (jar / uvicorn) against its own fresh database and drives it over HTTP.
Everything is configurable: `--events`, `--warmup`, `--concurrency 1,4,...`,
`--read-concurrency`, `--payload-leaves`, `--payload-bytes`, `--actors`,
`--queries`, `--query-limit`, `--scan-pages`, `--verify-runs`, `--export-runs`,
`--export-set-runs`, `--checkpoint-interval`, `--seed`, `--services`.
`python scripts\benchmark.py --help` lists all options; invalid workloads exit 2.
Exit 1 means a functional error (unexpected status, ledger not intact, export set
not READY); timings never affect the exit code.

What is recorded in the JSON (`docs/benchmarks/`): workload parameters, OS, CPU,
RAM, Java / Python / SQLite / library versions, git commit and dirty flag, a
4 KiB write+`fsync` probe on the benchmark volume, per-phase throughput and
min/mean/p50/p95/p99/max latency (nearest-rank), status-code counts, ledger and
file sizes, and peak memory of the service process tree (Windows
`PeakWorkingSetSize`, Linux `VmHWM`; elsewhere reported as unavailable).
Both services enforce `synchronous=FULL` + WAL, so every commit is fsynced; the
fsync probe is recorded because that cost is machine-specific.

## Recorded run (2026-10-18)

File: [`benchmarks/2026-10-18-windows-run1.json`](./benchmarks/2026-10-18-windows-run1.json).
Defaults: 200 warm-up + 2000 measured appends per concurrency level (1 then 4;
the ledger keeps growing, so the second level runs on a larger ledger), 5 string
leaves x 32 chars per event, 20 actors, checkpoint every 100 appends, 3 verify runs.

| Item | Value |
|---|---|
| OS / CPU / RAM | Windows 11 10.0.26200, AMD64 (AuthenticAMD Family 23 Model 160), 8 logical CPUs, 16 GB |
| Java | Temurin 21.0.12.1, sqlite-jdbc 3.53.4.0 |
| Python | benchmark client and service CPython 3.15.0, SQLite 3.53.4, Starlette 1.8.0, uvicorn 0.54.0, pydantic 2.14.1, cryptography 50.0.2 |
| Commit | `f3f6382` plus uncommitted Action 23 changes (`dirtyJavaOrPython: true`) |
| Storage | local drive under the repo; type not detected. 4 KiB write+fsync probe: p50 0.63 ms, p95 1.05 ms, p99 1.45 ms |
| Client | single Python process, keep-alive `http.client`, same machine as the services (they compete for the same 8 CPUs) |

| Service | Phase | Detail | Throughput | p50 ms | p95 ms | p99 ms | Peak RSS MiB |
|---|---|---|---:|---:|---:|---:|---:|
| java | append | concurrency 1 | 97.3/s | 10.0 | 13.4 | 16.8 | 262 |
| java | append | concurrency 4 | 257.8/s | 6.0 | 52.0 | 161.9 | 334 |
| java | query, filter by actor | concurrency 4 | 180.9/s | 18.8 | 41.5 | 65.7 | 384 |
| java | query, GET by id | concurrency 4 | 394.6/s | 5.2 | 32.6 | 64.4 | 384 |
| java | query, cursor scan | 84 pages x 50 | 4909 rec/s | 9.7 | 12.2 | 13.2 | |
| java | verify | 2200 records (first) | 761 ms wall | | | | |
| java | verify | 4200 records (3 runs) | | 489 | 490 | 490 | 384 |
| java | export bundle (actor-0) | 210 records | | 164.7 | 202.0 | 202.0 | |
| java | export set | 210 records, 1 chunk | 0.23 s to READY | | | | 409 |
| python | append | concurrency 1 | 117.0/s | 8.5 | 10.7 | 12.5 | 47 |
| python | append | concurrency 4 | 286.9/s | 5.4 | 37.4 | 161.9 | 52 |
| python | query, filter by actor | concurrency 4 | 69.3/s | 55.6 | 76.6 | 85.9 | 54 |
| python | query, GET by id | concurrency 4 | 395.1/s | 6.2 | 25.2 | 51.4 | 54 |
| python | query, cursor scan | 84 pages x 50 | 3710 rec/s | 12.8 | 14.6 | 36.1 | |
| python | verify | 2200 records (first) | 640 ms wall | | | | |
| python | verify | 4200 records (3 runs) | | 1044 | 1155 | 1155 | 54 |
| python | export bundle (actor-0) | 210 records | | 117.7 | 140.9 | 140.9 | |
| python | export set | 210 records, 1 chunk | 0.11 s to READY | | | | 54 |

Reading the numbers honestly:

- Throughput is per second of successful (2xx) requests; every request in this run
  succeeded. Percentiles for verify/export come from only 3 runs, so p95 and p99
  there equal the maximum; they are not statistically meaningful.
- A first full run of the same configuration (discarded only because the report
  then showed an unresolved sqlite-jdbc version) gave append at concurrency 1 of
  90.4/s (Java) and 117.7/s (Python); the recorded run gave 97.3/s and 117.0/s.
  Treat differences of about 5-10 % as noise. This is two runs, not a confidence
  interval.
- Java's first verify (761 ms at 2200 records) was slower than its verify at 4200
  records (528 ms): that is JVM warm-up, not scaling. Compare steady-state runs only.
- Java peak RSS is dominated by the JVM heap and was not tuned; Python's is smaller.
  Memory was sampled as a peak per phase from the process tree, not per request.
- The service and the load generator share one machine, so absolute figures
  understate what a dedicated host would do and say nothing about a network.

## Single-writer cost model

- Every mutation (append, redaction, archive, checkpoint, export, report) runs
  `BEGIN IMMEDIATE` on a single SQLite database in WAL mode. SQLite allows exactly
  one writer, so write transactions are serialised per ledger by design: the head
  (`seq`, `chainHash`) must be read and extended atomically.
- With `synchronous=FULL`, each commit waits for fsync of the WAL. On a drive where
  flush is slow, that wait (not CPU) becomes the ceiling and is paid serially. The
  recorded drive flushed in about 0.6 ms, so this run does **not** show that regime.
- Observed: 4 concurrent clients gave about 2.6x (Java) and 2.5x (Python) the
  throughput of 1 client, with a much worse tail (p99 162 ms vs 17/13 ms) because
  waiting writers queue on the lock. The gain shows that on this machine a
  meaningful share of per-request time (HTTP parsing, validation, JSON, hashing,
  signing outside the lock) overlaps across clients. The throughput ceiling of the
  serialised commit section was **not** isolated or measured; do not extrapolate the
  4-client figure to higher concurrency.
- Contention surfaces as latency up to `busy_timeout` (30 s), then HTTP 503
  `STORAGE_BUSY`. Scaling beyond one writer needs a different design
  (sharded ledgers or an external sequencer); this prototype does not attempt it.
- Every N appends (default 100) the request that crosses the interval also signs
  and stores a checkpoint, adding an Ed25519 signature to that request; the
  p99 includes those requests.

## Full-scan costs

- **Verify** reads the whole ledger in one snapshot in batches of 1000 and
  recomputes content, leaf and chain hashes: O(records) time, O(batch) memory plus
  at most 100 retained diagnostics. Measured steady-state: about 0.12 ms/record
  (Java) and 0.25 ms/record (Python) at 4200 records on this machine. It holds a
  read snapshot for its duration; in WAL this does not block writers but pins WAL
  frames until the read ends, so checkpointing cannot reclaim them meanwhile.
- **Account-access report** verifies the selected data head and derives evidence
  within one transaction, so it costs a full verify plus the selection, and is
  capped at 10,000 matching records (explicit 422 beyond).
- **Export bundle** (`GET /audit/export`) scales with the selection and is capped
  by record and byte limits (422 when exceeded); **export sets** stream chunks
  under bounded memory and also append `BUNDLE_EXPORTED` plus a checkpoint.
  Selection by `actorId` / `resourceId` uses indexes, but selecting all records is a
  full scan of live rows.
- **Archive audit** reads archive files and compares to the skeleton: cost scales
  with archived record count and file size.
- Filtered queries use indexed seq-keyset paging (no `OFFSET`); an unindexed
  combination of filters can still scan. The measured filter-by-actor query is
  slower than GET-by-id in both services, and Python was about 2.6x slower than
  Java there; the cause was not investigated.
- None of the above was measured beyond about 4,200 records or with large
  payloads; behaviour at millions of records is unmeasured.

## Failure behaviour (simulated, bounded)

No real disk is filled and no test asserts a timing target. Seams:
Python `SqliteStore(max_page_count=...)`, Java `JdbcAuditRepository.setMaxPageCount`
(SQLite `PRAGMA max_page_count`), a decorator that sleeps inside the write
transaction, and a held write lock with a short busy timeout
(`JdbcAuditRepository(path, ledger, busyTimeoutMillis)` / `busy_timeout_ms`).
Production defaults are unchanged (no page cap, 30 s timeout).

| Scenario | Tests | Observed behaviour |
|---|---|---|
| Disk full (`SQLITE_FULL`) | Python `test_failure_modes.py`, Java `FailureModeTests` | The failing write rolls back: no partial event, no sequence gap; the ledger verifies intact; reads keep working; appends resume contiguously when space returns. Over HTTP (Python) the client gets a generic `500 INTERNAL_ERROR` with no SQLite text. |
| Slow I/O | same | 4 writers x 3 appends with 50 ms added inside the transaction all succeed, `seq` is contiguous, ledger intact; elapsed time is at least the serial lower bound (asserted only as a lower bound). |
| Busy writers | same, plus existing `test_service_store.py` | With the write lock held, concurrent writers fail with the busy error (HTTP 503 `STORAGE_BUSY`) within the configured timeout instead of hanging, nothing is written, readers still work, and appends succeed after release. |
| Backpressure | Python `test_exports.py`, Java `ExportSetServiceTests.jobsBeyondTheActiveLimitAreRejectedAsBusyAndNothingIsStored` | More than 16 active export jobs yields `429 EXPORT_SET_BUSY`; the rejected request creates no job. |
| Request size / depth | earlier actions | 256 KiB request, 64 KiB payload, depth 10, 500 leaves enforced with 413/422. |

Known gap, deliberately not changed here: disk-full is reported as a generic 500,
not 503/507, in both services (Java's handler also maps non-constraint SQLite errors
to 500). Whether to expose a distinct, retryable code is a design decision for the
engineer; the data-integrity behaviour is the part verified.

## Limits of this evidence

- One machine, one drive type, one client process; Windows only. The Unix path of the
  memory probe (`VmHWM`) is implemented but was not run here.
- No fixed seed makes timings repeatable; the seed only fixes the payload content.
- Docker, a network between client and server, TLS, antivirus effects and realistic
  production payload mixes are not covered.
- The existing CI `e2e` job (`pytest -m e2e`) also runs a tiny benchmark against
  each service (`test_benchmark_script.py`); it asserts completion and result
  shape only, with no timing threshold. CI has not been executed here, so the
  Linux memory probe is untested until it runs.
