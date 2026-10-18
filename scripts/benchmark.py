"""Black-box HTTP benchmark for the Java and Python audit-log services.

Starts each service as an operator would (jar / uvicorn) against its own fresh
database, then measures append, query, verify and export with a synthetic,
configurable workload. Standard library only; run it with the Python that has
the service installed (the venv) so the Python service can be launched.

It reports whatever it measures. It has no pass/fail timing thresholds and
invents no targets. Exit status: 0 completed with no functional errors,
1 functional errors (unexpected HTTP status, verify not intact, service failed
to start), 2 usage error.

Results depend heavily on the machine, drive and fsync cost; read the recorded
environment and fsync probe next to the numbers. See docs/performance.md.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import http.client
import json
import math
import os
import platform
import random
import re
import shutil
import socket
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PYTHON_DIR = ROOT / "python"
DEFAULT_JAR = ROOT / "java" / "target" / "audit-log-service-0.1.0-SNAPSHOT.jar"
WRITER = {"X-API-Key": "dev-writer-only", "Content-Type": "application/json"}
READER = {"X-API-Key": "dev-reader-only"}
AUDITOR = {"X-API-Key": "dev-auditor-only"}
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
MAX_LEAVES = 500
MAX_PAYLOAD_BYTES = 60_000


def percentile(sorted_values: list[float], pct: float) -> float:
    """Nearest-rank percentile of an already sorted, non-empty list."""
    rank = max(1, math.ceil(pct / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


def summarize(latencies_ms: list[float]) -> dict[str, float] | None:
    if not latencies_ms:
        return None
    ordered = sorted(latencies_ms)
    return {
        "min": round(ordered[0], 3),
        "mean": round(statistics.fmean(ordered), 3),
        "p50": round(percentile(ordered, 50), 3),
        "p95": round(percentile(ordered, 95), 3),
        "p99": round(percentile(ordered, 99), 3),
        "max": round(ordered[-1], 3),
    }


def parse_int_list(text: str) -> list[int]:
    values = [int(part) for part in text.split(",") if part.strip()]
    if not values or any(value <= 0 for value in values):
        raise ValueError("expected a comma-separated list of positive integers")
    return values


# ---------------------------------------------------------------- environment


def _windows_total_ram() -> int | None:
    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(MemoryStatus)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
        return None
    return int(status.ullTotalPhys)


def total_ram_bytes() -> int | None:
    try:
        if os.name == "nt":
            return _windows_total_ram()
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, AttributeError):
        return None
    return None


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def run_text(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return (result.stderr or result.stdout).strip() or None


def package_version(name: str) -> str | None:
    from importlib import metadata

    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def sqlite_jdbc_version() -> str | None:
    match = re.search(
        r"<sqlite-jdbc\.version>([^<]+)</sqlite-jdbc\.version>",
        (ROOT / "java" / "pom.xml").read_text(encoding="utf-8"),
    )
    return match.group(1) if match else None


def git_state() -> dict[str, Any]:
    head = run_text(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    dirty = run_text(
        ["git", "-C", str(ROOT), "status", "--porcelain", "--", "java", "python"]
    )
    return {"commit": head, "dirtyJavaOrPython": bool(dirty)}


def fsync_probe(directory: Path, iterations: int) -> dict[str, Any]:
    """Time 4 KiB write+fsync on the benchmark volume (what synchronous=FULL pays)."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "fsync-probe.bin"
    block = os.urandom(4096)
    samples: list[float] = []
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    try:
        for _ in range(iterations):
            started = time.perf_counter_ns()
            os.write(descriptor, block)
            os.fsync(descriptor)
            samples.append((time.perf_counter_ns() - started) / 1e6)
    finally:
        os.close(descriptor)
        path.unlink(missing_ok=True)
    return {
        "iterations": iterations,
        "blockBytes": 4096,
        "latencyMs": summarize(samples),
        "note": "Plain file write+fsync; SQLite WAL commit cost is comparable but not identical.",
    }


def environment(args: argparse.Namespace, java_exe: str | None) -> dict[str, Any]:
    ram = total_ram_bytes()
    return {
        "capturedAt": datetime.now(UTC).isoformat(timespec="seconds"),
        "os": platform.platform(),
        "machine": platform.machine(),
        "cpuModel": cpu_model(),
        "logicalCpus": os.cpu_count(),
        "totalRamBytes": ram,
        "benchmarkClientPython": sys.version.split()[0],
        "javaVersion": run_text([java_exe, "-version"]) if java_exe else None,
        "pythonSqlite": sqlite3.sqlite_version,
        "sqliteJdbc": sqlite_jdbc_version(),
        "pythonPackages": {
            name: package_version(name)
            for name in ("starlette", "uvicorn", "pydantic", "cryptography")
        },
        "git": git_state(),
        "storage": {
            "workDir": str(args.work_dir),
            "synchronous": "FULL (enforced by both services on every connection)",
            "journalMode": "WAL",
            "note": "Drive type is not detected; record it by hand when comparing runs.",
        },
    }


# ------------------------------------------------------------ process memory


def _windows_tree_pids(root_pid: int) -> list[int]:
    class Entry(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", ctypes.c_ulong),
            ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(Entry)]
    kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(Entry)]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    snapshot = kernel32.CreateToolhelp32Snapshot(0x2, 0)
    parents: dict[int, int] = {}
    entry = Entry()
    entry.dwSize = ctypes.sizeof(Entry)
    try:
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            parents[entry.th32ProcessID] = entry.th32ParentProcessID
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    tree = [root_pid]
    for pid in tree:
        tree.extend(
            child
            for child, parent in parents.items()
            if parent == pid and child not in tree
        )
    return tree


def _windows_peak_bytes(pid: int) -> int | None:
    class Counters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    psapi = ctypes.WinDLL("psapi", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    psapi.GetProcessMemoryInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(Counters),
        ctypes.c_ulong,
    ]
    handle = kernel32.OpenProcess(0x0410, 0, pid)
    if not handle:
        return None
    try:
        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return None
        return int(counters.PeakWorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


def _linux_tree_pids(root_pid: int) -> list[int]:
    parents: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                stat = (entry / "stat").read_text()
                parents[int(entry.name)] = int(stat.rsplit(")", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                continue
    tree = [root_pid]
    for pid in tree:
        tree.extend(
            child
            for child, parent in parents.items()
            if parent == pid and child not in tree
        )
    return tree


def _linux_peak_bytes(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        return None
    return None


def peak_memory_bytes(root_pid: int) -> int | None:
    """Largest peak resident set among the service process and its descendants.

    Windows: PeakWorkingSetSize. Linux: VmHWM. Other platforms: unavailable.
    The venv launcher on Windows spawns the real interpreter as a child, hence the tree.
    """
    try:
        if os.name == "nt":
            peaks = [_windows_peak_bytes(pid) for pid in _windows_tree_pids(root_pid)]
        elif sys.platform.startswith("linux"):
            peaks = [_linux_peak_bytes(pid) for pid in _linux_tree_pids(root_pid)]
        else:
            return None
    except (OSError, AttributeError):
        return None
    known = [peak for peak in peaks if peak is not None]
    return max(known) if known else None


# ------------------------------------------------------------------ services


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Service:
    def __init__(self, kind: str, home: Path, args: argparse.Namespace) -> None:
        self.kind = kind
        self.home = home
        self.args = args
        self.port = free_port()
        self.process: subprocess.Popen[bytes] | None = None

    @property
    def env(self) -> dict[str, str]:
        home = self.home
        return {
            "AUDIT_ENV": "dev",
            "AUDIT_LEDGER_ID": f"bench-{self.kind}",
            "AUDIT_DB_PATH": str(home / "audit.db"),
            "AUDIT_SIGNING_PRIVATE_KEY": str(home / "keys" / "private.pem"),
            "AUDIT_SIGNING_PUBLIC_KEY": str(home / "keys" / "public.b64"),
            "AUDIT_ARCHIVE_DIR": str(home / "archives"),
            "AUDIT_EXPORT_DIR": str(home / "exports"),
            "AUDIT_CHECKPOINT_INTERVAL": str(self.args.checkpoint_interval),
        }

    def command(self) -> list[str]:
        if self.kind == "java":
            (self.home / "tmp").mkdir(parents=True, exist_ok=True)
            return [
                self.args.java,
                f"-Djava.io.tmpdir={self.home / 'tmp'}",
                "-jar",
                str(self.args.jar),
                f"--server.port={self.port}",
            ]
        return [
            self.args.python,
            "-m",
            "uvicorn",
            "audit_log_service.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--log-level",
            "warning",
        ]

    def start(self, timeout: float = 180) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        log = (self.home / f"{self.kind}.log").open("wb")
        self.process = subprocess.Popen(
            self.command(),
            cwd=PYTHON_DIR,
            env={**os.environ, **self.env},
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                tail = (self.home / f"{self.kind}.log").read_text(errors="replace")[
                    -2000:
                ]
                raise RuntimeError(f"{self.kind} exited at startup:\n{tail}")
            try:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", self.port, timeout=2
                )
                connection.request("GET", "/health")
                if connection.getresponse().status == 200:
                    return
            except (OSError, http.client.HTTPException):
                time.sleep(0.25)
        raise RuntimeError(f"{self.kind} did not become healthy within {timeout}s")

    def peak_memory(self) -> int | None:
        return peak_memory_bytes(self.process.pid) if self.process else None

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=20)


# ------------------------------------------------------------------ load gen


class Client:
    """One keep-alive connection per worker thread."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.connection: http.client.HTTPConnection | None = None

    def request(
        self, method: str, path: str, headers: dict[str, str], body: bytes | None = None
    ) -> tuple[int, bytes]:
        try:
            if self.connection is None:
                self.connection = http.client.HTTPConnection(
                    "127.0.0.1", self.port, timeout=300
                )
            self.connection.request(method, path, body=body, headers=headers)
            response = self.connection.getresponse()
            return response.status, response.read()
        except (OSError, http.client.HTTPException):
            if self.connection is not None:
                self.connection.close()
            self.connection = None
            return 0, b""


Build = Callable[[int], tuple[str, str, dict[str, str], bytes | None]]
Observe = Callable[[int, int, bytes], None]


def run_load(
    port: int,
    total: int,
    concurrency: int,
    build: Build,
    observe: Observe | None = None,
) -> dict[str, Any]:
    counter = iter(range(total))
    claim = threading.Lock()
    per_worker: list[list[tuple[int, float]]] = [[] for _ in range(concurrency)]
    barrier = threading.Barrier(concurrency + 1)

    def worker(index: int) -> None:
        client = Client(port)
        local = per_worker[index]
        barrier.wait()
        while True:
            with claim:
                item = next(counter, None)
            if item is None:
                return
            method, path, headers, body = build(item)
            started = time.perf_counter_ns()
            status, data = client.request(method, path, headers, body)
            local.append((status, (time.perf_counter_ns() - started) / 1e6))
            if observe is not None:
                observe(item, status, data)

    threads = [
        threading.Thread(target=worker, args=(i,), daemon=True)
        for i in range(concurrency)
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    started = time.perf_counter()
    for thread in threads:
        thread.join()
    wall = time.perf_counter() - started
    samples = [sample for local in per_worker for sample in local]
    statuses: dict[str, int] = {}
    for status, _ in samples:
        statuses[str(status)] = statuses.get(str(status), 0) + 1
    good = [latency for status, latency in samples if 200 <= status < 300]
    return {
        "requests": len(samples),
        "concurrency": concurrency,
        "statusCounts": statuses,
        "okRequests": len(good),
        "wallSeconds": round(wall, 4),
        "throughputPerSec": round(len(good) / wall, 2) if wall > 0 else None,
        "latencyMs": summarize(good),
    }


def event_body(rng: random.Random, index: int, args: argparse.Namespace) -> bytes:
    payload = {
        f"f{leaf}": "".join(rng.choices(ALPHABET, k=args.payload_bytes))
        for leaf in range(args.payload_leaves)
    }
    return json.dumps(
        {
            "eventType": "BENCH_EVENT",
            "actorId": f"actor-{index % args.actors}",
            "resourceType": "DOCUMENT",
            "resourceId": f"doc-{index % 97}",
            "payload": payload,
        }
    ).encode("utf-8")


# -------------------------------------------------------------------- phases


def measure_append(
    service: Service, args: argparse.Namespace, seed_offset: int
) -> dict[str, Any]:
    rng = random.Random(args.seed + seed_offset)
    sample_ids: list[str] = []
    guard = threading.Lock()

    def observe(_: int, status: int, data: bytes) -> None:
        if status == 201 and len(sample_ids) < 200:
            with guard:
                sample_ids.append(json.loads(data)["eventId"])

    def build_for(count_base: int) -> Build:
        def build(index: int) -> tuple[str, str, dict[str, str], bytes | None]:
            return (
                "POST",
                "/audit/events",
                WRITER,
                event_body(rng, count_base + index, args),
            )

        return build

    if args.warmup:
        run_load(service.port, args.warmup, args.concurrency_levels[0], build_for(0))
    results: list[dict[str, Any]] = []
    base = args.warmup
    for level in args.concurrency_levels:
        results.append(
            run_load(service.port, args.events, level, build_for(base), observe)
        )
        base += args.events
        service_state = {"peakMemoryBytes": service.peak_memory()}
        results[-1].update(service_state)
        results[-1]["ledgerSizeAfter"] = base
        if args.scale_verify:
            results[-1]["verifyAtThisSize"] = measure_verify_once(service)
    return {
        "warmupEvents": args.warmup,
        "levels": results,
        "sampleEventIds": sample_ids,
    }


def measure_verify_once(service: Service) -> dict[str, Any]:
    client = Client(service.port)
    started = time.perf_counter_ns()
    status, data = client.request("GET", "/audit/verify", AUDITOR)
    elapsed = (time.perf_counter_ns() - started) / 1e6
    report = json.loads(data) if status == 200 else {}
    return {
        "status": status,
        "wallMs": round(elapsed, 3),
        "serverDurationMs": report.get("durationMs"),
        "checkedRecords": report.get("checkedRecords"),
        "intact": report.get("intact"),
        "checkpointsVerified": report.get("checkpointsVerified"),
    }


def measure_query(
    service: Service, args: argparse.Namespace, ids: list[str]
) -> dict[str, Any]:
    total = args.queries
    first_page = run_load(
        service.port,
        total,
        args.read_concurrency,
        lambda i: (
            "GET",
            f"/audit/events?actorId=actor-{i % args.actors}&limit={args.query_limit}",
            READER,
            None,
        ),
    )
    by_id: dict[str, Any] | None = None
    if ids:
        by_id = run_load(
            service.port,
            total,
            args.read_concurrency,
            lambda i: ("GET", f"/audit/events/{ids[i % len(ids)]}", READER, None),
        )
    client = Client(service.port)
    page_latencies: list[float] = []
    cursor: str | None = None
    pages = 0
    records = 0
    statuses: dict[str, int] = {}
    started = time.perf_counter()
    while pages < args.scan_pages:
        path = f"/audit/events?limit={args.query_limit}&order=asc"
        if cursor:
            path += f"&cursor={cursor}"
        t0 = time.perf_counter_ns()
        status, data = client.request("GET", path, READER)
        page_latencies.append((time.perf_counter_ns() - t0) / 1e6)
        statuses[str(status)] = statuses.get(str(status), 0) + 1
        if status != 200:
            break
        page = json.loads(data)
        pages += 1
        records += len(page["items"])
        cursor = page.get("nextCursor")
        if not cursor:
            break
    wall = time.perf_counter() - started
    return {
        "filteredFirstPage": first_page,
        "getByEventId": by_id,
        "cursorScan": {
            "pagesRequested": pages,
            "recordsRead": records,
            "limit": args.query_limit,
            "reachedEnd": cursor is None,
            "statusCounts": statuses,
            "wallSeconds": round(wall, 4),
            "recordsPerSec": round(records / wall, 2) if wall > 0 else None,
            "pageLatencyMs": summarize(page_latencies),
        },
        "peakMemoryBytes": service.peak_memory(),
    }


def measure_verify(service: Service, args: argparse.Namespace) -> dict[str, Any]:
    runs = [measure_verify_once(service) for _ in range(args.verify_runs)]
    walls = [run["wallMs"] for run in runs if run["status"] == 200]
    return {
        "runs": runs,
        "wallLatencyMs": summarize(walls),
        "peakMemoryBytes": service.peak_memory(),
    }


def measure_export(service: Service, args: argparse.Namespace) -> dict[str, Any]:
    actor = "actor-0"
    client = Client(service.port)
    bundle_runs: list[dict[str, Any]] = []
    for _ in range(args.export_runs):
        started = time.perf_counter_ns()
        status, data = client.request("GET", f"/audit/export?actorId={actor}", AUDITOR)
        elapsed = (time.perf_counter_ns() - started) / 1e6
        entry: dict[str, Any] = {
            "status": status,
            "wallMs": round(elapsed, 3),
            "bytes": len(data),
        }
        if status == 200:
            entry["recordCount"] = json.loads(data).get("recordCount")
        elif status == 422:
            entry["note"] = (
                "selection exceeds small-bundle limits (expected for large selections)"
            )
        bundle_runs.append(entry)
    set_runs: list[dict[str, Any]] = []
    for _ in range(args.export_set_runs):
        started = time.perf_counter()
        status, data = client.request(
            "POST", f"/audit/export-sets?actorId={actor}", AUDITOR
        )
        entry = {"createStatus": status}
        if status == 202:
            descriptor = json.loads(data)
            deadline = time.monotonic() + args.export_timeout
            while descriptor.get("status") == "RUNNING" and time.monotonic() < deadline:
                time.sleep(0.1)
                code, data = client.request(
                    "GET", f"/audit/export-sets/{descriptor['exportSetId']}", AUDITOR
                )
                if code != 200:
                    break
                descriptor = json.loads(data)
            entry.update(
                {
                    "finalStatus": descriptor.get("status"),
                    "secondsToTerminal": round(time.perf_counter() - started, 3),
                    "totalRecords": descriptor.get("totalRecords"),
                    "chunkCount": descriptor.get("chunkCount"),
                }
            )
        set_runs.append(entry)
    return {
        "actor": actor,
        "smallBundle": {
            "runs": bundle_runs,
            "wallLatencyMs": summarize(
                [r["wallMs"] for r in bundle_runs if r["status"] == 200]
            ),
        },
        "exportSet": {"runs": set_runs},
        "peakMemoryBytes": service.peak_memory(),
    }


def storage_footprint(home: Path) -> dict[str, int]:
    sizes: dict[str, int] = {}
    for name in ("audit.db", "audit.db-wal", "audit.db-shm"):
        path = home / name
        sizes[name] = path.stat().st_size if path.exists() else 0
    return sizes


def benchmark_service(
    kind: str, args: argparse.Namespace, run_dir: Path
) -> dict[str, Any]:
    service = Service(kind, run_dir / kind, args)
    result: dict[str, Any] = {"service": kind}
    try:
        service.start()
        result["idlePeakMemoryBytes"] = service.peak_memory()
        result["append"] = measure_append(service, args, 0)
        ids = result["append"].pop("sampleEventIds")
        result["query"] = measure_query(service, args, ids)
        result["verify"] = measure_verify(service, args)
        result["export"] = measure_export(service, args)
        result["finalPeakMemoryBytes"] = service.peak_memory()
        result["storageBytes"] = storage_footprint(service.home)
    finally:
        service.stop()
    result["functionalErrors"] = functional_errors(result)
    return result


def functional_errors(result: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for level in result["append"]["levels"]:
        bad = {k: v for k, v in level["statusCounts"].items() if k != "201"}
        if bad:
            problems.append(f"append concurrency={level['concurrency']} statuses {bad}")
        verify = level.get("verifyAtThisSize")
        if verify and not verify.get("intact"):
            problems.append(f"verify after level {level['concurrency']} not intact")
    query = result["query"]
    for name in ("filteredFirstPage", "getByEventId"):
        phase = query[name]
        if phase and phase["okRequests"] != phase["requests"]:
            problems.append(f"query {name} statuses {phase['statusCounts']}")
    if set(query["cursorScan"]["statusCounts"]) - {"200"}:
        problems.append(f"cursor scan statuses {query['cursorScan']['statusCounts']}")
    for run in result["verify"]["runs"]:
        if run["status"] != 200 or not run["intact"]:
            problems.append(f"verify run failed: {run}")
    for run in result["export"]["smallBundle"]["runs"]:
        if run["status"] not in (200, 422):
            problems.append(f"export bundle status {run['status']}")
    for run in result["export"]["exportSet"]["runs"]:
        if run.get("createStatus") != 202 or run.get("finalStatus") != "READY":
            problems.append(f"export set not READY: {run}")
    return problems


# --------------------------------------------------------------------- report


def mib(value: int | None) -> str:
    return "n/a" if value is None else f"{value / 1048576:.0f}"


def fmt(summary: dict[str, float] | None, key: str) -> str:
    return "n/a" if not summary else f"{summary[key]:.1f}"


def markdown(report: dict[str, Any]) -> str:
    lines = [
        "| Service | Phase | Detail | Throughput | p50 ms | p95 ms | p99 ms | Peak RSS MiB |"
    ]
    lines.append("|---|---|---|---:|---:|---:|---:|---:|")
    for item in report["results"]:
        kind = item["service"]
        for level in item["append"]["levels"]:
            latency = level["latencyMs"]
            lines.append(
                f"| {kind} | append | concurrency {level['concurrency']}, "
                f"{level['okRequests']}/{level['requests']} ok | "
                f"{level['throughputPerSec']}/s | {fmt(latency, 'p50')} | {fmt(latency, 'p95')} | "
                f"{fmt(latency, 'p99')} | {mib(level['peakMemoryBytes'])} |"
            )
        query = item["query"]
        for name in ("filteredFirstPage", "getByEventId"):
            phase = query[name]
            if phase:
                latency = phase["latencyMs"]
                lines.append(
                    f"| {kind} | query {name} | concurrency {phase['concurrency']} | "
                    f"{phase['throughputPerSec']}/s | {fmt(latency, 'p50')} | {fmt(latency, 'p95')} | "
                    f"{fmt(latency, 'p99')} | {mib(query['peakMemoryBytes'])} |"
                )
        scan = query["cursorScan"]
        lines.append(
            f"| {kind} | query cursor scan | {scan['pagesRequested']} pages x {scan['limit']} | "
            f"{scan['recordsPerSec']} rec/s | {fmt(scan['pageLatencyMs'], 'p50')} | "
            f"{fmt(scan['pageLatencyMs'], 'p95')} | {fmt(scan['pageLatencyMs'], 'p99')} | |"
        )
        for level in item["append"]["levels"]:
            verify = level.get("verifyAtThisSize")
            if verify:
                lines.append(
                    f"| {kind} | verify | ledger {verify['checkedRecords']} records | "
                    f"{verify['wallMs']:.0f} ms wall (server {verify['serverDurationMs']} ms) | | | | |"
                )
        verify_summary = item["verify"]["wallLatencyMs"]
        lines.append(
            f"| {kind} | verify (final) | {len(item['verify']['runs'])} runs | | "
            f"{fmt(verify_summary, 'p50')} | {fmt(verify_summary, 'p95')} | "
            f"{fmt(verify_summary, 'p99')} | {mib(item['verify']['peakMemoryBytes'])} |"
        )
        export = item["export"]
        bundle = export["smallBundle"]["wallLatencyMs"]
        if bundle:
            lines.append(
                f"| {kind} | export bundle | actor-0 | | {fmt(bundle, 'p50')} | {fmt(bundle, 'p95')} | "
                f"{fmt(bundle, 'p99')} | |"
            )
        for run in export["exportSet"]["runs"]:
            lines.append(
                f"| {kind} | export set | {run.get('totalRecords')} records, "
                f"{run.get('chunkCount')} chunks, {run.get('finalStatus')} | "
                f"{run.get('secondsToTerminal')} s to terminal | | | | {mib(export['peakMemoryBytes'])} |"
            )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--services", default="java,python", help="comma list of java,python"
    )
    parser.add_argument(
        "--events",
        type=int,
        default=2000,
        help="measured appends per concurrency level",
    )
    parser.add_argument(
        "--warmup", type=int, default=200, help="unmeasured warm-up appends"
    )
    parser.add_argument(
        "--concurrency", default="1,4", help="comma list of append concurrency levels"
    )
    parser.add_argument("--read-concurrency", type=int, default=4)
    parser.add_argument("--payload-leaves", type=int, default=5)
    parser.add_argument(
        "--payload-bytes", type=int, default=32, help="characters per string leaf"
    )
    parser.add_argument("--actors", type=int, default=20)
    parser.add_argument("--queries", type=int, default=500)
    parser.add_argument("--query-limit", type=int, default=50)
    parser.add_argument("--scan-pages", type=int, default=100)
    parser.add_argument("--verify-runs", type=int, default=3)
    parser.add_argument("--no-scale-verify", dest="scale_verify", action="store_false")
    parser.add_argument("--export-runs", type=int, default=3)
    parser.add_argument("--export-set-runs", type=int, default=1)
    parser.add_argument("--export-timeout", type=float, default=300)
    parser.add_argument("--checkpoint-interval", type=int, default=100)
    parser.add_argument("--fsync-iterations", type=int, default=200)
    parser.add_argument("--seed", type=int, default=20261018)
    parser.add_argument("--jar", type=Path, default=DEFAULT_JAR)
    parser.add_argument("--java", default=shutil.which("java") or "java")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="default: <repo>/benchmark-work/<timestamp>",
    )
    parser.add_argument("--output", type=Path, default=None, help="JSON results file")
    parser.add_argument("--keep-work-dir", action="store_true")
    return parser


def validate(args: argparse.Namespace) -> str | None:
    try:
        args.concurrency_levels = parse_int_list(args.concurrency)
    except ValueError as error:
        return str(error)
    args.service_list = [
        item.strip() for item in args.services.split(",") if item.strip()
    ]
    if not args.service_list or set(args.service_list) - {"java", "python"}:
        return "--services must be java, python or java,python"
    positives = {
        "events": args.events,
        "read-concurrency": args.read_concurrency,
        "payload-leaves": args.payload_leaves,
        "payload-bytes": args.payload_bytes,
        "actors": args.actors,
        "queries": args.queries,
        "query-limit": args.query_limit,
        "scan-pages": args.scan_pages,
        "verify-runs": args.verify_runs,
        "checkpoint-interval": args.checkpoint_interval,
        "fsync-iterations": args.fsync_iterations,
    }
    for name, value in positives.items():
        if value <= 0:
            return f"--{name} must be positive"
    if args.warmup < 0 or args.export_runs < 0 or args.export_set_runs < 0:
        return "--warmup and export run counts must not be negative"
    if args.payload_leaves > MAX_LEAVES or args.query_limit > 500:
        return (
            f"payload leaves max {MAX_LEAVES} and query limit max 500 (service limits)"
        )
    if args.payload_leaves * (args.payload_bytes + 12) > MAX_PAYLOAD_BYTES:
        return "payload would exceed the 64 KiB service payload limit"
    if "java" in args.service_list and not args.jar.is_file():
        return f"jar not found: {args.jar} (run mvn -f java/pom.xml verify)"
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    problem = validate(args)
    if problem:
        print(f"usage error: {problem}", file=sys.stderr)
        return 2
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    created_work_dir = args.work_dir is None
    args.work_dir = args.work_dir or ROOT / "benchmark-work" / stamp
    run_dir = Path(args.work_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "tool": "scripts/benchmark.py",
        "workload": {
            key: getattr(args, key)
            for key in (
                "events",
                "warmup",
                "concurrency_levels",
                "read_concurrency",
                "payload_leaves",
                "payload_bytes",
                "actors",
                "queries",
                "query_limit",
                "scan_pages",
                "verify_runs",
                "export_runs",
                "export_set_runs",
                "checkpoint_interval",
                "seed",
            )
        },
        "environment": environment(
            args, args.java if "java" in args.service_list else None
        ),
        "fsyncProbe": fsync_probe(run_dir, args.fsync_iterations),
        "results": [],
        "disclaimer": (
            "Single-machine, single-client-process measurements of a synthetic workload. "
            "No targets are implied; do not compare across machines or drives."
        ),
    }
    failed = False
    try:
        for kind in args.service_list:
            print(f"== benchmarking {kind} ...", flush=True)
            try:
                item = benchmark_service(kind, args, run_dir)
            except (RuntimeError, OSError, KeyError, ValueError) as error:
                item = {"service": kind, "functionalErrors": [f"run failed: {error}"]}
                failed = True
                print(f"{kind} failed: {error}", file=sys.stderr)
                report["results"].append(item)
                continue
            failed = failed or bool(item["functionalErrors"])
            report["results"].append(item)
    finally:
        if created_work_dir and not args.keep_work_dir:
            shutil.rmtree(run_dir, ignore_errors=True)
    complete = [item for item in report["results"] if "append" in item]
    output = args.output or ROOT / "benchmark-results" / f"{stamp}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    digest = hashlib.sha256(output.read_bytes()).hexdigest()[:12]
    if complete:
        print(markdown({"results": complete}))
    print(f"\nresults: {output} (sha256 {digest})")
    for item in report["results"]:
        for problem_text in item.get("functionalErrors", []):
            print(
                f"FUNCTIONAL ERROR [{item['service']}]: {problem_text}", file=sys.stderr
            )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
