package com.auditlog.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.store.AuditRepository;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.store.StorageBusyException;
import com.auditlog.verify.LedgerVerifier;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Bounded failure simulation. Disk-full uses SQLite's max_page_count, slow I/O adds fixed latency
 * inside the write transaction and busy uses a held write lock with a short busy timeout. Nothing
 * fills a real disk and no test asserts a throughput figure.
 */
class FailureModeTests {

    private static final String LEDGER_ID = "failure-mode-ledger";

    @TempDir
    Path directory;

    private CheckpointSigner signer;
    private AuditConfiguration configuration;

    @BeforeEach
    void setUp() throws Exception {
        signer = CheckpointSigner.fromFiles(
                directory.resolve("keys/private.pem"), directory.resolve("keys/public.b64"), "dev");
        configuration = AuditConfiguration.fromEnvironment(
                Map.of("AUDIT_LEDGER_ID", LEDGER_ID, "AUDIT_CHECKPOINT_INTERVAL", "1000"));
    }

    @Test
    void diskFullRollsBackLeavesLedgerIntactAndResumesAfterLimitIsLifted() throws Exception {
        JdbcAuditRepository repository = new JdbcAuditRepository(directory.resolve("audit.db"), LEDGER_ID);
        AppendEventService service = service(repository);
        for (int index = 0; index < 3; index++) {
            service.append(request(index), "writer");
        }
        repository.setMaxPageCount(pageCount(repository) + 5);

        int committed = 3;
        SQLException failure = null;
        for (int index = 3; index < 200 && failure == null; index++) {
            try {
                service.append(request(index), "writer");
                committed++;
            } catch (SQLException exception) {
                failure = exception;
            }
        }
        assertNotNull(failure, "page cap never reached");
        assertTrue(!(failure instanceof StorageBusyException));
        assertEquals(13, failure.getErrorCode() & 0xFF, "expected SQLITE_FULL");

        assertEquals(committed, eventCount(repository));
        assertIntact(repository, committed);

        repository.setMaxPageCount(0);
        service.append(request(999), "writer");
        assertIntact(repository, committed + 1);
    }

    @Test
    void slowIoSerializesWritersWithoutLosingOrReorderingEvents() throws Exception {
        JdbcAuditRepository real = new JdbcAuditRepository(directory.resolve("audit.db"), LEDGER_ID);
        long delayMillis = 50;
        AuditRepository slow = new AuditRepository() {
            @Override
            public <T> T writeTransaction(TransactionWork<T> work) throws SQLException {
                return real.writeTransaction(connection -> {
                    sleep(delayMillis);
                    return work.execute(connection);
                });
            }

            @Override
            public <T> T readSnapshot(TransactionWork<T> work) throws SQLException {
                return real.readSnapshot(work);
            }
        };
        AppendEventService service = service(slow);
        int writers = 4;
        int perWriter = 3;
        var executor = Executors.newFixedThreadPool(writers);
        long started = System.nanoTime();
        try {
            List<Callable<Void>> calls = new ArrayList<>();
            for (int writer = 0; writer < writers; writer++) {
                int id = writer;
                calls.add(() -> {
                    for (int index = 0; index < perWriter; index++) {
                        service.append(request(id * 100 + index), "writer-" + id);
                    }
                    return null;
                });
            }
            for (var future : executor.invokeAll(calls)) {
                future.get();
            }
        } finally {
            executor.shutdownNow();
        }
        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);

        assertIntact(real, writers * perWriter);
        // Lower bound implied by BEGIN IMMEDIATE serialisation; not a performance gate.
        assertTrue(elapsedMillis >= writers * perWriter * delayMillis * 9 / 10, "elapsed " + elapsedMillis);
    }

    @Test
    void busyWritersFailFastWithStorageBusyThenRecover() throws Exception {
        new JdbcAuditRepository(directory.resolve("audit.db"), LEDGER_ID);
        JdbcAuditRepository shortTimeout = new JdbcAuditRepository(directory.resolve("audit.db"), LEDGER_ID, 100);
        AppendEventService service = service(shortTimeout);
        var executor = Executors.newFixedThreadPool(6);
        try (var holder = DriverManager.getConnection("jdbc:sqlite:" + directory.resolve("audit.db"));
                var statement = holder.createStatement()) {
            statement.execute("BEGIN IMMEDIATE");
            List<Callable<Throwable>> calls = new ArrayList<>();
            for (int index = 0; index < 6; index++) {
                int id = index;
                calls.add(() -> {
                    try {
                        service.append(request(id), "writer");
                        return null;
                    } catch (SQLException exception) {
                        return exception;
                    }
                });
            }
            for (var future : executor.invokeAll(calls, 60, TimeUnit.SECONDS)) {
                try {
                    assertInstanceOf(StorageBusyException.class, future.get());
                } catch (ExecutionException exception) {
                    throw new AssertionError("writer threw", exception);
                }
            }
            statement.execute("ROLLBACK");
        } finally {
            executor.shutdownNow();
        }

        assertEquals(0, eventCount(shortTimeout));
        service.append(request(100), "writer");
        assertIntact(shortTimeout, 1);
    }

    private AppendEventService service(AuditRepository repository) {
        return new AppendEventService(repository, configuration, signer, Clock.systemUTC());
    }

    private static AppendEventRequest request(int index) {
        Map<String, Object> payload = new LinkedHashMap<>();
        for (int leaf = 0; leaf < 40; leaf++) {
            payload.put("k" + leaf, "x".repeat(200));
        }
        return new AppendEventRequest("T", "actor", "R", "r" + index, payload, null);
    }

    private void assertIntact(AuditRepository repository, int expectedRecords) throws SQLException {
        var report = new LedgerVerifier(repository, LEDGER_ID, signer.publicKeyBase64(), Clock.systemUTC())
                .verify();
        assertTrue(report.intact(), () -> "violations: " + report.violations());
        assertEquals(expectedRecords, report.checkedRecords());
        assertEquals(expectedRecords, report.headSeq());
    }

    private static int eventCount(AuditRepository repository) throws SQLException {
        return repository.readSnapshot(connection -> {
            try (var statement = connection.createStatement();
                    var result = statement.executeQuery("SELECT COUNT(*) FROM audit_events")) {
                result.next();
                return result.getInt(1);
            }
        });
    }

    private static long pageCount(AuditRepository repository) throws SQLException {
        return repository.readSnapshot(connection -> {
            try (var statement = connection.createStatement();
                    var result = statement.executeQuery("PRAGMA page_count")) {
                result.next();
                return result.getLong(1);
            }
        });
    }

    private static void sleep(long millis) throws SQLException {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new SQLException("interrupted", exception);
        }
    }
}
