package com.auditlog.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.verifier.BundleVerifier;
import com.auditlog.verify.LedgerVerifier;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Report consistency against real SQLite. Synthetic data and non-production test keys only. */
class AccountAccessReportServiceTests {

    private static final String LEDGER_ID = "report-ledger";
    private static final Instant DAY0 = Instant.parse("2026-01-01T00:00:00Z");
    private static final String FROM = "2026-01-01T00:00:00.000000Z";
    private static final String TO = "2026-01-02T00:00:00.000000Z";

    private static final class MutableClock extends Clock {
        private volatile Instant now = DAY0;

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    @TempDir
    Path directory;

    private final MutableClock clock = new MutableClock();
    private JdbcAuditRepository repository;
    private CheckpointSigner signer;
    private AuditConfiguration configuration;
    private AppendEventService appendService;
    private LedgerVerifier verifier;
    private Path databasePath;
    private int tick;

    @BeforeEach
    void setUp() throws Exception {
        databasePath = directory.resolve("audit.db");
        repository = new JdbcAuditRepository(databasePath, LEDGER_ID);
        signer = CheckpointSigner.fromFiles(
                directory.resolve("keys/private.pem"), directory.resolve("keys/public.b64"), "dev");
        Map<String, String> values = new HashMap<>();
        values.put("AUDIT_LEDGER_ID", LEDGER_ID);
        values.put("AUDIT_DB_PATH", databasePath.toString());
        values.put("AUDIT_EXPORT_DIR", directory.resolve("exports").toString());
        values.put("AUDIT_ARCHIVE_DIR", directory.resolve("archives").toString());
        values.put("AUDIT_RETENTION_DAYS", "30");
        configuration = AuditConfiguration.fromEnvironment(values);
        appendService = new AppendEventService(repository, configuration, signer, clock);
        verifier = new LedgerVerifier(repository, LEDGER_ID, signer.publicKeyBase64(), clock);
    }

    private AccountAccessReportService reporter(int cap, Consumer<AccountAccessReportService.Stage> hook) {
        ExportBundleService bundles = new ExportBundleService(repository, configuration, signer, appendService);
        return new AccountAccessReportService(
                repository, configuration, signer, appendService, bundles, verifier, cap, hook);
    }

    private AccountAccessReportService reporter() {
        return reporter(AccountAccessReportService.REPORT_RECORD_CAP, stage -> { });
    }

    private AppendedEvent access(String actor, String account, String category, String purpose,
            String outcome) throws Exception {
        clock.now = DAY0.plus(++tick, ChronoUnit.SECONDS);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("dataCategory", category);
        payload.put("accessType", "VIEW");
        payload.put("accessPurpose", purpose);
        payload.put("channel", "API");
        payload.put("outcome", outcome);
        if ("OTHER".equals(purpose)) {
            payload.put("justification", "synthetic justification");
        }
        if ("DENIED".equals(outcome)) {
            payload.put("denialReason", "synthetic denial");
        }
        return appendService.append(
                new AppendEventRequest("ACCOUNT_DATA_ACCESS", actor, "CLIENT_ACCOUNT", account, payload, null),
                "writer");
    }

    private long count(String sql) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery(sql)) {
            result.next();
            return result.getLong(1);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }

    @Test
    void requiresExactlyOneSubjectAndExplicitPeriod() {
        AccountAccessReportService service = reporter();
        assertThrows(IllegalArgumentException.class, () -> service.generate(null, null, FROM, TO, "aud"));
        assertThrows(IllegalArgumentException.class, () -> service.generate("a", "b", FROM, TO, "aud"));
        assertThrows(IllegalArgumentException.class, () -> service.generate("a", null, null, TO, "aud"));
        assertThrows(IllegalArgumentException.class, () -> service.generate("a", null, FROM, null, "aud"));
        assertThrows(IllegalArgumentException.class, () -> service.generate("a", null, TO, FROM, "aud"));
    }

    @Test
    void groupsCountsAndExceptionsWithSeparateHeads() throws Exception {
        access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        access("bob", "acct-1", "PROFILE", "OTHER", "GRANTED");
        AppendedEvent last = access("bob", "acct-1", "TAX_DOCUMENTS", "COMPLIANCE_REVIEW", "DENIED");
        access("carol", "acct-2", "BALANCES", "SERVICING", "GRANTED");
        clock.now = DAY0.plus(1, ChronoUnit.HOURS);

        Map<String, Object> report = reporter().generate("acct-1", null, FROM, TO, "auditor-1");

        assertEquals(true, report.get("trustworthy"));
        Map<String, Object> counts = map(report.get("counts"));
        assertEquals(4L, counts.get("matchedEvents"));
        assertEquals(0L, counts.get("unknownRedactedEvents"));
        assertEquals(1L, map(counts.get("byOutcome")).get("DENIED"));
        assertEquals(3L, map(counts.get("byOutcome")).get("GRANTED"));
        assertEquals(1L, map(counts.get("byAccessPurpose")).get("OTHER"));
        List<?> groups = (List<?>) report.get("groups");
        assertEquals(3, groups.size());
        assertEquals(2, ((List<?>) report.get("exceptions")).size());

        Map<String, Object> verified = map(report.get("verifiedDataHead"));
        Map<String, Object> post = map(report.get("postReportHead"));
        assertEquals(5L, verified.get("seq"));
        assertEquals(6L, post.get("seq"));
        assertFalse(verified.get("chainHash").equals(post.get("chainHash")));
        assertEquals(1, ((List<?>) report.get("exclusions")).stream()
                .filter(item -> item.toString().startsWith("UPSTREAM")).count());
        assertEquals(1, count("SELECT COUNT(*) FROM audit_events WHERE event_type='COMPLIANCE_REPORT_GENERATED'"));
        assertEquals(1, count("SELECT COUNT(*) FROM checkpoints         WHERE seq=6"));
                assertTrue(last.seq() < 6);
    }

    @Test
    void actorSubjectSelectsAcrossAccountsAndEvidenceVerifiesWithPinnedKey() throws Exception {
        access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        access("alice", "acct-2", "PROFILE", "SERVICING", "GRANTED");
        access("bob", "acct-2", "PROFILE", "SERVICING", "GRANTED");
        clock.now = DAY0.plus(1, ChronoUnit.HOURS);

        Map<String, Object> report = reporter().generate(null, "alice", FROM, TO, "auditor-1");

        assertEquals(2L, map(report.get("counts")).get("matchedEvents"));
        byte[] evidence = CanonicalJson.canonicalize(
                map(report.get("evidence")), CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE);
        BundleVerifier.Result result =
                BundleVerifier.verify(evidence, BundleVerifier.Options.pinned(signer.publicKeyBase64()));
        assertEquals(BundleVerifier.Status.VERIFIED, result.status());
        assertEquals("COMPLIANCE_REPORT", map(report.get("evidence")).get("purpose"));
    }

    @Test
    void redactedGroupingLeafIsUnknownRedactedNotGrantedOrDenied() throws Exception {
        AppendedEvent target = access("alice", "acct-1", "BALANCES", "SERVICING", "DENIED");
        access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        RedactionCleanupService cleanup = new RedactionCleanupService(repository, configuration, clock);
        new RedactionService(repository, configuration, appendService, cleanup)
                .redact(target.eventId(), List.of("/outcome"), "synthetic", "T-1", "admin");
        clock.now = DAY0.plus(1, ChronoUnit.HOURS);

        Map<String, Object> report = reporter().generate("acct-1", null, FROM, TO, "auditor-1");

        Map<String, Object> counts = map(report.get("counts"));
        assertEquals(2L, counts.get("matchedEvents"));
        assertEquals(1L, counts.get("unknownRedactedEvents"));
        Map<String, Object> byOutcome = map(counts.get("byOutcome"));
        assertEquals(1L, byOutcome.get(AccountAccessReportService.UNKNOWN_REDACTED));
        assertEquals(1L, byOutcome.get("GRANTED"));
        assertNull(byOutcome.get("DENIED"));
        assertEquals(1, ((List<?>) report.get("exceptions")).size());
    }

    @Test
    void integrityFailureIsLabeledNotTrustworthy() throws Exception {
        access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
                Statement statement = connection.createStatement()) {
            statement.execute("DROP TRIGGER IF EXISTS audit_events_archive_only_update");
            statement.execute("UPDATE audit_events SET chain_hash='" + "0".repeat(64) + "' WHERE seq=1");
        }
        clock.now = DAY0.plus(1, ChronoUnit.HOURS);

        Map<String, Object> report = reporter().generate("acct-1", null, FROM, TO, "auditor-1");

        assertEquals(false, report.get("trustworthy"));
        assertTrue(report.get("trustLabel").toString().startsWith("NOT TRUSTWORTHY"));
        Map<String, Object> integrity = map(report.get("integrity"));
        assertEquals(false, integrity.get("intact"));
        assertNotNull(integrity.get("firstViolation"));
    }

    @Test
    void capRejectsWithoutPartialResultOrMetaEvent() throws Exception {
        access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        clock.now = DAY0.plus(1, ChronoUnit.HOURS);
        long events = count("SELECT COUNT(*) FROM audit_events");
        long checkpoints = count("SELECT COUNT(*) FROM checkpoints");

        assertThrows(AccountAccessReportService.ReportLimitExceededException.class,
                () -> reporter(2, stage -> { }).generate("acct-1", null, FROM, TO, "auditor-1"));

        assertEquals(events, count("SELECT COUNT(*) FROM audit_events"));
        assertEquals(checkpoints, count("SELECT COUNT(*) FROM checkpoints"));
        assertEquals(10_000, AccountAccessReportService.REPORT_RECORD_CAP);
    }

    @Test
    void concurrentAppendWaitsForReportAndIsNotInTheSnapshot() throws Exception {
        access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        clock.now = DAY0.plus(1, ChronoUnit.HOURS);
        AtomicReference<Thread> appender = new AtomicReference<>();
        AtomicReference<AppendedEvent> appended = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        boolean[] blocked = new boolean[1];

        Map<String, Object> report = reporter(10, stage -> {
            if (stage != AccountAccessReportService.Stage.AFTER_VERIFY) {
                return;
            }
            Thread thread = new Thread(() -> {
                try {
                    appended.set(appendService.append(new AppendEventRequest(
                            "ACCOUNT_DATA_ACCESS", "alice", "CLIENT_ACCOUNT", "acct-1",
                            Map.of("dataCategory", "PROFILE", "accessType", "VIEW",
                                    "accessPurpose", "SERVICING", "channel", "API", "outcome", "GRANTED"),
                            null), "writer"));
                } catch (Exception | Error exception) {
                    failure.set(exception);
                }
            });
            appender.set(thread);
            thread.start();
            try {
                Thread.sleep(500);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
            blocked[0] = appended.get() == null;
        }).generate("acct-1", null, FROM, TO, "auditor-1");
        appender.get().join(20_000);

        assertNull(failure.get());
        assertTrue(blocked[0], "the concurrent append must wait for the report transaction");
        assertEquals(1L, map(report.get("counts")).get("matchedEvents"));
        long reportSeq = (Long) map(report.get("postReportHead")).get("seq");
        assertTrue(appended.get().seq() > reportSeq);
    }

    @Test
    void concurrentRedactionWaitsAndReportKeepsPreRedactionEvidence() throws Exception {
        AppendedEvent target = access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        clock.now = DAY0.plus(1, ChronoUnit.HOURS);
        RedactionCleanupService cleanup = new RedactionCleanupService(repository, configuration, clock);
        RedactionService redaction = new RedactionService(repository, configuration, appendService, cleanup);
        AtomicReference<Thread> redactor = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();

        Map<String, Object> report = reporter(10, stage -> {
            if (stage != AccountAccessReportService.Stage.AFTER_SELECT) {
                return;
            }
            Thread thread = new Thread(() -> {
                try {
                    redaction.redact(target.eventId(), List.of("/outcome"), "synthetic", "T-2", "admin");
                } catch (Exception | Error exception) {
                    failure.set(exception);
                }
            });
            redactor.set(thread);
            thread.start();
            try {
                Thread.sleep(300);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }).generate("acct-1", null, FROM, TO, "auditor-1");
        redactor.get().join(20_000);

        assertNull(failure.get());
        assertEquals(0L, map(report.get("counts")).get("unknownRedactedEvents"));
        assertEquals(1L, map(map(report.get("counts")).get("byOutcome")).get("GRANTED"));
        assertEquals(1, count("SELECT COUNT(*) FROM audit_events WHERE event_type='RECORD_REDACTED'"));
        assertTrue(verifier.verify().intact());
    }

    @Test
    void concurrentArchiveWaitsAndReportStillCoversRetainedLiveRecords() throws Exception {
        access("alice", "acct-1", "BALANCES", "SERVICING", "GRANTED");
        access("alice", "acct-1", "PROFILE", "SERVICING", "GRANTED");
        clock.now = DAY0.plus(100, ChronoUnit.DAYS);
        ArchiveService archiver = new ArchiveService(repository, configuration, signer, appendService, clock);
        AtomicReference<Thread> thread = new AtomicReference<>();
        AtomicReference<ArchiveService.ArchiveResult> archived = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();

        Map<String, Object> report = reporter(10, stage -> {
            if (stage != AccountAccessReportService.Stage.AFTER_VERIFY) {
                return;
            }
            Thread worker = new Thread(() -> {
                try {
                    archived.set(archiver.archive(false, "admin"));
                } catch (Exception | Error exception) {
                    failure.set(exception);
                }
            });
            thread.set(worker);
            worker.start();
            try {
                Thread.sleep(300);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }).generate("acct-1", null, FROM, TO, "auditor-1");
        thread.get().join(30_000);

        assertNull(failure.get());
        assertEquals(2L, map(report.get("counts")).get("matchedEvents"));
        assertTrue(archived.get().count() >= 2);
        assertTrue(verifier.verify().intact());
    }
}
