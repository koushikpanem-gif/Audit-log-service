package com.auditlog.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.service.ArchiveService.ArchiveResult;
import com.auditlog.service.ArchiveService.Stage;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.verifier.BundleVerifier;
import com.auditlog.verify.LedgerVerifier;
import com.auditlog.verify.VerificationReport;
import com.auditlog.web.ApiException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Real SQLite and real files; no mocks. Markers are synthetic. */
class ArchiveServiceTests {

    private static final String LEDGER_ID = "archive-ledger";
    private static final String MARKER = "SYNTHETIC-ARCHIVE-MARKER-";
    private static final Instant DAY0 = Instant.parse("2026-01-01T00:00:00.000000Z");
    private static final ObjectMapper JSON = new ObjectMapper();

    /** Models a process crash: an Error is never handled by the service. */
    private static final class CrashError extends Error {
        private static final long serialVersionUID = 1L;
    }

    private static final class MutableClock extends Clock {
        private volatile Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

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

    private final MutableClock clock = new MutableClock(DAY0);
    private JdbcAuditRepository repository;
    private CheckpointSigner signer;
    private AuditConfiguration configuration;
    private AppendEventService appendService;
    private Path databasePath;
    private Path archiveDirectory;

    @BeforeEach
    void setUp() throws Exception {
        databasePath = directory.resolve("audit.db");
        archiveDirectory = directory.resolve("archives");
        repository = new JdbcAuditRepository(databasePath, LEDGER_ID);
        signer = CheckpointSigner.fromFiles(
                directory.resolve("keys/private.pem"), directory.resolve("keys/public.b64"), "dev");
        configure(Map.of());
    }

    private void configure(Map<String, String> overrides) {
        Map<String, String> values = new HashMap<>();
        values.put("AUDIT_LEDGER_ID", LEDGER_ID);
        values.put("AUDIT_DB_PATH", databasePath.toString());
        values.put("AUDIT_EXPORT_DIR", directory.resolve("exports").toString());
        values.put("AUDIT_ARCHIVE_DIR", archiveDirectory.toString());
        values.put("AUDIT_RETENTION_DAYS", "30");
        values.put("AUDIT_CLEANUP_BUSY_TIMEOUT_MS", "100");
        values.putAll(overrides);
        configuration = AuditConfiguration.fromEnvironment(values);
        appendService = new AppendEventService(repository, configuration, signer, clock);
    }

    private ArchiveService service() {
        return new ArchiveService(repository, configuration, signer, appendService, clock);
    }

    private ArchiveService service(Consumer<Stage> hook) {
        return new ArchiveService(repository, configuration, signer, appendService, clock, hook);
    }

    private ArchiveAuditService auditor() {
        return new ArchiveAuditService(repository, configuration, signer, clock);
    }

    private String appendAt(Instant at, String secret) throws Exception {
        clock.now = at;
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("secret", secret);
        payload.put("amount", 12);
        return appendService.append(
                new AppendEventRequest("TRADE", "actor-1", "ACCOUNT", "acct-1", payload, null), "writer")
                .eventId();
    }

    private void seedOld(int count) throws Exception {
        for (int index = 1; index <= count; index++) {
            appendAt(DAY0.plus(index, ChronoUnit.SECONDS), MARKER + index);
        }
    }

    private void afterRetention() {
        clock.now = DAY0.plus(100, ChronoUnit.DAYS);
    }

    private String scalar(String sql) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }

    private VerificationReport verify() throws Exception {
        return new LedgerVerifier(repository, LEDGER_ID, signer.publicKeyBase64(), clock).verify();
    }

    private String hashes() throws Exception {
        return scalar("SELECT group_concat(seq || content_hash || prev_hash || chain_hash || recorded_at, ',') "
                + "FROM (SELECT * FROM audit_events WHERE seq <= 5 ORDER BY seq)");
    }

    private List<String> archiveFiles() throws Exception {
        if (!Files.isDirectory(archiveDirectory)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(archiveDirectory)) {
            return files.map(path -> path.getFileName().toString()).sorted().toList();
        }
    }

    private Map<String, Object> onlyArchive(Map<String, Object> audit) {
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> archives = (List<Map<String, Object>>) audit.get("archives");
        assertEquals(1, archives.size());
        return archives.get(0);
    }

    private static List<String> statuses(Map<String, Object> audit) {
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> archives = (List<Map<String, Object>>) audit.get("archives");
        List<String> result = new ArrayList<>();
        for (Map<String, Object> archive : archives) {
            result.add((String) archive.get("status"));
        }
        return result;
    }

    @Test
    void dryRunWritesNoFileAndChangesNothing() throws Exception {
        seedOld(3);
        afterRetention();
        String before = scalar("SELECT group_concat(actor_id || payload_commitments) FROM audit_events");
        long events = Long.parseLong(scalar("SELECT COUNT(*) FROM audit_events"));

        ArchiveResult result = service().archive(true, "admin");

        assertTrue(result.dryRun());
        assertEquals("DRY_RUN", result.status());
        assertEquals(3, result.count());
        assertEquals(1L, result.fromSeq());
        assertEquals(3L, result.toSeq());
        assertTrue(result.estimatedBytes() > 0);
        assertNull(result.archiveFile());
        assertEquals(List.of(), archiveFiles());
        assertEquals("0", scalar("SELECT COUNT(*) FROM archive_jobs"));
        assertEquals(events, Long.parseLong(scalar("SELECT COUNT(*) FROM audit_events")));
        assertEquals(before, scalar("SELECT group_concat(actor_id || payload_commitments) FROM audit_events"));
    }

    @Test
    void archivesExpiredPrefixKeepingHashesAndChainIntact() throws Exception {
        seedOld(3);
        appendAt(DAY0.plus(95, ChronoUnit.DAYS), MARKER + "recent-4");
        appendAt(DAY0.plus(96, ChronoUnit.DAYS), MARKER + "recent-5");
        afterRetention();
        String hashesBefore = hashes();

        ArchiveResult result = service().archive(false, "admin");

        assertEquals("ARCHIVED", result.status());
        assertEquals(3, result.count());
        assertEquals(3L, result.toSeq());
        assertEquals(6L, result.archiveEventSeq());
        assertEquals(hashesBefore, hashes());
        assertEquals("2026-03-12T00:00:00.000000Z", result.cutoff());
        assertNull(scalar("SELECT actor_id FROM audit_events WHERE seq = 1"));
        assertNull(scalar("SELECT payload_commitments FROM audit_events WHERE seq = 3"));
        assertEquals("0", scalar("SELECT COUNT(*) FROM payload_leaves WHERE seq <= 3"));
        assertEquals("1", scalar("SELECT archived FROM audit_events WHERE seq = 2"));
        assertEquals("TRADE", scalar("SELECT event_type FROM audit_events WHERE seq = 4"));
        assertEquals("2", scalar("SELECT COUNT(*) FROM payload_leaves WHERE seq = 4"));
        assertEquals("RECORDS_ARCHIVED", scalar("SELECT event_type FROM audit_events WHERE seq = 6"));
        assertEquals("COMMITTED", scalar("SELECT status FROM archive_jobs"));

        VerificationReport report = verify();
        assertTrue(report.intact(), report.violations().toString());
        assertEquals(3, report.archivedRecords());

        byte[] file = Files.readAllBytes(archiveDirectory.resolve(result.archiveFile()));
        assertEquals(ArchiveService.sha256Hex(file), result.archiveSha256());
        BundleVerifier.Result bundle = BundleVerifier.verify(
                file, BundleVerifier.Options.pinned(signer.publicKeyBase64()));
        assertEquals(BundleVerifier.Status.VERIFIED, bundle.status(), bundle.diagnostics().toString());
        assertTrue(new String(file, java.nio.charset.StandardCharsets.UTF_8).contains(MARKER + "1"),
                "the archive file is a plaintext copy");
        Map<String, Object> audit = auditor().audit();
        assertEquals(true, audit.get("intact"), audit.toString());
        assertEquals("OK", onlyArchive(audit).get("status"));
        assertEquals(List.of(result.archiveFile()), archiveFiles());
    }

    @Test
    void cutoffIsStrictAndPolicyRoundsFractionalDaysUp() throws Exception {
        Instant now = DAY0.plus(100, ChronoUnit.DAYS);
        Instant cutoff = now.minus(30, ChronoUnit.DAYS);
        appendAt(cutoff.minus(1, ChronoUnit.MICROS), MARKER + "before");
        appendAt(cutoff, MARKER + "at");
        appendAt(cutoff.plusSeconds(1), MARKER + "after");
        clock.now = now;

        ArchiveResult result = service().archive(false, "admin");

        assertEquals(1, result.count());
        assertEquals(1L, result.toSeq());
        assertEquals("1", scalar("SELECT archived FROM audit_events WHERE seq = 1"));
        assertEquals("0", scalar("SELECT archived FROM audit_events WHERE seq = 2"));
        assertEquals(30L, result.effectiveRetentionDays());

        configure(Map.of("AUDIT_RETENTION_DAYS", "0.5"));
        assertEquals(1L, service().effectiveRetentionDays());
        configure(Map.of("AUDIT_RETENTION_DAYS", "30.2"));
        assertEquals(31L, service().effectiveRetentionDays());
    }

    @Test
    void nothingEligibleReturnsNoJobAndNoFile() throws Exception {
        seedOld(2);
        clock.now = DAY0.plus(5, ChronoUnit.DAYS);

        ArchiveResult result = service().archive(false, "admin");

        assertEquals("NOTHING_TO_ARCHIVE", result.status());
        assertEquals("0", scalar("SELECT COUNT(*) FROM archive_jobs"));
        assertEquals(List.of(), archiveFiles());
    }

    @Test
    void batchesAreBoundedByRecordCount() throws Exception {
        configure(Map.of("AUDIT_ARCHIVE_MAX_RECORDS", "2"));
        seedOld(5);
        afterRetention();

        ArchiveResult first = service().archive(false, "admin");
        assertEquals(2, first.count());
        assertTrue(first.moreEligible());
        assertTrue(verify().intact());
        ArchiveResult second = service().archive(false, "admin");
        assertEquals(3L, second.fromSeq());
        assertEquals(4L, second.toSeq());
        ArchiveResult third = service().archive(false, "admin");
        assertEquals(1, third.count());
        assertFalse(third.moreEligible());

        VerificationReport report = verify();
        assertTrue(report.intact(), report.violations().toString());
        assertEquals(5, report.archivedRecords());
        Map<String, Object> audit = auditor().audit();
        assertEquals(List.of("OK", "OK", "OK"), statuses(audit));
    }

    @Test
    void batchesAreBoundedByBytes() throws Exception {
        configure(Map.of("AUDIT_ARCHIVE_MAX_BYTES", "65536"));
        for (int index = 1; index <= 5; index++) {
            appendAt(DAY0.plus(index, ChronoUnit.SECONDS), "x".repeat(20_000));
        }
        afterRetention();

        ArchiveResult result = service().archive(true, "admin");

        assertEquals(2, result.count());
        assertTrue(result.moreEligible());
        assertTrue(result.estimatedBytes() <= 65536);
        ArchiveResult real = service().archive(false, "admin");
        assertEquals(2, real.count());
        assertTrue(Files.size(archiveDirectory.resolve(real.archiveFile())) <= 65536);
    }

    @ParameterizedTest
    @EnumSource(value = Stage.class, names = {
        "AFTER_JOB_RECORDED", "AFTER_TEMP_FORCED", "AFTER_PUBLISH", "BEFORE_COMMIT"})
    void crashBeforeCommitKeepsPlaintextAndRestartReconcilesFiles(Stage crashStage) throws Exception {
        seedOld(3);
        afterRetention();
        String hashesBefore = hashes();

        assertThrows(CrashError.class, () -> service(stage -> {
            if (stage == crashStage) {
                throw new CrashError();
            }
        }).archive(false, "admin"));

        assertEquals(MARKER + "1", scalar("SELECT value FROM payload_leaves WHERE seq = 1 AND pointer = '/secret'")
                .replace("\"", ""));
        assertEquals("TRADE", scalar("SELECT event_type FROM audit_events WHERE seq = 1"));
        assertEquals("PREPARING", scalar("SELECT status FROM archive_jobs"));
        assertEquals(hashesBefore, hashes());
        assertTrue(verify().intact());
        ApiExceptionCheck.assertConflict(() -> service().archive(false, "admin"), "ARCHIVE_JOB_INTERRUPTED");

        Map<String, Object> status = service().reconcile();

        assertEquals(0L, status.get("openJobs"));
        assertEquals("FAILED", scalar("SELECT status FROM archive_jobs"));
        assertEquals("DONE", scalar("SELECT cleanup_state FROM archive_jobs"));
        assertEquals(List.of(), archiveFiles());
        ArchiveResult retry = service().archive(false, "admin");
        assertEquals("ARCHIVED", retry.status());
        assertEquals(3, retry.count());
        assertTrue(verify().intact());
        assertEquals("OK", onlyArchive(auditor().audit()).get("status"));
    }

    @Test
    void crashAfterCommitLeavesCommittedArchiveAndNothingToClean() throws Exception {
        seedOld(3);
        afterRetention();

        assertThrows(CrashError.class, () -> service(stage -> {
            if (stage == Stage.AFTER_COMMIT) {
                throw new CrashError();
            }
        }).archive(false, "admin"));

        assertEquals("COMMITTED", scalar("SELECT status FROM archive_jobs"));
        Map<String, Object> status = service().reconcile();
        assertEquals(0L, status.get("openJobs"));
        assertEquals(1, archiveFiles().size());
        assertTrue(verify().intact());
        assertEquals("OK", onlyArchive(auditor().audit()).get("status"));
        assertEquals("NOTHING_TO_ARCHIVE", service().archive(false, "admin").status());
    }

    @ParameterizedTest
    @EnumSource(value = Stage.class, names = {"AFTER_JOB_RECORDED", "AFTER_TEMP_FORCED", "AFTER_PUBLISH", "BEFORE_COMMIT"})
    void publicationFailureRetainsLivePlaintextAndCleansFiles(Stage failingStage) throws Exception {
        seedOld(3);
        afterRetention();
        String hashesBefore = hashes();

        assertThrows(IllegalStateException.class, () -> service(stage -> {
            if (stage == failingStage) {
                throw new IllegalStateException("injected failure");
            }
        }).archive(false, "admin"));

        assertEquals("TRADE", scalar("SELECT event_type FROM audit_events WHERE seq = 1"));
        assertEquals("2", scalar("SELECT COUNT(*) FROM payload_leaves WHERE seq = 1"));
        assertEquals("0", scalar("SELECT archived FROM audit_events WHERE seq = 1"));
        assertEquals(hashesBefore, hashes());
        assertEquals("FAILED", scalar("SELECT status FROM archive_jobs"));
        assertEquals("DONE", scalar("SELECT cleanup_state FROM archive_jobs"));
        assertEquals(List.of(), archiveFiles());
        assertEquals("0", scalar("SELECT COUNT(*) FROM audit_events WHERE event_type = 'RECORDS_ARCHIVED'"));
        assertTrue(verify().intact());
        assertEquals("ARCHIVED", service().archive(false, "admin").status());
    }

    @Test
    void unusableArchiveDirectoryFailsWithoutClearingPlaintext() throws Exception {
        Path blocker = directory.resolve("not-a-directory");
        Files.writeString(blocker, "file");
        configure(Map.of("AUDIT_ARCHIVE_DIR", blocker.toString()));
        seedOld(2);
        afterRetention();

        assertThrows(RuntimeException.class, () -> service().archive(false, "admin"));

        assertEquals("TRADE", scalar("SELECT event_type FROM audit_events WHERE seq = 1"));
        assertEquals("FAILED", scalar("SELECT status FROM archive_jobs"));
        assertTrue(verify().intact());
    }

    @Test
    void repeatedArchiveCoversEarlierAuthorizationEvents() throws Exception {
        seedOld(5);
        afterRetention();
        assertEquals(5, service().archive(false, "admin").count());
        assertEquals(6L, Long.parseLong(scalar("SELECT MAX(seq) FROM audit_events")));

        clock.now = DAY0.plus(200, ChronoUnit.DAYS);
        appendAt(clock.now, MARKER + "late");
        clock.now = DAY0.plus(300, ChronoUnit.DAYS);
        ArchiveResult second = service().archive(false, "auditor-admin");

        assertEquals(6L, second.fromSeq());
        assertEquals(7L, second.toSeq());
        assertEquals("1", scalar("SELECT archived FROM audit_events WHERE seq = 6"));
        assertNull(scalar("SELECT event_type FROM audit_events WHERE seq = 6"));
        VerificationReport report = verify();
        assertTrue(report.intact(), report.violations().toString());
        assertEquals(7, report.archivedRecords());
        Map<String, Object> audit = auditor().audit();
        assertEquals(List.of("OK", "OK"), statuses(audit));
        assertEquals(true, audit.get("intact"));
    }

    @Test
    void redactedValuesAreNotDisclosedAndArchivedTargetsCannotBeRedacted() throws Exception {
        String eventId = appendAt(DAY0.plus(1, ChronoUnit.SECONDS), MARKER + "redact-me");
        appendAt(DAY0.plus(2, ChronoUnit.SECONDS), MARKER + "keep");
        RedactionCleanupService cleanup = new RedactionCleanupService(repository, configuration, clock);
        RedactionService redaction = new RedactionService(repository, configuration, appendService, cleanup);
        clock.now = DAY0.plus(3, ChronoUnit.SECONDS);
        redaction.redact(eventId, List.of("/secret"), "erasure", "T-1", "admin");
        afterRetention();

        ArchiveResult result = service().archive(false, "admin");

        assertEquals(3, result.count());
        String file = Files.readString(archiveDirectory.resolve(result.archiveFile()));
        assertFalse(file.contains(MARKER + "redact-me"));
        assertTrue(file.contains(MARKER + "keep"));
        JsonNode first = JSON.readTree(file).get("records").get(0);
        assertFalse(first.get("disclosedLeaves").has("/secret"));
        assertTrue(first.get("disclosedLeaves").has("/amount"));
        assertTrue(verify().intact());
        ApiException conflict = assertThrows(ApiException.class, () -> redaction.redact(
                eventId, List.of("/amount"), "late", "T-2", "admin"));
        assertEquals(409, conflict.status());
        assertEquals("OK", onlyArchive(auditor().audit()).get("status"));
    }

    @Test
    void missingArchiveIsReportedDistinctlyFromChainBreak() throws Exception {
        seedOld(3);
        afterRetention();
        ArchiveResult result = service().archive(false, "admin");
        Files.delete(archiveDirectory.resolve(result.archiveFile()));

        Map<String, Object> audit = auditor().audit();

        assertEquals(false, audit.get("intact"));
        assertEquals(1L, audit.get("missingArchiveCount"));
        assertEquals("ARCHIVE_FILE_MISSING", onlyArchive(audit).get("status"));
        VerificationReport report = verify();
        assertTrue(report.intact(), "a missing archive file is not a chain break");
    }

    @Test
    void tamperedArchiveFileIsDetected() throws Exception {
        seedOld(3);
        afterRetention();
        ArchiveResult result = service().archive(false, "admin");
        Path file = archiveDirectory.resolve(result.archiveFile());
        String text = Files.readString(file);
        Files.writeString(file, text.replace(MARKER + "2", MARKER + "9"));

        assertEquals("DIGEST_MISMATCH", onlyArchive(auditor().audit()).get("status"));
    }

    @Test
    void truncatedArchiveFileIsDetected() throws Exception {
        seedOld(3);
        afterRetention();
        ArchiveResult result = service().archive(false, "admin");
        Path file = archiveDirectory.resolve(result.archiveFile());
        byte[] original = Files.readAllBytes(file);
        Files.write(file, java.util.Arrays.copyOf(original, original.length - 3));

        String status = (String) onlyArchive(auditor().audit()).get("status");
        assertTrue(status.equals("DIGEST_MISMATCH") || status.equals("BUNDLE_INVALID"), status);
    }

    @Test
    void cleanupNeverDeletesUnprovenOrUnrelatedFiles() throws Exception {
        seedOld(3);
        afterRetention();
        ArchiveResult result = service().archive(false, "admin");
        Files.createDirectories(archiveDirectory);
        Path unrelated = archiveDirectory.resolve("notes.txt");
        Files.writeString(unrelated, "keep");
        Path orphan = archiveDirectory.resolve("archive-" + UUID.randomUUID() + ".json");
        Files.writeString(orphan, "{}");
        Path orphanTemp = archiveDirectory.resolve(".archive-" + UUID.randomUUID() + ".tmp");
        Files.writeString(orphanTemp, "partial");

        Map<String, Object> status = service().reconcile();

        assertTrue(Files.exists(unrelated));
        assertTrue(Files.exists(orphan));
        assertTrue(Files.exists(orphanTemp));
        assertTrue(Files.exists(archiveDirectory.resolve(result.archiveFile())));
        @SuppressWarnings("unchecked")
        List<String> orphans = (List<String>) status.get("orphanFiles");
        assertEquals(2, orphans.size());
        assertEquals(1L, status.get("unrecognizedFileCount"));
    }

    @Test
    void failedJobFileSharedWithCommittedArchiveIsNotDeleted() throws Exception {
        seedOld(3);
        afterRetention();
        ArchiveResult result = service().archive(false, "admin");
        String bundleId = result.bundleId();
        // Force an inconsistent FAILED/PENDING job whose pattern names would match a real file.
        String failedId = UUID.randomUUID().toString();
        execute("INSERT INTO archive_jobs(bundle_id, status, temp_name, final_name, requested_by, "
                + "created_at, updated_at, failure_code, cleanup_state) VALUES ('" + failedId
                + "', 'FAILED', '.archive-" + failedId + ".tmp', 'archive-" + failedId
                + ".json', 'admin', 'x', 'x', 'INTERRUPTED', 'PENDING')");
        Path ownFile = archiveDirectory.resolve("archive-" + failedId + ".json");
        Files.writeString(ownFile, "failed-attempt");
        long liveSeq = appendService.append(
                new AppendEventRequest("TRADE", "a", "ACCOUNT", "r", Map.of("k", "v"), null), "writer").seq();
        execute("INSERT INTO payload_leaves(seq, pointer, salt, value) VALUES (" + liveSeq
                + ", '/archiveFile', '" + "00".repeat(32) + "', '\"archive-" + failedId + ".json\"')");

        Map<String, Object> status = service().reconcile();

        assertTrue(Files.exists(ownFile), "a file referenced by a ledger leaf must survive");
        assertEquals("BLOCKED", scalar("SELECT cleanup_state FROM archive_jobs WHERE bundle_id = '"
                + failedId + "'"));
        assertNotNull(status);
        assertTrue(Files.exists(archiveDirectory.resolve(result.archiveFile())));
        assertEquals(bundleId, scalar("SELECT bundle_id FROM archive_jobs WHERE status = 'COMMITTED'"));
    }

    @Test
    void archiveJobTriggersGuardIdentityAndTerminalStates() throws Exception {
        seedOld(2);
        afterRetention();
        service().archive(false, "admin");

        assertThrows(SQLException.class, () -> execute("DELETE FROM archive_jobs"));
        assertThrows(SQLException.class, () -> execute("UPDATE archive_jobs SET status = 'FAILED'"));
        assertThrows(SQLException.class, () -> execute("UPDATE archive_jobs SET requested_by = 'x'"));
        assertThrows(SQLException.class, () -> execute("UPDATE archive_jobs SET archive_sha256 = 'x'"));
    }

    @Test
    void concurrentArchiveIsRejectedWhileOneRuns() throws Exception {
        seedOld(2);
        afterRetention();
        java.util.concurrent.CountDownLatch entered = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        ArchiveService blocking = service(stage -> {
            if (stage == Stage.AFTER_JOB_RECORDED) {
                entered.countDown();
                try {
                    release.await();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                }
            }
        });
        Thread worker = new Thread(() -> {
            try {
                blocking.archive(false, "admin");
            } catch (SQLException exception) {
                throw new IllegalStateException(exception);
            }
        });
        worker.start();
        assertTrue(entered.await(10, java.util.concurrent.TimeUnit.SECONDS));

        ApiExceptionCheck.assertConflict(() -> blocking.archive(false, "admin"), "ARCHIVE_IN_PROGRESS");

        release.countDown();
        worker.join(30_000);
        assertEquals("COMMITTED", scalar("SELECT status FROM archive_jobs"));
    }

    private void execute(String sql) throws SQLException {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
                Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute(sql);
        }
    }

    /** Small helper asserting an ArchiveException CONFLICT with a code. */
    private static final class ApiExceptionCheck {
        interface Action {
            void run() throws Exception;
        }

        static void assertConflict(Action action, String code) {
            ArchiveService.ArchiveException exception =
                    assertThrows(ArchiveService.ArchiveException.class, action::run);
            assertEquals(ArchiveService.Kind.CONFLICT, exception.kind());
            assertEquals(code, exception.code());
        }
    }
}
