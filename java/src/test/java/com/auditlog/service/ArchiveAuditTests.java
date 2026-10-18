package com.auditlog.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.service.ArchiveService.ArchiveResult;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.verify.LedgerVerifier;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Archive evidence audit failure modes against real SQLite and real files. Test keys only. */
class ArchiveAuditTests {

    private static final String LEDGER_ID = "archive-audit-ledger";
    private static final Instant DAY0 = Instant.parse("2026-01-01T00:00:00.000000Z");

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
    private Path databasePath;
    private Path archiveDirectory;

    @BeforeEach
    void setUp() throws Exception {
        databasePath = directory.resolve("audit.db");
        archiveDirectory = directory.resolve("archives");
        repository = new JdbcAuditRepository(databasePath, LEDGER_ID);
        signer = CheckpointSigner.fromFiles(
                directory.resolve("keys/private.pem"), directory.resolve("keys/public.b64"), "dev");
        Map<String, String> values = new HashMap<>();
        values.put("AUDIT_LEDGER_ID", LEDGER_ID);
        values.put("AUDIT_DB_PATH", databasePath.toString());
        values.put("AUDIT_EXPORT_DIR", directory.resolve("exports").toString());
        values.put("AUDIT_ARCHIVE_DIR", archiveDirectory.toString());
        values.put("AUDIT_RETENTION_DAYS", "30");
        configuration = AuditConfiguration.fromEnvironment(values);
        appendService = new AppendEventService(repository, configuration, signer, clock);
    }

    private ArchiveService archiver() {
        return new ArchiveService(repository, configuration, signer, appendService, clock);
    }

    private ArchiveAuditService auditor() {
        return new ArchiveAuditService(repository, configuration, signer, clock);
    }

    private void append(Instant at, String secret) throws Exception {
        clock.now = at;
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("secret", secret);
        appendService.append(new AppendEventRequest("TRADE", "actor-1", "ACCOUNT", "acct-1", payload, null),
                "writer");
    }

    /** Archives {@code count} old records, then returns the result. */
    private ArchiveResult archiveOld(int count, long offsetDays) throws Exception {
        for (int index = 1; index <= count; index++) {
            append(DAY0.plus(offsetDays, ChronoUnit.DAYS).plus(index, ChronoUnit.SECONDS), "synthetic-" + index);
        }
        clock.now = DAY0.plus(offsetDays + 100, ChronoUnit.DAYS);
        return archiver().archive(false, "admin");
    }

    private void tamper(String... statements) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
                Statement statement = connection.createStatement()) {
            for (String sql : statements) {
                statement.execute(sql);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> statuses(Map<String, Object> audit) {
        List<String> result = new ArrayList<>();
        for (Map<String, Object> archive : (List<Map<String, Object>>) audit.get("archives")) {
            result.add((String) archive.get("status"));
        }
        return result;
    }

    @Test
    void intactArchivesReportCompleteCoverage() throws Exception {
        archiveOld(3, 0);
        archiveOld(2, 200);

        Map<String, Object> audit = auditor().audit();

        assertEquals(true, audit.get("intact"), audit.toString());
        assertEquals(List.of("OK", "OK"), statuses(audit));
        @SuppressWarnings("unchecked")
        Map<String, Object> coverage = (Map<String, Object>) audit.get("coverage");
        assertEquals(true, coverage.get("complete"));
        assertEquals(coverage.get("archivedRecordsInLedger"), coverage.get("recordsCoveredByArchives"));
    }

    @Test
    void archiveWhoseAuthorizationEventWasArchivedStillAuditsAndMissingFirstFileIsLocalized() throws Exception {
        ArchiveResult first = archiveOld(3, 0);
        archiveOld(2, 200);
        assertEquals("1", scalar("SELECT archived FROM audit_events WHERE seq = " + (first.toSeq() + 1)));
        Files.delete(archiveDirectory.resolve(first.archiveFile()));

        Map<String, Object> audit = auditor().audit();

        assertEquals(List.of("ARCHIVE_FILE_MISSING", "OK"), statuses(audit));
        assertEquals(1L, audit.get("unavailableArchiveCount"));
        assertEquals(false, audit.get("intact"));
        assertTrue(new LedgerVerifier(repository, LEDGER_ID, signer.publicKeyBase64(), clock).verify().intact());
    }

    @Test
    void substitutedArchiveFileIsRejectedByDigest() throws Exception {
        ArchiveResult first = archiveOld(3, 0);
        ArchiveResult second = archiveOld(2, 200);
        Files.copy(archiveDirectory.resolve(second.archiveFile()), archiveDirectory.resolve(first.archiveFile()),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        assertEquals(List.of("DIGEST_MISMATCH", "OK"), statuses(auditor().audit()));
    }

    @Test
    void corruptAndOversizedFilesAreRejected() throws Exception {
        ArchiveResult result = archiveOld(3, 0);
        Path file = archiveDirectory.resolve(result.archiveFile());
        byte[] original = Files.readAllBytes(file);
        ArchiveAuditService small = new ArchiveAuditService(repository, LEDGER_ID, archiveDirectory,
                10, 10, signer.publicKeyBase64(), clock);
        assertEquals(List.of("DIGEST_MISMATCH"), statuses(small.audit()));

        Files.write(file, "not json".getBytes(StandardCharsets.UTF_8));
        assertEquals(List.of("DIGEST_MISMATCH"), statuses(auditor().audit()));
        Files.write(file, original);
        assertEquals(List.of("OK"), statuses(auditor().audit()));
    }

    @Test
    void wrongPinnedKeyFailsSignatureCheck() throws Exception {
        archiveOld(3, 0);
        CheckpointSigner other = CheckpointSigner.fromFiles(
                directory.resolve("other/private.pem"), directory.resolve("other/public.b64"), "dev");
        ArchiveAuditService wrong = new ArchiveAuditService(repository, configuration, other, clock);

        Map<String, Object> audit = wrong.audit();

        assertEquals(List.of("BUNDLE_INVALID"), statuses(audit));
        assertEquals(false, audit.get("intact"));
    }

    @Test
    void wrongLedgerBindingIsRejected() throws Exception {
        archiveOld(3, 0);
        ArchiveAuditService other = new ArchiveAuditService(repository, "some-other-ledger", archiveDirectory,
                configuration.archiveMaxBytes(), configuration.archiveMaxRecords(),
                signer.publicKeyBase64(), clock);

        assertEquals(List.of("METADATA_MISMATCH"), statuses(other.audit()));
    }

    @Test
    void changedSkeletonEventIdTimeOrVersionIsDetected() throws Exception {
        archiveOld(3, 0);
        String dropGuard = "DROP TRIGGER audit_events_archive_only_update";
        tamper(dropGuard, "UPDATE audit_events SET event_id = 'forged-id' WHERE seq = 2");
        assertEquals(List.of("SKELETON_MISMATCH"), statuses(auditor().audit()));
    }

    @Test
    void changedSkeletonTimestampIsDetected() throws Exception {
        archiveOld(3, 0);
        tamper("DROP TRIGGER audit_events_archive_only_update",
                "UPDATE audit_events SET recorded_at = '2026-01-01T00:00:09.000000Z' WHERE seq = 2");
        assertEquals(List.of("SKELETON_MISMATCH"), statuses(auditor().audit()));
    }

    @Test
    void changedSkeletonHashVersionIsDetected() throws Exception {
        archiveOld(3, 0);
        tamper("DROP TRIGGER audit_events_archive_only_update",
                "UPDATE audit_events SET hash_version = 2 WHERE seq = 2");
        assertEquals(List.of("SKELETON_MISMATCH"), statuses(auditor().audit()));
    }

    @Test
    void archivedRowWithoutArchiveEvidenceBreaksCoverage() throws Exception {
        archiveOld(3, 0);
        tamper("UPDATE audit_events SET archived = 1, archived_at = '2026-05-01T00:00:00.000000Z', "
                + "event_type = NULL, actor_id = NULL, resource_type = NULL, resource_id = NULL, "
                + "occurred_at = NULL, source = NULL, payload_commitments = NULL "
                + "WHERE seq = (SELECT MAX(seq) FROM audit_events)");

        Map<String, Object> audit = auditor().audit();

        assertEquals(List.of("OK"), statuses(audit));
        assertEquals(false, audit.get("intact"));
        @SuppressWarnings("unchecked")
        Map<String, Object> coverage = (Map<String, Object>) audit.get("coverage");
        assertEquals(false, coverage.get("complete"));
    }

    @Test
    void directoryInPlaceOfArchiveFileIsNotFollowed() throws Exception {
        ArchiveResult result = archiveOld(3, 0);
        Path file = archiveDirectory.resolve(result.archiveFile());
        Files.delete(file);
        Files.createDirectory(file);

        assertEquals(List.of("FILE_NAME_UNSAFE"), statuses(auditor().audit()));
    }

    @Test
    void cliExitCodesDistinguishIntactFailedAndUsage() throws Exception {
        ArchiveResult result = archiveOld(3, 0);
        Path keyFile = directory.resolve("pinned.b64");
        Files.writeString(keyFile, signer.publicKeyBase64());
        String[] base = {"--db", databasePath.toString(), "--ledger-id", LEDGER_ID,
                "--archive-dir", archiveDirectory.toString(), "--pinned-key-file", keyFile.toString()};

        assertEquals(0, runCli(base));

        CheckpointSigner other = CheckpointSigner.fromFiles(
                directory.resolve("other/private.pem"), directory.resolve("other/public.b64"), "dev");
        assertEquals(1, runCli("--db", databasePath.toString(), "--ledger-id", LEDGER_ID,
                "--archive-dir", archiveDirectory.toString(), "--pinned-key", other.publicKeyBase64()));

        Files.delete(archiveDirectory.resolve(result.archiveFile()));
        assertEquals(1, runCli(base));

        assertEquals(2, runCli("--db", databasePath.toString()));
        assertEquals(2, runCli("--db", directory.resolve("missing.db").toString(), "--ledger-id", LEDGER_ID,
                "--archive-dir", archiveDirectory.toString(), "--pinned-key", signer.publicKeyBase64()));
        assertEquals(2, runCli("--db", databasePath.toString(), "--ledger-id", LEDGER_ID,
                "--archive-dir", archiveDirectory.toString()));
    }

    @Test
    void cliOutputNamesMissingArchiveWithoutPrintingStoredValues() throws Exception {
        ArchiveResult result = archiveOld(3, 0);
        Files.delete(archiveDirectory.resolve(result.archiveFile()));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int code = ArchiveAuditCli.run(new String[] {"--db", databasePath.toString(), "--ledger-id", LEDGER_ID,
                "--archive-dir", archiveDirectory.toString(), "--pinned-key", signer.publicKeyBase64()},
                new PrintStream(out, true, StandardCharsets.UTF_8), System.err);
        String text = out.toString(StandardCharsets.UTF_8);

        assertEquals(1, code);
        assertTrue(text.contains("ARCHIVE_FILE_MISSING"));
        assertFalse(text.contains("synthetic-1"));
    }

    private int runCli(String... args) {
        return ArchiveAuditCli.run(args, new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(new ByteArrayOutputStream()));
    }

    private String scalar(String sql) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
                Statement statement = connection.createStatement();
                java.sql.ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }
}
