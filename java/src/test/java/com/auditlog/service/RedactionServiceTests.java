package com.auditlog.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.service.RedactionService.RedactionResult;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.verify.LedgerVerifier;
import com.auditlog.verify.VerificationReport;
import com.auditlog.verify.ViolationType;
import com.auditlog.web.ApiException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Real SQLite files; no mocks. The marker is synthetic and never a real identifier. */
class RedactionServiceTests {

    private static final String LEDGER_ID = "redaction-ledger";
    private static final String MARKER = "SYNTHETIC-PLAINTEXT-MARKER-7f3a91c2";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-03-04T05:06:07.123456Z"), ZoneOffset.UTC);

    @TempDir
    Path directory;

    private JdbcAuditRepository repository;
    private CheckpointSigner signer;
    private AppendEventService appendService;
    private RedactionCleanupService cleanup;
    private RedactionService redaction;
    private Path databasePath;

    @BeforeEach
    void setUp() throws Exception {
        databasePath = directory.resolve("audit.db");
        repository = new JdbcAuditRepository(databasePath, LEDGER_ID);
        signer = CheckpointSigner.fromFiles(
                directory.resolve("keys/private.pem"), directory.resolve("keys/public.b64"), "dev");
        wire(repository);
    }

    private void wire(JdbcAuditRepository target) {
        Map<String, String> values = new HashMap<>();
        values.put("AUDIT_LEDGER_ID", LEDGER_ID);
        values.put("AUDIT_DB_PATH", databasePath.toString());
        values.put("AUDIT_EXPORT_DIR", directory.resolve("exports").toString());
        values.put("AUDIT_CLEANUP_BUSY_TIMEOUT_MS", "100");
        values.put("AUDIT_CLEANUP_MAX_ATTEMPTS", "2");
        AuditConfiguration configuration = AuditConfiguration.fromEnvironment(values);
        appendService = new AppendEventService(target, configuration, signer, CLOCK);
        cleanup = new RedactionCleanupService(target, configuration, CLOCK);
        redaction = new RedactionService(target, configuration, appendService, cleanup);
    }

    private String seed() throws Exception {
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("ssn", MARKER);
        payload.put("profile", Map.of("name", "Zed Example", "tags", List.of("alpha-tag", "beta-tag")));
        payload.put("count", 7);
        payload.put("note", null);
        return appendService.append(
                new AppendEventRequest("CUSTOMER_UPDATED", "actor-1", "CUSTOMER", "c-1", payload, null),
                "writer").eventId();
    }

    private List<String> leaves(long seq) throws Exception {
        List<String> result = new ArrayList<>();
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery(
                        "SELECT pointer FROM payload_leaves WHERE seq = " + seq + " ORDER BY pointer")) {
            while (rows.next()) {
                result.add(rows.getString(1));
            }
        }
        return result;
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
        return new LedgerVerifier(repository, LEDGER_ID, signer.publicKeyBase64(), CLOCK).verify();
    }

    private static int status(Throwable throwable) {
        return ((ApiException) throwable).status();
    }

    @Test
    void redactsNestedScalarKeepingHashesAndChainIntact() throws Exception {
        String eventId = seed();
        String hashesBefore = scalar("SELECT content_hash || chain_hash || payload_commitments FROM audit_events WHERE seq = 1");

        RedactionResult result = redaction.redact(eventId, List.of("/profile/name"), "erasure request", "T-1", "admin");

        assertEquals(List.of("/profile/name"), result.redactedPaths());
        assertEquals(2, result.redactionSeq());
        assertEquals("COMPLETE", result.cleanupStatus());
        assertEquals(List.of("/count", "/note", "/profile/tags/0", "/profile/tags/1", "/ssn"), leaves(1));
        assertEquals(hashesBefore,
                scalar("SELECT content_hash || chain_hash || payload_commitments FROM audit_events WHERE seq = 1"));
        VerificationReport report = verify();
        assertTrue(report.intact(), report.violations().toString());
        assertEquals(1, report.redactedFields());
        assertEquals(2, report.headSeq());
        assertEquals("system", scalar("SELECT source FROM audit_events WHERE seq = 2"));
        assertEquals("RECORD_REDACTED", scalar("SELECT event_type FROM audit_events WHERE seq = 2"));
    }

    @Test
    void redactsRootPointerAsEveryLeaf() throws Exception {
        String eventId = seed();

        RedactionResult result = redaction.redact(eventId, List.of(""), "erasure request", "T-2", "admin");

        assertEquals(
                List.of("/count", "/note", "/profile/name", "/profile/tags/0", "/profile/tags/1", "/ssn"),
                result.redactedPaths());
        assertEquals(List.of(), leaves(1));
        VerificationReport report = verify();
        assertTrue(report.intact(), report.violations().toString());
        assertEquals(6, report.redactedFields());
    }

    @Test
    void subtreeAndOverlappingPathsAreExpandedAndDeduplicated() throws Exception {
        String eventId = seed();

        RedactionResult result = redaction.redact(
                eventId, List.of("/profile", "/profile/tags/1", "/profile/tags"), "erasure", "T-3", "admin");

        assertEquals(List.of("/profile/name", "/profile/tags/0", "/profile/tags/1"), result.redactedPaths());
        assertTrue(verify().intact());
    }

    @Test
    void secondRedactionOfSameValuesIsConflictAndPartialOverlapOnlyRemovesRemaining() throws Exception {
        String eventId = seed();
        redaction.redact(eventId, List.of("/ssn"), "erasure", "T-4", "admin");

        ApiException conflict = assertThrows(ApiException.class,
                () -> redaction.redact(eventId, List.of("/ssn"), "again", "T-5", "admin"));
        assertEquals(409, status(conflict));
        assertEquals(2, Long.parseLong(scalar("SELECT COUNT(*) FROM audit_events")));

        RedactionResult partial = redaction.redact(eventId, List.of("/ssn", "/count"), "more", "T-6", "admin");
        assertEquals(List.of("/count"), partial.redactedPaths());
        assertTrue(verify().intact());
    }

    @Test
    void rejectsMissingArchivedAndSystemTargetsAndBadPaths() throws Exception {
        String eventId = seed();
        redaction.redact(eventId, List.of("/ssn"), "erasure", "T-7", "admin");
        String systemEventId = scalar("SELECT event_id FROM audit_events WHERE seq = 2");

        assertEquals(404, status(assertThrows(ApiException.class,
                () -> redaction.redact("missing", List.of("/ssn"), "r", "T", "admin"))));
        assertEquals(409, status(assertThrows(ApiException.class,
                () -> redaction.redact(systemEventId, List.of("/reason"), "r", "T", "admin"))));
        assertThrows(IllegalArgumentException.class,
                () -> redaction.redact(eventId, List.of("/doesNotExist"), "r", "T", "admin"));
        assertThrows(IllegalArgumentException.class,
                () -> redaction.redact(eventId, List.of("/profile/tags/01"), "r", "T", "admin"));
        assertThrows(IllegalArgumentException.class,
                () -> redaction.redact(eventId, List.of("no-slash"), "r", "T", "admin"));
        assertThrows(IllegalArgumentException.class,
                () -> redaction.redact(eventId, List.of("/a~2b"), "r", "T", "admin"));
        assertThrows(IllegalArgumentException.class,
                () -> redaction.redact(eventId, List.of(), "r", "T", "admin"));
        assertThrows(IllegalArgumentException.class,
                () -> redaction.redact(eventId, List.of("/count"), " ", "T", "admin"));
        assertThrows(IllegalArgumentException.class,
                () -> redaction.redact(eventId, List.of("/count"), "r", "x".repeat(129), "admin"));

        execute("UPDATE audit_events SET archived = 1, archived_at = '2026-03-04T05:06:07.123456Z', "
                + "event_type = NULL, actor_id = NULL, resource_type = NULL, resource_id = NULL, "
                + "occurred_at = NULL, source = NULL, payload_commitments = NULL WHERE seq = 1");
        assertEquals(409, status(assertThrows(ApiException.class,
                () -> redaction.redact(eventId, List.of("/count"), "r", "T", "admin"))));
    }

    @Test
    void rejectsReasonThatEchoesRedactedValue() throws Exception {
        String eventId = seed();

        assertThrows(IllegalArgumentException.class,
                () -> redaction.redact(eventId, List.of("/ssn"), "remove " + MARKER, "T-8", "admin"));

        assertEquals(1, Long.parseLong(scalar("SELECT COUNT(*) FROM audit_events")));
        assertTrue(leaves(1).contains("/ssn"));
    }

    @Test
    void authorizationEventNeverContainsRedactedValue() throws Exception {
        String eventId = seed();

        redaction.redact(eventId, List.of("/ssn"), "erasure request", "T-9", "admin");

        assertFalse(scalar("SELECT payload_commitments FROM audit_events WHERE seq = 2").contains(MARKER));
        assertEquals(0, Long.parseLong(scalar(
                "SELECT COUNT(*) FROM payload_leaves WHERE seq = 2 AND value LIKE '%" + MARKER + "%'")));
    }

    @Test
    void failureAfterAppendRollsBackEventDeletionAndJob() throws Exception {
        String eventId = seed();
        execute("CREATE TRIGGER fail_cleanup BEFORE INSERT ON redaction_cleanup "
                + "BEGIN SELECT RAISE(ABORT, 'forced failure'); END");

        assertThrows(SQLException.class,
                () -> redaction.redact(eventId, List.of("/ssn", "/count"), "erasure", "T-10", "admin"));

        assertEquals(1, Long.parseLong(scalar("SELECT COUNT(*) FROM audit_events")));
        assertEquals(List.of("/count", "/note", "/profile/name", "/profile/tags/0", "/profile/tags/1", "/ssn"),
                leaves(1));
        assertEquals(0, Long.parseLong(scalar("SELECT COUNT(*) FROM redaction_cleanup")));
        assertTrue(verify().intact());
    }

    @Test
    void deletingLeafWithoutAuthorizationIsDetected() throws Exception {
        seed();
        execute("DELETE FROM payload_leaves WHERE seq = 1 AND pointer = '/ssn'");

        VerificationReport report = verify();

        assertFalse(report.intact());
        assertEquals(ViolationType.UNAUTHORIZED_REDACTION, report.firstViolation().type());
    }

    @Test
    void forgedAuthorizationWithWrongTargetIdOrShapeGrantsNothing() throws Exception {
        String eventId = seed();
        Map<String, Object> wrongTarget = Map.of(
                "targetSeq", 1, "targetEventId", "00000000-0000-0000-0000-000000000000",
                "paths", List.of("/ssn"), "reason", "forged", "ticketId", "T", "requestedBy", "attacker");
        Map<String, Object> extraKey = new java.util.LinkedHashMap<>(wrongTarget);
        extraKey.put("targetEventId", eventId);
        extraKey.put("extra", "x");
        repository.writeTransaction(connection -> {
            appendService.appendSystemEvent(connection, "RECORD_REDACTED", "attacker", "AUDIT_EVENT", eventId, wrongTarget);
            appendService.appendSystemEvent(connection, "RECORD_REDACTED", "attacker", "AUDIT_EVENT", eventId, extraKey);
            return null;
        });
        execute("DELETE FROM payload_leaves WHERE seq = 1 AND pointer = '/ssn'");

        VerificationReport report = verify();

        assertFalse(report.intact());
        List<ViolationType> types = report.violations().stream().map(v -> v.type()).toList();
        assertTrue(types.contains(ViolationType.UNAUTHORIZED_REDACTION), types.toString());
        assertTrue(types.contains(ViolationType.MALFORMED_RECORD), types.toString());
    }

    @Test
    void heldReaderLeavesCleanupPendingThenReleaseAndRetryCompletes() throws Exception {
        String eventId = seed();
        Path wal = Path.of(databasePath + "-wal");
        Connection reader = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
        try {
            reader.setAutoCommit(false);
            try (Statement statement = reader.createStatement();
                    ResultSet rows = statement.executeQuery("SELECT COUNT(*) FROM audit_events")) {
                rows.next();
            }

            RedactionResult result = redaction.redact(eventId, List.of("/ssn"), "erasure", "T-11", "admin");

            assertEquals("PENDING", result.cleanupStatus());
            assertEquals(2, result.cleanupAttempts());
            assertEquals("PENDING", scalar("SELECT status FROM redaction_cleanup"));
            assertEquals("BUSY", scalar("SELECT last_outcome FROM redaction_cleanup"));
            assertFalse(leaves(1).contains("/ssn"), "the deletion itself is committed even if cleanup is pending");
            assertTrue(contains(wal, MARKER) || contains(databasePath, MARKER),
                    "the value still sits in the database or WAL file while the reader blocks cleanup");
            assertEquals(1L, cleanup.status(10).get("pendingJobs"));
        } finally {
            reader.rollback();
            reader.close();
        }

        RedactionCleanupService.Summary retry = cleanup.runPending();

        assertEquals("COMPLETE", retry.status());
        assertEquals("COMPLETE", scalar("SELECT status FROM redaction_cleanup"));
        assertEquals("OK", scalar("SELECT last_outcome FROM redaction_cleanup"));
        assertFalse(contains(databasePath, MARKER), "main database file must not contain the value");
        assertFalse(contains(wal, MARKER), "WAL must not contain the value");
        assertTrue(verify().intact());
    }

    @Test
    void restartRecoveryFinishesPendingJobWithNewServiceInstance() throws Exception {
        String eventId = seed();
        Connection reader = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
        try {
            reader.setAutoCommit(false);
            try (Statement statement = reader.createStatement();
                    ResultSet rows = statement.executeQuery("SELECT COUNT(*) FROM audit_events")) {
                rows.next();
            }
            assertEquals("PENDING",
                    redaction.redact(eventId, List.of("/ssn"), "erasure", "T-12", "admin").cleanupStatus());
        } finally {
            reader.rollback();
            reader.close();
        }

        JdbcAuditRepository restarted = new JdbcAuditRepository(databasePath, LEDGER_ID);
        wire(restarted);
        RedactionCleanupService.Summary summary = cleanup.recover();

        assertEquals("COMPLETE", summary.status());
        assertEquals("COMPLETE", scalar("SELECT status FROM redaction_cleanup"));
        assertFalse(contains(databasePath, MARKER));
    }

    @Test
    void runPendingWithNoJobsIsComplete() {
        assertEquals("COMPLETE", cleanup.runPending().status());
    }

    @Test
    void cleanupJobsCannotBeDeletedOrRewrittenExceptToComplete() throws Exception {
        String eventId = seed();
        redaction.redact(eventId, List.of("/ssn"), "erasure", "T-13", "admin");

        assertThrows(SQLException.class, () -> execute("DELETE FROM redaction_cleanup"));
        assertThrows(SQLException.class, () -> execute("UPDATE redaction_cleanup SET status = 'PENDING'"));
        assertThrows(SQLException.class, () -> execute("UPDATE redaction_cleanup SET target_seq = 2"));
        assertThrows(SQLException.class, () -> execute("UPDATE redaction_cleanup SET completed_at = NULL"));
    }

    private void execute(String sql) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
                Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute(sql);
        }
    }

    private static boolean contains(Path file, String text) throws Exception {
        if (!Files.exists(file)) {
            return false;
        }
        byte[] bytes = Files.readAllBytes(file);
        return new String(bytes, StandardCharsets.ISO_8859_1)
                .contains(new String(text.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1));
    }
}
