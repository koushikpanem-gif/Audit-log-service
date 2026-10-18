package com.auditlog.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.core.crypto.PayloadCommitments;
import com.auditlog.core.crypto.V1Hashes;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.service.AppendEventService;
import com.auditlog.store.JdbcAuditRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LedgerVerifierTests {

    private static final String LEDGER_ID = "verify-test-ledger";
    private static final Instant START = Instant.parse("2026-01-02T03:04:05.123456Z");
    private static final String START_TEXT = "2026-01-02T03:04:05.123456Z";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final List<String> GUARD_TRIGGERS = List.of(
            "audit_events_block_delete", "audit_events_archive_only_update",
            "payload_leaves_block_update", "checkpoints_block_update", "checkpoints_block_delete");

    @TempDir
    Path directory;

    private JdbcAuditRepository repository;
    private CheckpointSigner signer;
    private LedgerVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        repository = new JdbcAuditRepository(directory.resolve("audit.db"), LEDGER_ID);
        signer = CheckpointSigner.fromFiles(
                directory.resolve("keys/private.pem"),
                directory.resolve("keys/public.b64"),
                "dev");
        verifier = new LedgerVerifier(
                repository, LEDGER_ID, signer.publicKeyBase64(), Clock.fixed(START, ZoneOffset.UTC), 3);
    }

    @Test
    void emptyLedgerIsIntactAtGenesis() throws Exception {
        VerificationReport report = verifier.verify();

        assertTrue(report.intact());
        assertEquals(0, report.headSeq());
        assertEquals(V1Hashes.genesisHash(LEDGER_ID), report.headHash());
        assertEquals(0, report.checkedRecords());
        assertNull(report.firstViolation());
        assertEquals("SHA-256", report.hashAlgorithm());
    }

    @Test
    void cleanLedgerWithCheckpointsIsIntact() throws Exception {
        append(5, 2);

        VerificationReport report = verifier.verify();

        assertTrue(report.intact(), report.violations().toString());
        assertEquals(5, report.checkedRecords());
        assertEquals(5, report.headSeq());
        assertEquals(2, report.checkpointsVerified());
        assertEquals(0, report.totalViolationCount());
        assertFalse(report.violationsTruncated());
    }

    @Test
    void editedFieldIsLocalizedToItsRecord() throws Exception {
        append(5, 100);
        tamper("UPDATE audit_events SET actor_id = 'mallory' WHERE seq = 3");

        VerificationReport report = verifier.verify();

        assertFalse(report.intact());
        assertEquals(ViolationType.CONTENT_HASH_MISMATCH, report.firstViolation().type());
        assertEquals(3L, report.firstViolation().seq());
        assertEquals(1, report.totalViolationCount());
    }

    @Test
    void editWithRecomputedHashesBreaksTheNextLink() throws Exception {
        append(5, 100);
        tamper("UPDATE audit_events SET actor_id = 'mallory' WHERE seq = 3");
        rehashRow(3);

        VerificationReport report = verifier.verify();

        assertEquals(1, report.totalViolationCount());
        assertEquals(ViolationType.CHAIN_LINK_BROKEN, report.firstViolation().type());
        assertEquals(4L, report.firstViolation().seq());
    }

    @Test
    void deletedRecordIsAGapAndABrokenLink() throws Exception {
        append(5, 100);
        tamper("DELETE FROM payload_leaves WHERE seq = 3", "DELETE FROM audit_events WHERE seq = 3");

        VerificationReport report = verifier.verify();

        assertEquals(List.of(ViolationType.SEQUENCE_GAP, ViolationType.CHAIN_LINK_BROKEN), types(report));
        assertEquals(4L, report.violations().get(0).seq());
    }

    @Test
    void reorderedRecordsAreDetected() throws Exception {
        append(4, 100);
        tamper("UPDATE audit_events SET seq = 99 WHERE seq = 2",
                "UPDATE audit_events SET seq = 2 WHERE seq = 3",
                "UPDATE audit_events SET seq = 3 WHERE seq = 99");

        VerificationReport report = verifier.verify();

        assertFalse(report.intact());
        assertEquals(2L, report.firstViolation().seq());
        assertTrue(types(report).contains(ViolationType.CHAIN_LINK_BROKEN));
    }

    @Test
    void editedLeafValueIsAPayloadMismatch() throws Exception {
        append(3, 100);
        tamper("UPDATE payload_leaves SET value = '999' WHERE seq = 2 AND pointer = '/amount'");

        VerificationReport report = verifier.verify();

        assertEquals(1, report.totalViolationCount());
        assertEquals(ViolationType.PAYLOAD_VALUE_MISMATCH, report.firstViolation().type());
        assertEquals("/amount", report.firstViolation().pointer());
        assertFalse(report.firstViolation().message().contains("999"));
    }

    @Test
    void missingLeafWithoutAuthorizationFailsClosed() throws Exception {
        append(3, 100);
        tamper("DELETE FROM payload_leaves WHERE seq = 2 AND pointer = '/amount'");

        VerificationReport report = verifier.verify();

        assertEquals(ViolationType.UNAUTHORIZED_REDACTION, report.firstViolation().type());
        assertEquals(2L, report.firstViolation().seq());
        assertEquals("/amount", report.firstViolation().pointer());
    }

    @Test
    void validatedSystemRedactionAuthorizesAMissingLeaf() throws Exception {
        append(3, 100);
        tamper("DELETE FROM payload_leaves WHERE seq = 2 AND pointer = '/amount'");
        forge("RECORD_REDACTED", redactionPayload(2, List.of("/amount")), "system");

        VerificationReport report = verifier.verify();

        assertTrue(report.intact(), report.violations().toString());
        assertEquals(1, report.redactedFields());
    }

    @Test
    void redactionForOtherPathOrWrongTargetGrantsNothing() throws Exception {
        append(3, 100);
        tamper("DELETE FROM payload_leaves WHERE seq = 2 AND pointer = '/amount'");
        forge("RECORD_REDACTED", redactionPayload(2, List.of("/other")), "system");
        Map<String, Object> wrongTarget = redactionPayload(2, List.of("/amount"));
        wrongTarget.put("targetEventId", "not-the-event");
        forge("RECORD_REDACTED", wrongTarget, "system");

        VerificationReport report = verifier.verify();

        assertTrue(types(report).contains(ViolationType.UNAUTHORIZED_REDACTION));
        assertTrue(types(report).contains(ViolationType.MALFORMED_RECORD));
    }

    @Test
    void malformedAuthorizationPayloadGrantsNothing() throws Exception {
        append(3, 100);
        tamper("DELETE FROM payload_leaves WHERE seq = 2 AND pointer = '/amount'");
        forge("RECORD_REDACTED", Map.of("targetSeq", 2, "paths", List.of("/amount")), "system");

        VerificationReport report = verifier.verify();

        assertTrue(types(report).contains(ViolationType.UNAUTHORIZED_REDACTION));
        assertTrue(types(report).contains(ViolationType.MALFORMED_RECORD));
    }

    @Test
    void callerSourcedReservedTypeIsMalformed() throws Exception {
        append(2, 100);
        forge("RECORD_REDACTED", redactionPayload(1, List.of("/amount")), "dev-writer");

        VerificationReport report = verifier.verify();

        assertEquals(ViolationType.MALFORMED_RECORD, report.firstViolation().type());
        assertEquals(3L, report.firstViolation().seq());
    }

    @Test
    void archivedSkeletonNeedsAValidatedArchiveAuthorization() throws Exception {
        append(3, 100);
        archiveSkeleton(1);

        VerificationReport unauthorized = verifier.verify();
        assertEquals(ViolationType.UNAUTHORIZED_ARCHIVE, unauthorized.firstViolation().type());
        assertEquals(1L, unauthorized.firstViolation().seq());
        assertEquals(1, unauthorized.archivedRecords());

        forge("RECORDS_ARCHIVED", archivePayload(1, 1, chainHashOf(1), "2025-12-01T00:00:00.000000Z", 30),
                "system");
        VerificationReport authorized = verifier.verify();
        assertTrue(authorized.intact(), authorized.violations().toString());
        assertEquals(1, authorized.archivedRecords());
    }

    @Test
    void archiveCutoffBeyondDeclaredRetentionIsAPolicyViolationButStillAuthorizes() throws Exception {
        append(3, 100);
        archiveSkeleton(1);
        forge("RECORDS_ARCHIVED", archivePayload(1, 1, chainHashOf(1), "2026-01-02T03:04:06.000000Z", 30),
                "system");

        assertEquals(List.of(ViolationType.RETENTION_POLICY_VIOLATION), types(verifier.verify()));
    }

    @Test
    void archiveEndHashMustMatchTheLedger() throws Exception {
        append(3, 100);
        archiveSkeleton(1);
        forge("RECORDS_ARCHIVED", archivePayload(1, 1, "0".repeat(64), "2025-12-01T00:00:00.000000Z", 30),
                "system");

        VerificationReport report = verifier.verify();

        assertTrue(types(report).contains(ViolationType.UNAUTHORIZED_ARCHIVE));
        assertTrue(types(report).contains(ViolationType.MALFORMED_RECORD));
    }

    @Test
    void rawMalformedStoredValuesAreDiagnosedWithoutExceptions() throws Exception {
        append(8, 100);
        tamper("UPDATE audit_events SET hash_version = 2 WHERE seq = 1",
                "UPDATE audit_events SET payload_commitments = '{bad' WHERE seq = 2",
                "UPDATE audit_events SET recorded_at = 'yesterday' WHERE seq = 3",
                "UPDATE audit_events SET content_hash = 'ABC' WHERE seq = 4",
                "UPDATE payload_leaves SET salt = 'zz' WHERE seq = 5 AND pointer = '/amount'",
                "UPDATE payload_leaves SET value = '{\"a\":1}' WHERE seq = 6 AND pointer = '/amount'",
                "UPDATE audit_events SET archived = 7 WHERE seq = 7",
                "UPDATE audit_events SET event_type = '   ' WHERE seq = 8");

        VerificationReport report = verifier.verify();

        assertFalse(report.intact());
        for (long seq = 1; seq <= 8; seq++) {
            long target = seq;
            assertTrue(report.violations().stream().anyMatch(violation ->
                    violation.seq() == target && violation.type() == ViolationType.MALFORMED_RECORD),
                    "seq " + seq + " should be malformed: " + report.violations());
        }
    }

    @Test
    void extraAndOrphanLeavesAreMalformed() throws Exception {
        append(2, 100);
        String salt = "11".repeat(32);
        tamper("INSERT INTO payload_leaves(seq, pointer, salt, value) VALUES (2, '/extra', '" + salt + "', '1')",
                "INSERT INTO payload_leaves(seq, pointer, salt, value) VALUES (50, '/x', '" + salt + "', '1')");

        VerificationReport report = verifier.verify();

        assertEquals(List.of(ViolationType.MALFORMED_RECORD, ViolationType.MALFORMED_RECORD), types(report));
    }

    @Test
    void genesisMismatchIsReported() throws Exception {
        append(2, 100);
        tamper("UPDATE audit_events SET prev_hash = '" + "a".repeat(64) + "' WHERE seq = 1");

        VerificationReport report = verifier.verify();

        assertEquals(ViolationType.GENESIS_MISMATCH, report.violations().get(0).type());
        assertTrue(types(report).contains(ViolationType.CHAIN_HASH_MISMATCH));
    }

    @Test
    void checkpointSignatureTamperingIsDetected() throws Exception {
        append(4, 2);
        tamper("UPDATE checkpoints SET chain_hash = '" + "b".repeat(64) + "' WHERE seq = 2");

        VerificationReport report = verifier.verify();

        assertEquals(List.of(ViolationType.CHECKPOINT_SIGNATURE_INVALID), types(report));
        assertEquals(1, report.checkpointsVerified());
    }

    @Test
    void validlySignedCheckpointForDifferentHashIsAMismatch() throws Exception {
        append(4, 100);
        insertCheckpoint(signer, 2, "c".repeat(64));

        assertEquals(List.of(ViolationType.CHECKPOINT_MISMATCH), types(verifier.verify()));
    }

    @Test
    void checkpointSignedByAnotherKeyIsRejected() throws Exception {
        append(4, 100);
        CheckpointSigner other = CheckpointSigner.fromFiles(
                directory.resolve("other/private.pem"), directory.resolve("other/public.b64"), "dev");
        insertCheckpoint(other, 2, chainHashOf(2));

        assertEquals(List.of(ViolationType.CHECKPOINT_SIGNATURE_INVALID), types(verifier.verify()));
    }

    @Test
    void malformedCheckpointRowIsDiagnosed() throws Exception {
        append(4, 100);
        tamper("INSERT INTO checkpoints(seq, chain_hash, created_at, key_id, signature) "
                + "VALUES (2, 'nope', 'x', 'y', 'z')");

        assertEquals(List.of(ViolationType.MALFORMED_RECORD), types(verifier.verify()));
    }

    @Test
    void truncationBeforeACheckpointIsDetected() throws Exception {
        append(5, 2);
        deleteFrom(4);

        VerificationReport report = verifier.verify();

        assertEquals(List.of(ViolationType.TRUNCATION_DETECTED), types(report));
        assertEquals(4L, report.firstViolation().seq());
        assertEquals(3, report.headSeq());
    }

    @Test
    void documentedLimitUncheckpointedTailRewriteIsNotDetected() throws Exception {
        append(5, 2);
        tamper("UPDATE audit_events SET actor_id = 'forged-actor' WHERE seq = 5");
        rehashRow(5);

        assertTrue(verifier.verify().intact());
    }

    @Test
    void documentedLimitTailDeletionAfterTheLastCheckpointIsNotDetected() throws Exception {
        append(5, 2);
        deleteFrom(5);

        VerificationReport report = verifier.verify();

        assertTrue(report.intact());
        assertEquals(4, report.headSeq());
    }

    @Test
    void documentedLimitTailDeletionTogetherWithItsCheckpointsIsNotDetected() throws Exception {
        append(5, 2);
        deleteFrom(3);
        tamper("DELETE FROM checkpoints WHERE seq = 4");

        VerificationReport report = verifier.verify();

        assertTrue(report.intact());
        assertEquals(2, report.headSeq());
        assertEquals(1, report.checkpointsVerified());
    }

    @Test
    void fullRewriteIsCaughtOnlyByASurvivingAnchoredCheckpoint() throws Exception {
        append(4, 2);
        tamper("UPDATE audit_events SET actor_id = 'rewritten' WHERE seq = 1");
        rewriteChainFrom(1);

        assertEquals(List.of(ViolationType.CHECKPOINT_MISMATCH, ViolationType.CHECKPOINT_MISMATCH),
                types(verifier.verify()));

        tamper("DELETE FROM checkpoints");
        assertTrue(verifier.verify().intact(), "a full rewrite without checkpoints is undetectable");
    }

    @Test
    void keepsOnlyTheEarliest100DiagnosticsWithExactTotals() throws Exception {
        append(150, 1000);
        tamper("UPDATE audit_events SET content_hash = '" + "a".repeat(64) + "'");

        VerificationReport report = verifier.verify();

        assertEquals(300, report.totalViolationCount());
        assertEquals(100, report.violations().size());
        assertTrue(report.violationsTruncated());
        assertEquals(1L, report.firstViolation().seq());
        assertEquals(ViolationType.CONTENT_HASH_MISMATCH, report.firstViolation().type());
        assertEquals(ViolationType.CHAIN_HASH_MISMATCH, report.violations().get(1).type());
        assertEquals(50L, report.violations().get(99).seq());
        assertEquals(150, report.checkedRecords());
    }

    @Test
    void scansAcrossBatchesInOneSnapshot() throws Exception {
        append(10, 100);
        LedgerVerifier small = new LedgerVerifier(
                repository, LEDGER_ID, signer.publicKeyBase64(), Clock.fixed(START, ZoneOffset.UTC), 2);

        VerificationReport report = small.verify();

        assertTrue(report.intact());
        assertEquals(10, report.checkedRecords());
    }

    @Test
    void ledgerBoundToAnotherIdFailsClosed() throws Exception {
        append(1, 100);
        LedgerVerifier other = new LedgerVerifier(
                repository, "different-ledger", signer.publicKeyBase64(),
                Clock.fixed(START, ZoneOffset.UTC), 3);

        VerificationReport report = other.verify();

        assertFalse(report.intact());
        assertTrue(report.violations().stream().anyMatch(violation ->
                violation.type() == ViolationType.MALFORMED_RECORD && violation.seq() == null));
    }

    private void append(int count, int interval) throws Exception {
        AuditConfiguration configuration = AuditConfiguration.fromEnvironment(Map.of(
                "AUDIT_LEDGER_ID", LEDGER_ID,
                "AUDIT_CHECKPOINT_INTERVAL", Integer.toString(interval)));
        Clock old = Clock.fixed(START.minus(Duration.ofDays(100)), ZoneOffset.UTC);
        AppendEventService service = new AppendEventService(repository, configuration, signer, old);
        for (int index = 1; index <= count; index++) {
            service.append(new AppendEventRequest("EVENT", "actor-" + index, "ACCOUNT", "account-1",
                    Map.of("amount", index, "note", "n" + index), null), "writer");
        }
    }

    private static List<ViolationType> types(VerificationReport report) {
        return report.violations().stream().map(Violation::type).toList();
    }

    private Connection raw() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + directory.resolve("audit.db"));
    }

    private void tamper(String... statements) throws SQLException {
        try (Connection connection = raw(); Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = OFF");
            statement.execute("PRAGMA ignore_check_constraints = ON");
            for (String trigger : GUARD_TRIGGERS) {
                statement.execute("DROP TRIGGER IF EXISTS " + trigger);
            }
            for (String sql : statements) {
                statement.execute(sql);
            }
        }
    }

    private void deleteFrom(long seq) throws SQLException {
        tamper("DELETE FROM payload_leaves WHERE seq >= " + seq,
                "DELETE FROM audit_events WHERE seq >= " + seq);
    }

    private String query(String sql) throws SQLException {
        try (Connection connection = raw();
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery(sql)) {
            return result.next() ? result.getString(1) : null;
        }
    }

    private String chainHashOf(long seq) throws SQLException {
        return query("SELECT chain_hash FROM audit_events WHERE seq = " + seq);
    }

    private void insertCheckpoint(CheckpointSigner by, long seq, String chainHash) throws SQLException {
        Map<String, Object> signed = by.signCheckpoint(LEDGER_ID, seq, chainHash, START_TEXT);
        tamper("INSERT INTO checkpoints(seq, chain_hash, created_at, key_id, signature) VALUES ("
                + seq + ", '" + chainHash + "', '" + START_TEXT + "', '" + signed.get("keyId")
                + "', '" + signed.get("signature") + "')");
    }

    private void archiveSkeleton(long seq) throws SQLException {
        tamper("DELETE FROM payload_leaves WHERE seq = " + seq,
                "UPDATE audit_events SET archived = 1, archived_at = '" + START_TEXT + "', "
                        + "event_type = NULL, actor_id = NULL, resource_type = NULL, resource_id = NULL, "
                        + "occurred_at = NULL, source = NULL, payload_commitments = NULL WHERE seq = " + seq);
    }

    private void rehashRow(long seq) throws Exception {
        try (Connection connection = raw()) {
            rehash(connection, seq, null);
        }
    }

    private void rewriteChainFrom(long from) throws Exception {
        try (Connection connection = raw()) {
            long max;
            try (Statement statement = connection.createStatement();
                    ResultSet result = statement.executeQuery("SELECT MAX(seq) FROM audit_events")) {
                result.next();
                max = result.getLong(1);
            }
            String previous = null;
            for (long seq = from; seq <= max; seq++) {
                previous = rehash(connection, seq, previous);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private String rehash(Connection connection, long seq, String newPrev) throws Exception {
        try (PreparedStatement select = connection.prepareStatement(
                "SELECT event_id, event_type, actor_id, resource_type, resource_id, occurred_at, "
                        + "recorded_at, source, payload_commitments, prev_hash FROM audit_events WHERE seq = ?")) {
            select.setLong(1, seq);
            try (ResultSet result = select.executeQuery()) {
                result.next();
                String prev = newPrev != null ? newPrev : result.getString(10);
                Map<String, Object> commitments = JSON.readValue(result.getString(9), LinkedHashMap.class);
                String content = V1Hashes.contentHash(V1Hashes.contentObject(
                        seq, result.getString(1), result.getString(2), result.getString(3),
                        result.getString(4), result.getString(5), result.getString(6),
                        result.getString(7), result.getString(8), commitments));
                String chain = V1Hashes.chainHash(prev, content);
                try (PreparedStatement update = connection.prepareStatement(
                        "UPDATE audit_events SET content_hash = ?, prev_hash = ?, chain_hash = ? WHERE seq = ?")) {
                    update.setString(1, content);
                    update.setString(2, prev);
                    update.setString(3, chain);
                    update.setLong(4, seq);
                    update.executeUpdate();
                }
                return chain;
            }
        }
    }

    private Map<String, Object> redactionPayload(long targetSeq, List<String> paths) throws SQLException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("targetSeq", targetSeq);
        payload.put("targetEventId", query("SELECT event_id FROM audit_events WHERE seq = " + targetSeq));
        payload.put("paths", paths);
        payload.put("reason", "synthetic test reason");
        payload.put("ticketId", "TICKET-1");
        payload.put("requestedBy", "dev-admin");
        return payload;
    }

    private Map<String, Object> archivePayload(
            long from, long to, String lastHash, String cutoff, long retentionDays) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("archivedThroughSeq", to);
        payload.put("fromSeq", from);
        payload.put("toSeq", to);
        payload.put("count", to - from + 1);
        payload.put("cutoff", cutoff);
        payload.put("retentionDays", retentionDays);
        payload.put("lastArchivedChainHash", lastHash);
        payload.put("archiveFile", "synthetic.bundle.json");
        payload.put("archiveSha256", "d".repeat(64));
        payload.put("archiveBundleId", "bundle-1");
        payload.put("requestedBy", "dev-admin");
        return payload;
    }

    /** Inserts a hash-consistent record directly through SQL, as a DB administrator could. */
    private void forge(String type, Map<String, ?> payload, String source) throws Exception {
        long seq = Long.parseLong(query("SELECT MAX(seq) FROM audit_events")) + 1;
        String prev = chainHashOf(seq - 1);
        String eventId = "forged-" + seq;
        int[] counter = {0};
        PayloadCommitments.CommitmentResult committed = PayloadCommitments.commit(payload, () -> {
            byte[] salt = new byte[32];
            salt[0] = (byte) (++counter[0]);
            salt[1] = (byte) seq;
            return salt;
        });
        String content = V1Hashes.contentHash(V1Hashes.contentObject(
                seq, eventId, type, "system", "LEDGER", LEDGER_ID, null, START_TEXT, source,
                committed.commitments()));
        String chain = V1Hashes.chainHash(prev, content);
        try (Connection connection = raw()) {
            try (PreparedStatement insert = connection.prepareStatement("""
                    INSERT INTO audit_events(seq, event_id, event_type, actor_id, resource_type, resource_id,
                        occurred_at, recorded_at, source, payload_commitments, hash_version,
                        content_hash, prev_hash, chain_hash)
                    VALUES (?, ?, ?, 'system', 'LEDGER', ?, NULL, ?, ?, ?, 1, ?, ?, ?)""")) {
                insert.setLong(1, seq);
                insert.setString(2, eventId);
                insert.setString(3, type);
                insert.setString(4, LEDGER_ID);
                insert.setString(5, START_TEXT);
                insert.setString(6, source);
                insert.setString(7, new String(
                        CanonicalJson.canonicalize(committed.commitments()), StandardCharsets.UTF_8));
                insert.setString(8, content);
                insert.setString(9, prev);
                insert.setString(10, chain);
                insert.executeUpdate();
            }
            for (var entry : committed.leaves().entrySet()) {
                try (PreparedStatement leaf = connection.prepareStatement(
                        "INSERT INTO payload_leaves(seq, pointer, salt, value) VALUES (?, ?, ?, ?)")) {
                    leaf.setLong(1, seq);
                    leaf.setString(2, entry.getKey());
                    leaf.setString(3, HexFormat.of().formatHex(entry.getValue().salt()));
                    leaf.setString(4, JSON.writeValueAsString(entry.getValue().value()));
                    leaf.executeUpdate();
                }
            }
        }
    }
}
