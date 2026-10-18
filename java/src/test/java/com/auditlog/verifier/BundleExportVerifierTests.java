package com.auditlog.verifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.service.AppendEventService;
import com.auditlog.service.ExportBundleService;
import com.auditlog.service.ExportBundleService.EmptyLedgerException;
import com.auditlog.service.ExportBundleService.ExportTooLargeException;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.verify.LedgerVerifier;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BundleExportVerifierTests {

    private static final String LEDGER_ID = "bundle-test-ledger";
    private static final Instant START = Instant.parse("2026-01-02T03:04:05.123456Z");
    private static final ObjectMapper JSON = new ObjectMapper();

    @TempDir
    Path directory;

    private JdbcAuditRepository repository;
    private CheckpointSigner signer;
    private AppendEventService appendService;
    private ExportBundleService exportService;
    private AuditConfiguration configuration;

    @BeforeEach
    void setUp() throws Exception {
        configuration = AuditConfiguration.fromEnvironment(Map.of(
                "AUDIT_LEDGER_ID", LEDGER_ID, "AUDIT_CHECKPOINT_INTERVAL", "100"));
        repository = new JdbcAuditRepository(directory.resolve("audit.db"), LEDGER_ID);
        signer = CheckpointSigner.fromFiles(
                directory.resolve("keys/private.pem"), directory.resolve("keys/public.b64"), "dev");
        Clock clock = Clock.fixed(START, ZoneOffset.UTC);
        appendService = new AppendEventService(repository, configuration, signer, clock);
        exportService = new ExportBundleService(repository, configuration, signer, appendService, clock);
    }

    private void seed() throws Exception {
        append("alice", "acct-1", Map.of("note", "hello", "amount", "10.50", "nested", Map.of("flag", true)));
        append("bob", "acct-2", Map.of("note", "other"));
        append("alice", "acct-3", Map.of("note", "again", "list", List.of(1, "x", false)));
        append("bob", "acct-1", Map.of("note", "mid"));
        append("alice", "acct-4", Map.of());
    }

    private void append(String actor, String resource, Map<String, Object> payload) throws Exception {
        appendService.append(
                new AppendEventRequest("TEST_EVENT", actor, "ACCOUNT", resource, payload, null), "writer");
    }

    private Map<String, Object> exportActor(String actor) throws Exception {
        return exportService.export(actor, null, "auditor");
    }

    private static byte[] bytes(Map<String, Object> bundle) throws Exception {
        return JSON.writeValueAsBytes(bundle);
    }

    private BundleVerifier.Result verifyPinned(Map<String, Object> bundle) throws Exception {
        return BundleVerifier.verify(bytes(bundle), BundleVerifier.Options.pinned(signer.publicKeyBase64()));
    }

    private Map<String, Object> mutable(Map<String, Object> bundle) throws Exception {
        return JSON.readValue(bytes(bundle), new TypeReference<Map<String, Object>>() { });
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> records(Map<String, Object> bundle) {
        return (List<Map<String, Object>>) bundle.get("records");
    }

    /** Re-derives count, digest and signature with the given key, as a malicious signer could. */
    private void resign(Map<String, Object> bundle, CheckpointSigner with) throws Exception {
        bundle.remove("signature");
        bundle.put("recordCount", records(bundle).size());
        bundle.put("recordsDigest", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(CanonicalJson.canonicalize(bundle.get("records"), 32, Integer.MAX_VALUE))));
        bundle.put("signature", with.signMessage(bundle, Integer.MAX_VALUE));
    }

    private static boolean has(BundleVerifier.Result result, String code) {
        return result.violations().stream().anyMatch(violation -> violation.startsWith(code + ":"));
    }

    @Test
    void validBundleVerifiesWithPinnedKeyAndDistinguishesHeads() throws Exception {
        seed();
        Map<String, Object> bundle = exportActor("alice");

        BundleVerifier.Result result = verifyPinned(bundle);

        assertTrue(result.verified(), result.violations().toString());
        assertEquals("PINNED_KEY", result.trust());
        assertEquals(3, result.recordCount());
        assertEquals(0, result.undisclosedLeafCount());
        Map<?, ?> completeness = (Map<?, ?>) bundle.get("completeness");
        assertEquals(5, ((Number) completeness.get("selectionHeadSeq")).intValue());
        assertEquals(6, ((Number) completeness.get("postEventSeq")).intValue());
        assertEquals(5, ((Number) ((Map<?, ?>) bundle.get("headCheckpoint")).get("seq")).intValue());
        assertEquals(List.of(1, 3, 5), records(bundle).stream()
                .map(record -> ((Number) record.get("seq")).intValue()).toList());
    }

    @Test
    void exportAppendsSystemEventWithoutSensitiveValuesAndLedgerStaysIntact() throws Exception {
        seed();
        exportActor("alice");

        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + directory.resolve("audit.db"));
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery(
                        "SELECT event_type, source, actor_id, resource_type FROM audit_events WHERE seq = 6")) {
            assertTrue(result.next());
            assertEquals("BUNDLE_EXPORTED", result.getString("event_type"));
            assertEquals("system", result.getString("source"));
            assertEquals("auditor", result.getString("actor_id"));
            assertEquals("AUDIT_EXPORT", result.getString("resource_type"));
        }
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + directory.resolve("audit.db"));
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery(
                        "SELECT count(*) FROM payload_leaves WHERE seq = 6 AND value LIKE '%alice%'")) {
            assertTrue(result.next());
            assertEquals(0, result.getInt(1), "selection value must not be repeated in the export event");
        }
        LedgerVerifier ledgerVerifier = new LedgerVerifier(
                repository, LEDGER_ID, signer.publicKeyBase64(), Clock.fixed(START, ZoneOffset.UTC));
        assertTrue(ledgerVerifier.verify().intact());
    }

    @Test
    void emptySelectionOnNonEmptyLedgerIsVerifiable() throws Exception {
        seed();
        Map<String, Object> bundle = exportActor("nobody");

        BundleVerifier.Result result = verifyPinned(bundle);

        assertTrue(result.verified(), result.violations().toString());
        assertEquals(0, result.recordCount());
    }

    @Test
    void emptyLedgerExportIsRejectedBecauseNoCheckpointExists() {
        assertThrows(EmptyLedgerException.class, () -> exportActor("alice"));
    }

    @Test
    void gappedSelectionVerifiesButCarriesNoInclusionProof() throws Exception {
        seed();
        Map<String, Object> bundle = exportService.export(null, "acct-1", "auditor");

        BundleVerifier.Result result = verifyPinned(bundle);

        assertTrue(result.verified(), result.violations().toString());
        assertEquals(2, result.recordCount());
        assertTrue(result.notes().stream().anyMatch(note -> note.contains("no global inclusion proof")));
    }

    @Test
    void alteredRecordFieldIsDetected() throws Exception {
        seed();
        Map<String, Object> bundle = mutable(exportActor("alice"));
        records(bundle).get(1).put("actorId", "mallory");

        BundleVerifier.Result result = verifyPinned(bundle);

        assertFalse(result.verified());
        assertTrue(has(result, "CONTENT_HASH_MISMATCH"));
        assertTrue(has(result, "RECORDS_DIGEST_MISMATCH"));
        assertTrue(has(result, "SIGNATURE_INVALID"));
    }

    @Test
    void alteredRecordResignedByTheSignerStillFailsHashChecks() throws Exception {
        seed();
        Map<String, Object> bundle = mutable(exportActor("alice"));
        records(bundle).get(1).put("actorId", "mallory");
        resign(bundle, signer);

        BundleVerifier.Result result = verifyPinned(bundle);

        assertFalse(result.verified());
        assertTrue(has(result, "CONTENT_HASH_MISMATCH"));
        assertFalse(has(result, "SIGNATURE_INVALID"));
    }

    @Test
    void alteredMetadataFieldsBreakTheSignature() throws Exception {
        seed();
        for (String field : List.of("exportedBy", "purpose", "ledgerId", "exportedAt")) {
            Map<String, Object> bundle = mutable(exportActor("alice"));
            bundle.put(field, field.equals("purpose") ? "COMPLIANCE_REPORT" : "changed");

            BundleVerifier.Result result = verifyPinned(bundle);

            assertFalse(result.verified(), field);
            assertTrue(has(result, "SIGNATURE_INVALID"), field);
        }
    }

    @Test
    void unsupportedAlgorithmsAndVersionsAreRejectedEvenWhenResigned() throws Exception {
        seed();
        for (Map.Entry<String, Object> change : Map.<String, Object>of(
                "hashVersion", 2,
                "hashAlgorithm", "SHA-512",
                "signatureAlgorithm", "RSA",
                "format", "audit-export-bundle/v2").entrySet()) {
            Map<String, Object> bundle = mutable(exportActor("alice"));
            bundle.put(change.getKey(), change.getValue());
            resign(bundle, signer);

            BundleVerifier.Result result = verifyPinned(bundle);

            assertFalse(result.verified(), change.getKey());
            assertTrue(has(result, "SCHEMA_INVALID"), change.getKey());
        }
    }

    @Test
    void wrongPinnedKeyIsRejected() throws Exception {
        seed();
        CheckpointSigner other = CheckpointSigner.fromFiles(
                directory.resolve("other/private.pem"), directory.resolve("other/public.b64"), "dev");

        BundleVerifier.Result result = BundleVerifier.verify(
                bytes(exportActor("alice")), BundleVerifier.Options.pinned(other.publicKeyBase64()));

        assertFalse(result.verified());
        assertTrue(has(result, "KEY_NOT_PINNED"));
        assertTrue(has(result, "SIGNATURE_INVALID"));
    }

    @Test
    void attackerSignedBundleIsRejectedWithPinnedKeyAndLabelledUntrustedWhenSelfAsserted() throws Exception {
        seed();
        CheckpointSigner attacker = CheckpointSigner.fromFiles(
                directory.resolve("attacker/private.pem"), directory.resolve("attacker/public.b64"), "dev");
        Map<String, Object> bundle = mutable(exportActor("alice"));
        records(bundle).remove(0);
        bundle.put("signer", Map.of("keyId", attacker.keyId(), "publicKey", attacker.publicKeyBase64()));
        resign(bundle, attacker);

        BundleVerifier.Result pinned = verifyPinned(bundle);
        BundleVerifier.Result selfAsserted = BundleVerifier.verify(
                bytes(bundle), BundleVerifier.Options.selfAsserted());

        assertFalse(pinned.verified());
        assertTrue(has(pinned, "KEY_NOT_PINNED"));
        assertEquals("UNTRUSTED_SELF_ASSERTED_KEY", selfAsserted.trust());
        assertTrue(selfAsserted.notes().stream().anyMatch(note -> note.contains("untrusted")));
        assertFalse(selfAsserted.verified(), "head checkpoint is signed by the service key, not the attacker");
        assertTrue(has(selfAsserted, "HEAD_CHECKPOINT_INVALID"));
    }

    @Test
    void selfAssertedModeOnGenuineBundleVerifiesButStaysLabelledUntrusted() throws Exception {
        seed();

        BundleVerifier.Result result = BundleVerifier.verify(
                bytes(exportActor("alice")), BundleVerifier.Options.selfAsserted());

        assertTrue(result.verified());
        assertEquals("UNTRUSTED_SELF_ASSERTED_KEY", result.trust());
    }

    @Test
    void mismatchedKeyIdIsRejected() throws Exception {
        seed();
        Map<String, Object> bundle = mutable(exportActor("alice"));
        @SuppressWarnings("unchecked")
        Map<String, Object> signerInfo = (Map<String, Object>) bundle.get("signer");
        signerInfo.put("keyId", "0000000000000000");
        resign(bundle, signer);

        assertTrue(has(verifyPinned(bundle), "SIGNER_INVALID"));
    }

    @Test
    void undisclosedLeavesVerifyWithoutClaimingAuthorization() throws Exception {
        seed();
        Map<String, Object> bundle = mutable(exportActor("alice"));
        @SuppressWarnings("unchecked")
        Map<String, Object> leaves = (Map<String, Object>) records(bundle).get(0).get("disclosedLeaves");
        int removed = leaves.size();
        leaves.clear();
        resign(bundle, signer);

        BundleVerifier.Result result = verifyPinned(bundle);

        assertTrue(result.verified(), result.violations().toString());
        assertEquals(removed, result.undisclosedLeafCount());
        assertTrue(result.notes().stream().anyMatch(note -> note.contains("does not")));
    }

    @Test
    void wrongDisclosedValueAndUnknownPointerAreDetected() throws Exception {
        seed();
        Map<String, Object> bundle = mutable(exportActor("alice"));
        @SuppressWarnings("unchecked")
        Map<String, Object> leaves = (Map<String, Object>) records(bundle).get(0).get("disclosedLeaves");
        @SuppressWarnings("unchecked")
        Map<String, Object> note = (Map<String, Object>) leaves.get("/note");
        note.put("value", "forged");
        leaves.put("/ghost", Map.of("salt", "00".repeat(32), "value", "x"));
        resign(bundle, signer);

        BundleVerifier.Result result = verifyPinned(bundle);

        assertTrue(has(result, "LEAF_COMMITMENT_MISMATCH"));
        assertTrue(has(result, "LEAF_POINTER_UNKNOWN"));
    }

    @Test
    void reorderedAndBrokenLinksAreDetected() throws Exception {
        seed();
        Map<String, Object> bundle = mutable(exportActor("alice"));
        java.util.Collections.swap(records(bundle), 0, 1);
        resign(bundle, signer);
        assertTrue(has(verifyPinned(bundle), "ORDER_INVALID"));

        Map<String, Object> linked = mutable(exportService.export("bob", null, "auditor"));
        records(linked).get(1).put("seq", 5);
        resign(linked, signer);
        assertFalse(verifyPinned(linked).verified());
    }

    @Test
    void brokenAdjacentLinkIsDetected() throws Exception {
        append("alice", "acct-1", Map.of("n", "a"));
        append("alice", "acct-1", Map.of("n", "b"));
        Map<String, Object> bundle = mutable(exportActor("alice"));
        records(bundle).get(1).put("prevHash", "f".repeat(64));
        resign(bundle, signer);

        BundleVerifier.Result result = verifyPinned(bundle);

        assertTrue(has(result, "CHAIN_LINK_BROKEN"));
        assertTrue(has(result, "CHAIN_HASH_MISMATCH"));
    }

    @Test
    void headBoundsAreEnforced() throws Exception {
        seed();
        Map<String, Object> bundle = mutable(exportActor("alice"));
        @SuppressWarnings("unchecked")
        Map<String, Object> head = (Map<String, Object>) bundle.get("headCheckpoint");
        head.put("seq", 2);
        resign(bundle, signer);

        BundleVerifier.Result result = verifyPinned(bundle);

        assertTrue(has(result, "HEAD_CHECKPOINT_INVALID"));
        assertTrue(has(result, "RECORD_AFTER_HEAD"));
    }

    @Test
    void recordCountAndDigestMismatchesAreDetected() throws Exception {
        seed();
        Map<String, Object> bundle = mutable(exportActor("alice"));
        bundle.put("recordCount", 99);
        bundle.put("recordsDigest", "0".repeat(64));
        bundle.remove("signature");
        bundle.put("signature", signer.signMessage(bundle, Integer.MAX_VALUE));

        BundleVerifier.Result result = verifyPinned(bundle);

        assertTrue(has(result, "RECORD_COUNT_MISMATCH"));
        assertTrue(has(result, "RECORDS_DIGEST_MISMATCH"));
        assertFalse(has(result, "SIGNATURE_INVALID"));
    }

    @Test
    void missingOrExtraFieldsFailClosed() throws Exception {
        seed();
        Map<String, Object> missing = mutable(exportActor("alice"));
        missing.remove("completeness");
        assertTrue(has(verifyPinned(missing), "SCHEMA_INVALID"));

        Map<String, Object> extra = mutable(exportActor("alice"));
        extra.put("surprise", 1);
        assertTrue(has(verifyPinned(extra), "SCHEMA_INVALID"));
    }

    @Test
    void malformedAndOverLimitInputIsAnInputError() throws Exception {
        seed();
        BundleVerifier.Options options = BundleVerifier.Options.pinned(signer.publicKeyBase64());
        assertThrows(BundleVerifier.InputException.class,
                () -> BundleVerifier.verify("not json".getBytes(StandardCharsets.UTF_8), options));
        assertThrows(BundleVerifier.InputException.class,
                () -> BundleVerifier.verify("[]".getBytes(StandardCharsets.UTF_8), options));
        assertThrows(BundleVerifier.InputException.class,
                () -> BundleVerifier.verify("{\"a\":1,\"a\":2}".getBytes(StandardCharsets.UTF_8), options));
        assertThrows(BundleVerifier.InputException.class,
                () -> BundleVerifier.verify(new byte[0], options));
        byte[] valid = bytes(exportActor("alice"));
        assertThrows(BundleVerifier.InputException.class,
                () -> BundleVerifier.verify(valid, options.withLimits(100, 10)));
        assertThrows(BundleVerifier.InputException.class,
                () -> BundleVerifier.verify(valid, options.withLimits(1 << 20, 1)));
        assertThrows(BundleVerifier.InputException.class,
                () -> BundleVerifier.verify("{}".getBytes(StandardCharsets.UTF_8),
                        new BundleVerifier.Options(null, false, 1000, 10)));
        assertThrows(BundleVerifier.InputException.class,
                () -> BundleVerifier.verify("{}".getBytes(StandardCharsets.UTF_8),
                        new BundleVerifier.Options("AAAA", false, 1000, 10)));
    }

    @Test
    void oversizedSelectionIsExplicitlyRejectedAndLeavesNoExportEvent() throws Exception {
        seed();
        Clock clock = Clock.fixed(START, ZoneOffset.UTC);
        ExportBundleService small = new ExportBundleService(
                repository, configuration, signer, appendService, clock, 2, ExportBundleService.DEFAULT_MAX_BYTES);
        ExportBundleService tiny = new ExportBundleService(
                repository, configuration, signer, appendService, clock, 100, 200);

        assertThrows(ExportTooLargeException.class, () -> small.export("alice", null, "auditor"));
        assertThrows(ExportTooLargeException.class, () -> tiny.export("alice", null, "auditor"));

        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + directory.resolve("audit.db"));
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("SELECT max(seq) FROM audit_events")) {
            assertTrue(result.next());
            assertEquals(5, result.getInt(1));
        }
    }

    @Test
    void selectionMustNameExactlyOneCriterion() throws Exception {
        seed();
        assertThrows(IllegalArgumentException.class, () -> exportService.export(null, null, "auditor"));
        assertThrows(IllegalArgumentException.class, () -> exportService.export("a", "b", "auditor"));
        assertThrows(IllegalArgumentException.class, () -> exportService.export(" ", null, "auditor"));
    }

    @Test
    void cliUsesDocumentedExitCodes() throws Exception {
        seed();
        Path good = directory.resolve("good.json");
        Files.write(good, bytes(exportActor("alice")));
        Map<String, Object> tamperedBundle = mutable(exportActor("alice"));
        records(tamperedBundle).get(0).put("actorId", "mallory");
        Path bad = directory.resolve("bad.json");
        Files.write(bad, bytes(tamperedBundle));
        Path keyFile = directory.resolve("pinned.b64");
        Files.writeString(keyFile, signer.publicKeyBase64() + "\n");

        assertEquals(0, cli("--bundle", good.toString(), "--pinned-key-file", keyFile.toString()));
        assertEquals(0, cli("--bundle", good.toString(), "--pinned-key", signer.publicKeyBase64()));
        assertEquals(0, cli("--bundle", good.toString(), "--allow-self-asserted"));
        assertEquals(1, cli("--bundle", bad.toString(), "--pinned-key", signer.publicKeyBase64()));
        assertEquals(2, cli("--bundle", good.toString()));
        assertEquals(2, cli("--bundle", directory.resolve("missing.json").toString(), "--allow-self-asserted"));
        assertEquals(2, cli("--allow-self-asserted"));
        assertEquals(2, cli("--bogus"));
        assertEquals(2, cli("--bundle", good.toString(), "--allow-self-asserted", "--pinned-key", "AAAA"));
        assertEquals(2, cli("--bundle", good.toString(), "--allow-self-asserted", "--max-bytes", "10"));
        assertEquals(2, cli("--bundle", good.toString(), "--max-bytes", "abc"));
    }

    private static int cli(String... args) {
        return BundleVerifierCli.run(args,
                new PrintStream(new ByteArrayOutputStream()), new PrintStream(new ByteArrayOutputStream()));
    }
}
