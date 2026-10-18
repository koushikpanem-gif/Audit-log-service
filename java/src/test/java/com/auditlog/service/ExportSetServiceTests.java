package com.auditlog.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.domain.BundleDiagnosticCode;
import com.auditlog.domain.BundleSelection;
import com.auditlog.service.ExportSetService.ExportSetException;
import com.auditlog.service.ExportSetService.Kind;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.verifier.BundleVerifier;
import com.auditlog.verifier.BundleVerifier.Options;
import com.auditlog.verifier.BundleVerifier.Result;
import com.auditlog.verifier.BundleVerifier.Status;
import com.auditlog.verifier.ExportSetVerifier;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Round trips use the Java builder and Java verifier, so they prove internal consistency and the
 * failure behaviour of the protocol, not independent cross-language agreement.
 */
class ExportSetServiceTests {

    private static final String LEDGER_ID = "export-set-ledger";
    private static final Instant START = Instant.parse("2026-03-04T05:06:07.123456Z");
    private static final ObjectMapper JSON = new ObjectMapper();

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

    private JdbcAuditRepository repository;
    private CheckpointSigner signer;
    private AppendEventService appendService;
    private final MutableClock clock = new MutableClock(START);
    private Path exportRoot;

    @BeforeEach
    void setUp() throws Exception {
        AuditConfiguration base = config(Map.of());
        repository = new JdbcAuditRepository(directory.resolve("audit.db"), LEDGER_ID);
        signer = CheckpointSigner.fromFiles(
                directory.resolve("keys/private.pem"), directory.resolve("keys/public.b64"), "dev");
        appendService = new AppendEventService(
                repository, base, signer, Clock.fixed(START, ZoneOffset.UTC));
        exportRoot = directory.resolve("exports");
    }

    private AuditConfiguration config(Map<String, String> extra) {
        Map<String, String> values = new HashMap<>();
        values.put("AUDIT_LEDGER_ID", LEDGER_ID);
        values.put("AUDIT_DB_PATH", directory.resolve("audit.db").toString());
        values.put("AUDIT_EXPORT_DIR", directory.resolve("exports").toString());
        values.putAll(extra);
        return AuditConfiguration.fromEnvironment(values);
    }

    private ExportSetService service(Map<String, String> extra) {
        return service(extra, Runnable::run);
    }

    private ExportSetService service(Map<String, String> extra, java.util.concurrent.Executor executor) {
        return new ExportSetService(repository, config(extra), signer, appendService, clock, executor);
    }

    private void bulkSeed(int count) throws Exception {
        repository.writeTransaction(connection -> {
            for (int index = 0; index < count; index++) {
                appendService.appendSystemEvent(connection, "BULK_TEST", "actor-" + (index % 3), "ACCOUNT",
                        "acct-" + index, Map.of("n", index, "note", "bulk"));
            }
            return null;
        });
    }

    private BundleSelection all() {
        return new BundleSelection(null, null, null, null, null, null, null, null);
    }

    private Options pinned() {
        return Options.pinned(signer.publicKeyBase64());
    }

    private Path readyDirectory(String id) {
        return exportRoot.resolve("ready").resolve(id);
    }

    private static Map<String, Object> read(Path file) throws IOException {
        return JSON.readValue(Files.readAllBytes(file), new TypeReference<Map<String, Object>>() { });
    }

    private static boolean has(Result result, BundleDiagnosticCode code) {
        return result.diagnostics().stream().anyMatch(d -> d.code() == code);
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private long ledgerCount(String where) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + directory.resolve("audit.db"));
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("SELECT COUNT(*) FROM audit_events " + where)) {
            rows.next();
            return rows.getLong(1);
        }
    }

    /** Creates a ready set whose chunks hold 100 records each. */
    private Path readySmallSet(int records) throws Exception {
        bulkSeed(records);
        ExportSetService service = service(Map.of("AUDIT_EXPORT_CHUNK_MAX_RECORDS", "100"));
        Map<String, Object> descriptor = service.create(all(), "auditor");
        assertEquals("READY", descriptor.get("status"));
        Path work = directory.resolve("work-" + System.nanoTime());
        Files.createDirectories(work);
        try (Stream<Path> files = Files.list(readyDirectory((String) descriptor.get("exportSetId")))) {
            for (Path file : (Iterable<Path>) files::iterator) {
                Files.copy(file, work.resolve(file.getFileName()));
            }
        }
        return work;
    }

    private Result verify(Path work) {
        return ExportSetVerifier.verify(work.resolve("manifest.json"), pinned());
    }

    private void rewriteManifest(Path work, Consumer<Map<String, Object>> change, boolean refreshDigest)
            throws Exception {
        Map<String, Object> manifest = read(work.resolve("manifest.json"));
        change.accept(manifest);
        if (refreshDigest) {
            manifest.put("chunksDigest", sha256(CanonicalJson.canonicalize(
                    manifest.get("chunks"), 32, Integer.MAX_VALUE)));
        }
        manifest.remove("signature");
        manifest.put("signature", signer.signMessage(manifest, Integer.MAX_VALUE));
        Files.write(work.resolve("manifest.json"), JSON.writeValueAsBytes(manifest));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> chunkEntries(Map<String, Object> manifest) {
        return (List<Map<String, Object>>) manifest.get("chunks");
    }

    // ------------------------------------------------------------------ happy paths

    @Test
    void completeSetOver10000RecordsVerifiesAndIsBounded() throws Exception {
        bulkSeed(10_100);
        ExportSetService service = service(Map.of("AUDIT_EXPORT_CHUNK_MAX_RECORDS", "1000"));
        Map<String, Object> descriptor = service.create(all(), "auditor");
        String id = (String) descriptor.get("exportSetId");

        assertEquals("READY", descriptor.get("status"));
        assertEquals(10_100L, ((Number) descriptor.get("totalRecords")).longValue());
        assertEquals(11, ((Number) descriptor.get("chunkCount")).intValue());
        assertEquals(10_100L, ((Number) descriptor.get("selectionHeadSeq")).longValue());
        assertEquals(10_101L, ((Number) descriptor.get("postEventHeadSeq")).longValue());
        assertEquals("/audit/export-sets/" + id + "/manifest", descriptor.get("manifestUrl"));

        Path manifestFile = service.manifestFile(id);
        Result result = ExportSetVerifier.verify(manifestFile, pinned());
        assertEquals(Status.VERIFIED, result.status(), () -> result.diagnostics().toString());
        assertEquals(10_100L, result.recordCount());

        Map<String, Object> manifest = read(manifestFile);
        assertEquals(1, ledgerCount("WHERE event_type = 'BUNDLE_EXPORTED'"));
        for (Map<String, Object> chunk : chunkEntries(manifest)) {
            assertTrue(((Number) chunk.get("recordCount")).intValue() <= 1000);
            assertEquals(Files.size(service.chunkFile(id, (String) chunk.get("name"))),
                    ((Number) chunk.get("bytes")).longValue());
        }
        assertFalse(Files.exists(exportRoot.resolve("staging").resolve(id)));

        Result unpinned = ExportSetVerifier.verify(manifestFile, Options.unconfigured());
        assertEquals(Status.INVALID, unpinned.status());
        assertTrue(has(unpinned, BundleDiagnosticCode.TRUSTED_KEY_REQUIRED));
        Result selfAsserted = ExportSetVerifier.verify(manifestFile, Options.selfAsserted());
        assertEquals(Status.INTEGRITY_VALID_ORIGIN_UNTRUSTED, selfAsserted.status());
    }

    @Test
    void selectionFiltersApplyAndEmptySelectionIsAnExplicitEmptySet() throws Exception {
        bulkSeed(30);
        ExportSetService service = service(Map.of());
        Map<String, Object> filtered = service.create(
                new BundleSelection("actor-1", null, null, null, null, null, null, null), "auditor");
        assertEquals(10L, ((Number) filtered.get("totalRecords")).longValue());
        Result result = ExportSetVerifier.verify(service.manifestFile((String) filtered.get("exportSetId")), pinned());
        assertEquals(Status.VERIFIED, result.status(), () -> result.diagnostics().toString());

        Map<String, Object> none = service.create(
                new BundleSelection("nobody", null, null, null, null, null, null, null), "auditor");
        assertEquals("READY", none.get("status"));
        assertEquals(0L, ((Number) none.get("totalRecords")).longValue());
        assertEquals(0, ((Number) none.get("chunkCount")).intValue());
        assertEquals(Status.VERIFIED,
                ExportSetVerifier.verify(service.manifestFile((String) none.get("exportSetId")), pinned()).status());
    }

    @Test
    void largeValuesAreSplitByByteLimitWithoutLoss() throws Exception {
        String big = "x".repeat(60_000);
        for (int index = 0; index < 12; index++) {
            appendService.append(new AppendEventRequest("TEST_EVENT", "alice", "ACCOUNT", "acct-" + index,
                    Map.of("blob", big), null), "writer");
        }
        ExportSetService service = service(Map.of("AUDIT_EXPORT_CHUNK_MAX_BYTES", "200000"));
        Map<String, Object> descriptor = service.create(all(), "auditor");
        assertEquals("READY", descriptor.get("status"));
        assertEquals(12L, ((Number) descriptor.get("totalRecords")).longValue());
        String id = (String) descriptor.get("exportSetId");
        assertTrue(((Number) descriptor.get("chunkCount")).intValue() >= 4);
        for (Map<String, Object> chunk : chunkEntries(read(service.manifestFile(id)))) {
            assertTrue(((Number) chunk.get("bytes")).longValue() <= 200_000);
        }
        Result result = ExportSetVerifier.verify(service.manifestFile(id), pinned());
        assertEquals(Status.VERIFIED, result.status(), () -> result.diagnostics().toString());
        assertEquals(12L, result.recordCount());
    }

    @Test
    void concurrentAppendsAreExcludedAndSelectionHeadIsDistinctFromPostEventHead() throws Exception {
        bulkSeed(3000);
        ExecutorService jobs = Executors.newSingleThreadExecutor();
        ExecutorService writer = Executors.newSingleThreadExecutor();
        AtomicBoolean stop = new AtomicBoolean();
        AtomicInteger appended = new AtomicInteger();
        try {
            writer.submit(() -> {
                while (!stop.get()) {
                    try {
                        appendService.append(new AppendEventRequest("LIVE_EVENT", "writer-actor", "ACCOUNT",
                                "live-" + appended.get(), Map.of("n", appended.get()), null), "writer");
                        appended.incrementAndGet();
                    } catch (Exception exception) {
                        return;
                    }
                }
            });
            while (appended.get() == 0) {
                Thread.sleep(5);
            }
            ExportSetService service = service(Map.of("AUDIT_EXPORT_CHUNK_MAX_RECORDS", "500"), jobs);
            String id = (String) service.create(all(), "auditor").get("exportSetId");
            Map<String, Object> descriptor = awaitReady(service, id);
            stop.set(true);
            writer.shutdown();
            writer.awaitTermination(30, java.util.concurrent.TimeUnit.SECONDS);

            long selectionHead = ((Number) descriptor.get("selectionHeadSeq")).longValue();
            long postEventHead = ((Number) descriptor.get("postEventHeadSeq")).longValue();
            assertTrue(selectionHead >= 3001, "an append happened before the snapshot was taken");
            assertTrue(postEventHead > selectionHead);
            assertEquals(selectionHead, ((Number) descriptor.get("totalRecords")).longValue(),
                    "exactly the records up to the fixed selection head, none after it");
            assertTrue(ledgerCount("") >= postEventHead, "the ledger kept growing past the set");
            Result result = ExportSetVerifier.verify(service.manifestFile(id), pinned());
            assertEquals(Status.VERIFIED, result.status(), () -> result.diagnostics().toString());
        } finally {
            stop.set(true);
            jobs.shutdownNow();
            writer.shutdownNow();
        }
    }

    private static Map<String, Object> awaitReady(ExportSetService service, String id) throws Exception {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(120);
        while (System.nanoTime() < deadline) {
            Map<String, Object> descriptor = service.describe(id);
            if ("READY".equals(descriptor.get("status"))) {
                return descriptor;
            }
            assertEquals("RUNNING", descriptor.get("status"), () -> descriptor.toString());
            Thread.sleep(25);
        }
        throw new AssertionError("export set did not become READY");
    }

    // ------------------------------------------------------------------ no silent truncation

    @Test
    void setLimitFailsExplicitlyAndLeavesNoArtifactsOrMetaEvent() throws Exception {
        bulkSeed(8);
        ExportSetService service = service(Map.of("AUDIT_EXPORT_SET_MAX_RECORDS", "5"));
        Map<String, Object> descriptor = service.create(all(), "auditor");
        assertEquals("FAILED", descriptor.get("status"));
        assertEquals("EXPORT_SET_TOO_LARGE", descriptor.get("errorCode"));
        assertEquals(0, ledgerCount("WHERE event_type = 'BUNDLE_EXPORTED'"));
        String id = (String) descriptor.get("exportSetId");
        assertFalse(Files.exists(exportRoot.resolve("staging").resolve(id)));
        assertEquals(Kind.NOT_READY, assertThrows(ExportSetException.class, () -> service.manifestFile(id)).kind());
    }

    @Test
    void recordLargerThanChunkLimitFailsInsteadOfBeingSkipped() throws Exception {
        appendService.append(new AppendEventRequest("TEST_EVENT", "alice", "ACCOUNT", "acct-1",
                Map.of("blob", "y".repeat(50_000)), null), "writer");
        ExportSetService service = service(Map.of("AUDIT_EXPORT_CHUNK_MAX_BYTES", "4096"));
        Map<String, Object> descriptor = service.create(all(), "auditor");
        assertEquals("FAILED", descriptor.get("status"));
        assertEquals("EXPORT_RECORD_TOO_LARGE", descriptor.get("errorCode"));
        assertEquals(0, ledgerCount("WHERE event_type = 'BUNDLE_EXPORTED'"));
    }

    @Test
    void sequenceBoundsAreRejected() {
        ExportSetService service = service(Map.of());
        assertThrows(IllegalArgumentException.class, () -> service.create(
                new BundleSelection(null, null, null, null, null, null, 1L, 5L), "auditor"));
    }

    // ------------------------------------------------------------------ tamper detection

    @Test
    void missingChunkIsDetected() throws Exception {
        Path work = readySmallSet(350);
        assertEquals(Status.VERIFIED, verify(work).status());
        Files.delete(work.resolve("chunk-000001.json"));
        Result result = verify(work);
        assertEquals(Status.INVALID, result.status());
        assertTrue(has(result, BundleDiagnosticCode.CHUNK_MISSING));
        assertTrue(has(result, BundleDiagnosticCode.TOTAL_COUNT_MISMATCH));
    }

    @Test
    void alteredChunkIsDetectedByDigest() throws Exception {
        Path work = readySmallSet(350);
        byte[] bytes = Files.readAllBytes(work.resolve("chunk-000002.json"));
        String text = new String(bytes, java.nio.charset.StandardCharsets.UTF_8).replace("BULK_TEST", "BULK_TEXT");
        Files.write(work.resolve("chunk-000002.json"), text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Result result = verify(work);
        assertEquals(Status.INVALID, result.status());
        assertTrue(has(result, BundleDiagnosticCode.CHUNK_DIGEST_MISMATCH));
        assertTrue(has(result, BundleDiagnosticCode.CONTENT_HASH_MISMATCH), "record-level hash also localizes it");
    }

    @Test
    void alteredRecordIsCaughtEvenWhenTheSignerResignsTheManifest() throws Exception {
        Path work = readySmallSet(350);
        Path chunkFile = work.resolve("chunk-000001.json");
        Map<String, Object> chunk = read(chunkFile);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> records = (List<Map<String, Object>>) chunk.get("records");
        records.get(5).put("actorId", "mallory");
        byte[] altered = JSON.writeValueAsBytes(chunk);
        Files.write(chunkFile, altered);
        rewriteManifest(work, manifest -> {
            Map<String, Object> entry = chunkEntries(manifest).get(1);
            entry.put("bytes", altered.length);
            try {
                entry.put("sha256", sha256(altered));
            } catch (Exception exception) {
                throw new IllegalStateException(exception);
            }
        }, true);
        Result result = verify(work);
        assertEquals(Status.INVALID, result.status());
        assertFalse(has(result, BundleDiagnosticCode.BUNDLE_SIGNATURE_INVALID));
        assertFalse(has(result, BundleDiagnosticCode.CHUNK_DIGEST_MISMATCH));
        assertTrue(has(result, BundleDiagnosticCode.CONTENT_HASH_MISMATCH));
        assertEquals(101 + 5L, result.diagnostics().get(0).seq() + 0, "first diagnostic localizes the edited record");
    }

    @Test
    void reorderedChunksAreDetected() throws Exception {
        Path work = readySmallSet(350);
        Path first = work.resolve("chunk-000000.json");
        Path second = work.resolve("chunk-000001.json");
        Path swap = work.resolve("swap.tmp");
        Files.move(first, swap);
        Files.move(second, first);
        Files.move(swap, second);
        Result result = verify(work);
        assertEquals(Status.INVALID, result.status());
        assertTrue(has(result, BundleDiagnosticCode.CHUNK_DIGEST_MISMATCH));
        assertTrue(has(result, BundleDiagnosticCode.CHUNK_ORDER_INVALID));
    }

    @Test
    void reorderedManifestEntriesAreDetected() throws Exception {
        Path work = readySmallSet(350);
        rewriteManifest(work, manifest -> java.util.Collections.swap(chunkEntries(manifest), 0, 1), true);
        Result result = verify(work);
        assertEquals(Status.INVALID, result.status());
        assertTrue(has(result, BundleDiagnosticCode.CHUNK_ORDER_INVALID));
    }

    @Test
    void duplicatedChunkIsDetected() throws Exception {
        Path work = readySmallSet(350);
        Files.copy(work.resolve("chunk-000000.json"), work.resolve("chunk-000001.json"),
                StandardCopyOption.REPLACE_EXISTING);
        Result result = verify(work);
        assertEquals(Status.INVALID, result.status());
        assertTrue(has(result, BundleDiagnosticCode.CHUNK_DIGEST_MISMATCH));
        assertTrue(has(result, BundleDiagnosticCode.RECORD_ORDER_INVALID));
    }

    @Test
    void duplicateManifestEntryIsDetected() throws Exception {
        Path work = readySmallSet(350);
        rewriteManifest(work, manifest -> chunkEntries(manifest).set(1, new java.util.LinkedHashMap<>(
                chunkEntries(manifest).get(0))), true);
        Result result = verify(work);
        assertEquals(Status.INVALID, result.status());
        assertTrue(has(result, BundleDiagnosticCode.CHUNK_ORDER_INVALID));
    }

    @Test
    void unlistedChunkFileIsDetected() throws Exception {
        Path work = readySmallSet(350);
        Files.copy(work.resolve("chunk-000000.json"), work.resolve("chunk-000099.json"));
        Result result = verify(work);
        assertEquals(Status.INVALID, result.status());
        assertTrue(has(result, BundleDiagnosticCode.CHUNK_UNEXPECTED));
    }

    @Test
    void unsafeChunkNamesAreNeverResolved() throws Exception {
        Path work = readySmallSet(350);
        Path outside = directory.resolve("outside.json");
        Files.writeString(outside, "{}");
        rewriteManifest(work, manifest -> chunkEntries(manifest).get(0).put("name", "../outside.json"), true);
        Result result = verify(work);
        assertEquals(Status.INVALID, result.status());
        assertTrue(has(result, BundleDiagnosticCode.CHUNK_NAME_UNSAFE));
    }

    @Test
    void manifestTamperingWrongKeyAndCountsAreDetected() throws Exception {
        Path work = readySmallSet(350);
        Path manifestFile = work.resolve("manifest.json");
        byte[] original = Files.readAllBytes(manifestFile);

        Map<String, Object> altered = read(manifestFile);
        altered.put("totalRecords", 349);
        Files.write(manifestFile, JSON.writeValueAsBytes(altered));
        Result signature = verify(work);
        assertTrue(has(signature, BundleDiagnosticCode.BUNDLE_SIGNATURE_INVALID));
        assertTrue(has(signature, BundleDiagnosticCode.TOTAL_COUNT_MISMATCH));

        Files.write(manifestFile, original);
        String other = CheckpointSigner.fromFiles(directory.resolve("k2/private.pem"),
                directory.resolve("k2/public.b64"), "dev").publicKeyBase64();
        Result wrongKey = ExportSetVerifier.verify(manifestFile, Options.pinned(other));
        assertTrue(has(wrongKey, BundleDiagnosticCode.SIGNER_KEY_MISMATCH));

        rewriteManifest(work, manifest -> manifest.put("chunkCount", 3), true);
        assertTrue(has(verify(work), BundleDiagnosticCode.CHUNK_COUNT_MISMATCH));
    }

    @Test
    void chunkDigestInManifestCannotBeForgedWithoutTheSigningKey() throws Exception {
        Path work = readySmallSet(350);
        Map<String, Object> manifest = read(work.resolve("manifest.json"));
        chunkEntries(manifest).get(0).put("sha256", "0".repeat(64));
        Files.write(work.resolve("manifest.json"), JSON.writeValueAsBytes(manifest));
        Result result = verify(work);
        assertTrue(has(result, BundleDiagnosticCode.BUNDLE_SIGNATURE_INVALID));
        assertTrue(has(result, BundleDiagnosticCode.CHUNKS_DIGEST_MISMATCH));
    }

    @Test
    void verifierReadsOnlyBoundedChunkSizes() throws Exception {
        Path work = readySmallSet(350);
        Options tiny = pinned().withLimits(2_000, 1_000_000);
        Result result = ExportSetVerifier.verify(work.resolve("manifest.json"), tiny);
        assertEquals(Status.INVALID, result.status());
        assertTrue(has(result, BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED));

        Path huge = work.resolve("chunk-000000.json");
        Files.write(huge, new byte[600_000]);
        Result oversized = verify(work);
        assertTrue(has(oversized, BundleDiagnosticCode.CHUNK_DIGEST_MISMATCH));
    }

    @Test
    void cliVerifiesAManifestDirectory() throws Exception {
        Path work = readySmallSet(120);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
        int ok = com.auditlog.verifier.BundleVerifierCli.run(
                new String[] {"--manifest", work.resolve("manifest.json").toString(),
                    "--pinned-key", signer.publicKeyBase64()},
                new java.io.PrintStream(out), new java.io.PrintStream(err));
        assertEquals(0, ok, out.toString());
        assertTrue(out.toString().startsWith("VERIFIED"));

        Files.delete(work.resolve("chunk-000000.json"));
        int invalid = com.auditlog.verifier.BundleVerifierCli.run(
                new String[] {"--manifest", work.resolve("manifest.json").toString(),
                    "--pinned-key", signer.publicKeyBase64()},
                new java.io.PrintStream(out), new java.io.PrintStream(err));
        assertEquals(1, invalid);
        int usage = com.auditlog.verifier.BundleVerifierCli.run(
                new String[] {"--manifest", work.resolve("manifest.json").toString(),
                    "--bundle", "x", "--allow-self-asserted"},
                new java.io.PrintStream(out), new java.io.PrintStream(err));
        assertEquals(2, usage);
        assertNotNull(BundleVerifier.DEFAULT_MAX_BYTES);
    }

    // ------------------------------------------------------------------ restart, expiry, safety

    @Test
    void interruptedJobBecomesFailedOnRestartAndStagingIsRemoved() throws Exception {
        bulkSeed(5);
        ExportSetService first = service(Map.of(), runnable -> { });
        String id = (String) first.create(all(), "auditor").get("exportSetId");
        assertEquals("RUNNING", first.describe(id).get("status"));
        Path staging = exportRoot.resolve("staging").resolve(id);
        Files.createDirectories(staging);
        Files.writeString(staging.resolve("chunk-000000.json"), "partial");

        ExportSetService restarted = service(Map.of());
        Map<String, Object> descriptor = restarted.describe(id);
        assertEquals("FAILED", descriptor.get("status"));
        assertEquals("EXPORT_INTERRUPTED", descriptor.get("errorCode"));
        assertFalse(Files.exists(staging));
        assertEquals(0, ledgerCount("WHERE event_type = 'BUNDLE_EXPORTED'"));
    }

    @Test
    void committedButUnpublishedJobIsPublishedOnRestart() throws Exception {
        bulkSeed(250);
        ExportSetService first = service(Map.of("AUDIT_EXPORT_CHUNK_MAX_RECORDS", "100"));
        first.afterCommitHook = () -> {
            throw new ExportSetService.SimulatedCrash();
        };
        assertThrows(ExportSetService.SimulatedCrash.class, () -> first.create(all(), "auditor"));
        assertEquals(1, ledgerCount("WHERE event_type = 'BUNDLE_EXPORTED'"));

        String id;
        try (Stream<Path> jobs = Files.list(exportRoot.resolve("jobs"))) {
            String name = jobs.findFirst().orElseThrow().getFileName().toString();
            id = name.substring(0, name.length() - ".json".length());
        }
        assertFalse(Files.exists(readyDirectory(id)), "nothing is READY before publication");
        assertTrue(Files.exists(exportRoot.resolve("staging").resolve(id).resolve("manifest.json")));

        ExportSetService restarted = service(Map.of());
        Map<String, Object> descriptor = restarted.describe(id);
        assertEquals("READY", descriptor.get("status"));
        assertEquals(250L, ((Number) descriptor.get("totalRecords")).longValue());
        assertFalse(Files.exists(exportRoot.resolve("staging").resolve(id)));
        Result result = ExportSetVerifier.verify(restarted.manifestFile(id), pinned());
        assertEquals(Status.VERIFIED, result.status(), () -> result.diagnostics().toString());
    }

    @Test
    void stagedFilesAreRejectedOnRestartWhenAChunkWasDamaged() throws Exception {
        bulkSeed(250);
        ExportSetService first = service(Map.of("AUDIT_EXPORT_CHUNK_MAX_RECORDS", "100"));
        first.afterCommitHook = () -> {
            throw new ExportSetService.SimulatedCrash();
        };
        assertThrows(ExportSetService.SimulatedCrash.class, () -> first.create(all(), "auditor"));
        String id;
        try (Stream<Path> jobs = Files.list(exportRoot.resolve("jobs"))) {
            String name = jobs.findFirst().orElseThrow().getFileName().toString();
            id = name.substring(0, name.length() - ".json".length());
        }
        Files.writeString(exportRoot.resolve("staging").resolve(id).resolve("chunk-000001.json"), "damaged");

        Map<String, Object> descriptor = service(Map.of()).describe(id);
        assertEquals("FAILED", descriptor.get("status"));
        assertFalse(Files.exists(readyDirectory(id)));
    }

    @Test
    void orphanedArtifactsAreRemovedOnRestart() throws Exception {
        service(Map.of());
        Path orphanStaging = exportRoot.resolve("staging").resolve("11111111-2222-3333-4444-555555555555");
        Path orphanReady = exportRoot.resolve("ready").resolve("66666666-7777-8888-9999-000000000000");
        Files.createDirectories(orphanStaging);
        Files.createDirectories(orphanReady);
        Files.writeString(orphanStaging.resolve("chunk-000000.json"), "x");
        Files.writeString(exportRoot.resolve("jobs").resolve("stale.json.1234.tmp"), "x");
        service(Map.of());
        assertFalse(Files.exists(orphanStaging));
        assertFalse(Files.exists(orphanReady));
        assertFalse(Files.exists(exportRoot.resolve("jobs").resolve("stale.json.1234.tmp")));
    }

    @Test
    void expiredSetsAreRemovedAndReportedGone() throws Exception {
        bulkSeed(10);
        ExportSetService service = service(Map.of("AUDIT_EXPORT_SET_TTL_SECONDS", "60"));
        Map<String, Object> descriptor = service.create(all(), "auditor");
        String id = (String) descriptor.get("exportSetId");
        assertEquals("READY", descriptor.get("status"));
        assertNotNull(service.chunkFile(id, "chunk-000000.json"));

        clock.now = START.plusSeconds(61);
        assertEquals("EXPIRED", service.describe(id).get("status"));
        assertFalse(Files.exists(readyDirectory(id)));
        assertEquals(Kind.GONE, assertThrows(ExportSetException.class, () -> service.manifestFile(id)).kind());
        assertEquals(Kind.GONE,
                assertThrows(ExportSetException.class, () -> service.chunkFile(id, "chunk-000000.json")).kind());
    }

    @Test
    void downloadPathsAreStrictlyValidated() throws Exception {
        bulkSeed(10);
        ExportSetService service = service(Map.of());
        String id = (String) service.create(all(), "auditor").get("exportSetId");
        for (String name : new String[] {"../manifest.json", "manifest.json", "chunk-000000.json/..",
            "chunk-0.json", "chunk-000000.JSON", "..\\manifest.json", "chunk-000001.json", "chunk-999999.json",
            "", "chunk-000000.json\u0000"}) {
            ExportSetException failure =
                    assertThrows(ExportSetException.class, () -> service.chunkFile(id, name), name);
            assertEquals(Kind.NOT_FOUND, failure.kind(), name);
        }
        for (String badId : new String[] {"../" + id, "..", id.toUpperCase(), id + "/../x", "", "not-a-uuid"}) {
            assertEquals(Kind.NOT_FOUND,
                    assertThrows(ExportSetException.class, () -> service.describe(badId), badId).kind());
            assertEquals(Kind.NOT_FOUND,
                    assertThrows(ExportSetException.class, () -> service.manifestFile(badId), badId).kind());
        }
        assertNotNull(service.chunkFile(id, "chunk-000000.json"));
        assertEquals(Kind.NOT_FOUND, assertThrows(ExportSetException.class,
                () -> service.describe("00000000-0000-0000-0000-000000000000")).kind());
    }

    @Test
    void configurationRejectsUnsafeExportSettings() {
        for (Map<String, String> bad : List.of(
                Map.of("AUDIT_EXPORT_CHUNK_MAX_RECORDS", "0"),
                Map.of("AUDIT_EXPORT_CHUNK_MAX_RECORDS", "100001"),
                Map.of("AUDIT_EXPORT_CHUNK_MAX_BYTES", "-1"),
                Map.of("AUDIT_EXPORT_CHUNK_MAX_BYTES", "67108865"),
                Map.of("AUDIT_EXPORT_SET_MAX_RECORDS", "10000001"),
                Map.of("AUDIT_EXPORT_SET_MAX_RECORDS", "abc"),
                Map.of("AUDIT_EXPORT_SET_TTL_SECONDS", "59"),
                Map.of("AUDIT_EXPORT_SET_TTL_SECONDS", "2592001"),
                Map.of("AUDIT_EXPORT_DIR", " "))) {
            assertThrows(IllegalArgumentException.class, () -> config(bad), bad.toString());
        }
        AuditConfiguration defaults = AuditConfiguration.fromEnvironment(Map.of());
        assertEquals(1000, defaults.exportChunkMaxRecords());
        assertEquals(8 * 1024 * 1024, defaults.exportChunkMaxBytes());
        assertEquals(1_000_000L, defaults.exportSetMaxRecords());
        assertEquals(86_400L, defaults.exportSetTtlSeconds());
        assertTrue(defaults.exportDirectory().endsWith("exports"));
    }
}
