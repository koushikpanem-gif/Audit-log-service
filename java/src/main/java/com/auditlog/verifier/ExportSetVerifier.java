package com.auditlog.verifier;

import static com.auditlog.verifier.BundleVerifier.asMap;
import static com.auditlog.verifier.BundleVerifier.isHash;
import static com.auditlog.verifier.BundleVerifier.sha256Hex;

import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.V1Hashes;
import com.auditlog.domain.BundleCompleteness;
import com.auditlog.domain.BundleDiagnosticCode;
import com.auditlog.domain.BundleSelection;
import com.auditlog.verifier.BundleVerifier.Options;
import com.auditlog.verifier.BundleVerifier.Result;
import com.auditlog.verifier.BundleVerifier.Run;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Offline verifier for audit-export-set-manifest/v1 sets stored in one directory (manifest.json
 * plus chunk-NNNNNN.json files). It reads one chunk at a time with hard byte limits, so memory is
 * bounded by the largest permitted chunk, and it never follows names outside the directory.
 *
 * <p>Like the small-bundle verifier it needs an out-of-band pinned key by default and gives no
 * proof about omitted records or upstream capture; the manifest signature only asserts completeness.
 */
public final class ExportSetVerifier {

    public static final int DEFAULT_MAX_RECORDS = 10_000_000;
    public static final String MANIFEST_FORMAT = "audit-export-set-manifest/v1";
    public static final String CHUNK_FORMAT = "audit-export-chunk/v1";
    public static final int MAX_CHUNKS = 100_000;
    public static final Pattern CHUNK_NAME = Pattern.compile("chunk-[0-9]{6}\\.json");

    private static final Set<String> MANIFEST_FIELDS = Set.of(
            "format", "exportSetId", "purpose", "ledgerId", "hashAlgorithm", "hashVersion",
            "genesisHash", "signatureAlgorithm", "createdAt", "expiresAt", "exportedBy", "selection",
            "completeness", "selectionHead", "headCheckpoint", "totalRecords", "chunkCount",
            "chunkLimits", "chunks", "chunksDigest", "exclusions", "signer", "signature");
    private static final Set<String> CHUNK_ENTRY_FIELDS = Set.of(
            "index", "name", "recordCount", "firstSeq", "lastSeq", "bytes", "sha256");
    private static final Set<String> CHUNK_FIELDS = Set.of("format", "exportSetId", "index", "records");
    private static final Map<String, String> EXCLUSIONS = Map.of(
            "archivedRecords", "EXCLUDED",
            "nonMatchingRecords", "EXCLUDED",
            "recordsAfterSelectionHead", "EXCLUDED",
            "upstreamCoverage", "NOT_PROVEN");
    private static final Pattern SIGNATURE = Pattern.compile("[A-Za-z0-9+/]{86}==");
    private static final long MAX_SAFE = BundleSelection.MAX_SAFE;

    private ExportSetVerifier() {
    }

    /** Verifies the set whose manifest is manifestFile; chunks are resolved in the same directory. */
    public static Result verify(Path manifestFile, Options options) {
        Run run = BundleVerifier.prepare(options);
        if (!run.begin()) {
            return run.result();
        }
        Path directory = manifestFile.toAbsolutePath().normalize().getParent();
        byte[] manifestBytes;
        try {
            manifestBytes = readBounded(manifestFile, options.maxBytes());
        } catch (IOException exception) {
            throw new BundleVerifier.InputException("Manifest file could not be read", exception);
        }
        if (manifestBytes == null) {
            run.fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, null,
                    "Manifest exceeds the configured byte limit");
            return run.result();
        }
        Map<String, Object> manifest = run.parse(manifestBytes);
        if (manifest == null || !structure(run, manifest)) {
            return run.result();
        }
        run.checkTrustAndSignature(manifest);
        run.checkGenesis(manifest);
        Map<String, Object> head = asMap(manifest.get("headCheckpoint"));
        run.checkCheckpoint(manifest, head);

        List<Map<String, Object>> chunks = new ArrayList<>();
        for (Object entry : (List<?>) manifest.get("chunks")) {
            chunks.add(asMap(entry));
        }
        checkManifestConsistency(run, manifest, head, chunks);
        verifyChunks(run, manifest, head, chunks, directory);
        return run.result();
    }

    // ------------------------------------------------------------------ manifest shape

    private static boolean structure(Run run, Map<String, Object> manifest) {
        Object format = manifest.get("format");
        if (format instanceof String text && !text.equals(MANIFEST_FORMAT)) {
            run.fail(BundleDiagnosticCode.UNSUPPORTED_FORMAT, null, "/format", "Unsupported manifest format");
            return false;
        }
        if (!manifest.keySet().equals(MANIFEST_FIELDS) || !MANIFEST_FORMAT.equals(format)) {
            run.schema(null, "Manifest must have exactly the v1 fields");
            return false;
        }
        boolean ok = true;
        run.ledgerId = BundleVerifier.text(manifest.get("ledgerId"));
        run.bundleId = BundleVerifier.text(manifest.get("exportSetId"));
        for (String field : List.of("exportSetId", "ledgerId", "exportedBy")) {
            if (!(manifest.get(field) instanceof String text) || text.isEmpty()) {
                run.schema("/" + field, field + " must be a non-empty string");
                ok = false;
            }
        }
        for (String field : List.of("createdAt", "expiresAt")) {
            if (!(manifest.get(field) instanceof String text) || !BundleSelection.isCanonicalTimestamp(text)) {
                run.schema("/" + field, field + " must be a UTC microsecond timestamp");
                ok = false;
            }
        }
        if (ok && ((String) manifest.get("expiresAt")).compareTo((String) manifest.get("createdAt")) <= 0) {
            run.schema("/expiresAt", "expiresAt must be after createdAt");
            ok = false;
        }
        if (!"EXPORT".equals(manifest.get("purpose"))) {
            run.schema("/purpose", "purpose must be EXPORT");
            ok = false;
        }
        ok &= algorithm(run, manifest, "hashAlgorithm", "SHA-256");
        ok &= algorithm(run, manifest, "signatureAlgorithm", "Ed25519");
        if (!(manifest.get("hashVersion") instanceof Long version)) {
            run.schema("/hashVersion", "hashVersion must be an integer");
            ok = false;
        } else if (version != 1L) {
            run.fail(BundleDiagnosticCode.UNSUPPORTED_ALGORITHM, null, "/hashVersion", "Unsupported hash version");
            ok = false;
        }
        for (String field : List.of("genesisHash", "chunksDigest")) {
            if (!isHash(manifest.get(field))) {
                run.schema("/" + field, field + " must be 64 lowercase hex");
                ok = false;
            }
        }
        if (manifest.get("selection") instanceof Map<?, ?> selection) {
            try {
                BundleSelection parsed = BundleSelection.fromMap(selection);
                if (parsed.seqFrom() != null || parsed.seqTo() != null) {
                    run.schema("/selection", "an export set selection has no sequence bounds");
                    ok = false;
                }
            } catch (IllegalArgumentException exception) {
                run.schema("/selection", exception.getMessage());
                ok = false;
            }
        } else {
            run.schema("/selection", "selection must be an object");
            ok = false;
        }
        if (manifest.get("completeness") instanceof Map<?, ?> completeness) {
            try {
                BundleCompleteness.fromMap(completeness);
            } catch (IllegalArgumentException exception) {
                run.schema("/completeness", exception.getMessage());
                ok = false;
            }
        } else {
            run.schema("/completeness", "completeness must be an object");
            ok = false;
        }
        if (!(manifest.get("selectionHead") instanceof Map<?, ?> selectionHead)
                || !selectionHead.keySet().equals(Set.of("seq", "chainHash"))
                || !(selectionHead.get("seq") instanceof Long seq) || seq < 0 || seq > MAX_SAFE
                || !isHash(selectionHead.get("chainHash"))) {
            run.schema("/selectionHead", "selectionHead must be {seq >= 0, chainHash}");
            ok = false;
        }
        for (String field : List.of("totalRecords", "chunkCount")) {
            if (!(manifest.get(field) instanceof Long number) || number < 0 || number > MAX_SAFE) {
                run.schema("/" + field, field + " must be a safe nonnegative integer");
                ok = false;
            }
        }
        if (!(manifest.get("chunkLimits") instanceof Map<?, ?> limits)
                || !limits.keySet().equals(Set.of("maxRecords", "maxBytes"))
                || !(limits.get("maxRecords") instanceof Long maxRecords) || maxRecords < 1
                || !(limits.get("maxBytes") instanceof Long maxBytes) || maxBytes < 1) {
            run.schema("/chunkLimits", "chunkLimits must be {maxRecords >= 1, maxBytes >= 1}");
            ok = false;
        }
        if (!(manifest.get("exclusions") instanceof Map<?, ?> exclusions) || !exclusions.equals(EXCLUSIONS)) {
            run.schema("/exclusions", "exclusions do not match the fixed v1 scope statement");
            ok = false;
        }
        if (manifest.get("chunks") instanceof List<?> list) {
            if (list.size() > MAX_CHUNKS) {
                run.fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, "/chunks",
                        "Manifest lists more chunks than the protocol allows");
                ok = false;
            } else {
                for (int index = 0; index < list.size(); index++) {
                    ok &= chunkEntryShape(run, list.get(index), "/chunks/" + index);
                }
            }
        } else {
            run.schema("/chunks", "chunks must be an array");
            ok = false;
        }
        ok &= run.checkpointShape(manifest.get("headCheckpoint"));
        ok &= run.signerShape(manifest.get("signer"));
        if (!(manifest.get("signature") instanceof String signature) || !SIGNATURE.matcher(signature).matches()) {
            run.schema("/signature", "signature must be canonical Base64 of 64 bytes");
            ok = false;
        }
        return ok;
    }

    private static boolean chunkEntryShape(Run run, Object item, String pointer) {
        if (!(item instanceof Map<?, ?> entry) || !entry.keySet().equals(CHUNK_ENTRY_FIELDS)) {
            run.schema(pointer, "Chunk entry must have exactly the v1 fields");
            return false;
        }
        boolean ok = true;
        for (String field : List.of("index", "recordCount", "firstSeq", "lastSeq", "bytes")) {
            if (!(entry.get(field) instanceof Long number) || number < 0 || number > MAX_SAFE) {
                run.schema(pointer + "/" + field, field + " must be a safe nonnegative integer");
                ok = false;
            }
        }
        if (!(entry.get("name") instanceof String)) {
            run.schema(pointer + "/name", "name must be a string");
            ok = false;
        }
        if (!isHash(entry.get("sha256"))) {
            run.schema(pointer + "/sha256", "sha256 must be 64 lowercase hex");
            ok = false;
        }
        return ok;
    }

    private static boolean algorithm(Run run, Map<String, Object> manifest, String field, String expected) {
        if (!(manifest.get(field) instanceof String text)) {
            run.schema("/" + field, field + " must be a string");
            return false;
        }
        if (!expected.equals(text)) {
            run.fail(BundleDiagnosticCode.UNSUPPORTED_ALGORITHM, null, "/" + field, "Unsupported " + field);
            return false;
        }
        return true;
    }

    // ------------------------------------------------------------------ manifest consistency

    private static void checkManifestConsistency(
            Run run, Map<String, Object> manifest, Map<String, Object> head, List<Map<String, Object>> chunks) {
        Options options = run.options();
        long selectionSeq = ((Number) asMap(manifest.get("selectionHead")).get("seq")).longValue();
        long throughSeq = ((Number) asMap(manifest.get("completeness")).get("throughSeq")).longValue();
        if (selectionSeq != throughSeq) {
            run.fail(BundleDiagnosticCode.CHECKPOINT_MISMATCH, null, "/selectionHead/seq",
                    "selectionHead.seq differs from completeness.throughSeq");
        }
        if (selectionSeq >= ((Number) head.get("seq")).longValue()) {
            run.fail(BundleDiagnosticCode.CHECKPOINT_MISMATCH, null, "/headCheckpoint/seq",
                    "The post-event head must be newer than the selection head");
        }
        if (selectionSeq == 0 && !V1Hashes.genesisHash(run.ledgerId)
                .equals(asMap(manifest.get("selectionHead")).get("chainHash"))) {
            run.fail(BundleDiagnosticCode.GENESIS_MISMATCH, null, "/selectionHead/chainHash",
                    "An empty selection head must be the genesis hash");
        }
        long declaredTotal = ((Number) manifest.get("totalRecords")).longValue();
        long sum = 0;
        for (Map<String, Object> chunk : chunks) {
            sum += ((Number) chunk.get("recordCount")).longValue();
        }
        if (declaredTotal != sum) {
            run.fail(BundleDiagnosticCode.TOTAL_COUNT_MISMATCH, null, "/totalRecords",
                    "totalRecords does not equal the sum of the chunk record counts");
        }
        if (declaredTotal > options.maxRecords()) {
            run.fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, "/totalRecords",
                    "The set exceeds the verifier record limit");
        }
        if (((Number) manifest.get("chunkCount")).longValue() != chunks.size()) {
            run.fail(BundleDiagnosticCode.CHUNK_COUNT_MISMATCH, null, "/chunkCount",
                    "chunkCount does not equal the number of listed chunks");
        }
        try {
            String digest = sha256Hex(CanonicalJson.canonicalize(
                    chunks, CanonicalJson.MAX_DOCUMENT_DEPTH, options.maxBytes()));
            if (!digest.equals(manifest.get("chunksDigest"))) {
                run.fail(BundleDiagnosticCode.CHUNKS_DIGEST_MISMATCH, null, "/chunksDigest",
                        "chunksDigest does not match the ordered chunk list");
            }
        } catch (IllegalArgumentException exception) {
            run.fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, "/chunks",
                    "The chunk list cannot be canonicalized within the verifier limits");
        }
    }

    private static void verifyChunks(
            Run run, Map<String, Object> manifest, Map<String, Object> head,
            List<Map<String, Object>> chunks, Path directory) {
        Options options = run.options();
        BundleSelection selection = BundleSelection.fromMap(asMap(manifest.get("selection")));
        Map<String, Object> limits = asMap(manifest.get("chunkLimits"));
        long maxChunkRecords = ((Number) limits.get("maxRecords")).longValue();
        long maxChunkBytes = ((Number) limits.get("maxBytes")).longValue();
        long throughSeq = ((Number) asMap(manifest.get("completeness")).get("throughSeq")).longValue();
        long headSeq = ((Number) head.get("seq")).longValue();
        String headHash = head.get("chainHash").toString();
        String setId = (String) manifest.get("exportSetId");

        Set<String> listed = new HashSet<>();
        run.resetChain();
        long seen = 0;
        for (int position = 0; position < chunks.size(); position++) {
            Map<String, Object> entry = chunks.get(position);
            String pointer = "/chunks/" + position;
            String name = (String) entry.get("name");
            long declaredIndex = ((Number) entry.get("index")).longValue();
            if (!CHUNK_NAME.matcher(name).matches()) {
                run.fail(BundleDiagnosticCode.CHUNK_NAME_UNSAFE, null, pointer + "/name",
                        "Chunk name does not match the protocol pattern");
                run.resetChain();
                continue;
            }
            if (declaredIndex != position || !name.equals(String.format("chunk-%06d.json", position))) {
                run.fail(BundleDiagnosticCode.CHUNK_ORDER_INVALID, null, pointer,
                        "Chunk entries must be consecutively indexed and named");
            }
            if (!listed.add(name)) {
                run.fail(BundleDiagnosticCode.CHUNK_ORDER_INVALID, null, pointer + "/name",
                        "A chunk is listed more than once");
                run.resetChain();
                continue;
            }
            long declaredBytes = ((Number) entry.get("bytes")).longValue();
            if (declaredBytes > maxChunkBytes || declaredBytes > options.maxBytes()) {
                run.fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, pointer + "/bytes",
                        "A chunk exceeds the byte limit of the set or of the verifier");
                run.resetChain();
                continue;
            }
            long recordCount = ((Number) entry.get("recordCount")).longValue();
            if (recordCount > maxChunkRecords) {
                run.fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, pointer + "/recordCount",
                        "A chunk exceeds the record limit of the set");
            }
            Path file = directory.resolve(name).normalize();
            if (!file.getParent().equals(directory) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                run.fail(BundleDiagnosticCode.CHUNK_MISSING, null, pointer + "/name", "A listed chunk file is missing");
                run.resetChain();
                continue;
            }
            byte[] bytes;
            try {
                bytes = readBounded(file, (int) declaredBytes);
            } catch (IOException exception) {
                run.fail(BundleDiagnosticCode.CHUNK_MISSING, null, pointer + "/name", "A chunk file cannot be read");
                run.resetChain();
                continue;
            }
            if (bytes == null || bytes.length != declaredBytes || !sha256Hex(bytes).equals(entry.get("sha256"))) {
                run.fail(BundleDiagnosticCode.CHUNK_DIGEST_MISMATCH, null, pointer,
                        "A chunk file differs from its manifest size or digest");
                if (bytes == null) {
                    run.resetChain();
                    continue;
                }
            }
            seen += checkChunkContent(run, bytes, entry, position, setId, selection, throughSeq, headSeq, headHash,
                    maxChunkRecords);
        }
        run.recordCount = seen;
        if (seen != ((Number) manifest.get("totalRecords")).longValue()) {
            run.fail(BundleDiagnosticCode.TOTAL_COUNT_MISMATCH, null, "/totalRecords",
                    "The records found in the chunks differ from totalRecords");
        }
        checkUnexpectedFiles(run, directory, listed);
    }

    private static long checkChunkContent(
            Run run, byte[] bytes, Map<String, Object> entry, int position, String setId,
            BundleSelection selection, long throughSeq, long headSeq, String headHash, long maxChunkRecords) {
        String pointer = "/chunks/" + position;
        Map<String, Object> chunk = run.parse(bytes);
        if (chunk == null) {
            run.resetChain();
            return 0;
        }
        if (!chunk.keySet().equals(CHUNK_FIELDS)
                || !CHUNK_FORMAT.equals(chunk.get("format"))
                || !(chunk.get("records") instanceof List<?>)) {
            run.schema(pointer, "Chunk must have exactly the v1 chunk fields");
            run.resetChain();
            return 0;
        }
        if (!setId.equals(chunk.get("exportSetId")) || !Long.valueOf(position).equals(chunk.get("index"))) {
            run.fail(BundleDiagnosticCode.CHUNK_ORDER_INVALID, null, pointer,
                    "Chunk does not belong to this set at this position");
        }
        List<?> records = (List<?>) chunk.get("records");
        if (records.size() > maxChunkRecords) {
            run.fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, pointer + "/records",
                    "A chunk holds more records than the set limit");
            run.resetChain();
            return 0;
        }
        if (records.size() != ((Number) entry.get("recordCount")).longValue()) {
            run.fail(BundleDiagnosticCode.CHUNK_COUNT_MISMATCH, null, pointer + "/recordCount",
                    "A chunk's record count differs from the manifest");
        }
        run.checkRecordChunk(records, pointer + "/records/", selection, throughSeq, headSeq, headHash);
        if (!records.isEmpty() && records.get(0) instanceof Map<?, ?> first
                && records.get(records.size() - 1) instanceof Map<?, ?> last
                && (!entry.get("firstSeq").equals(first.get("seq")) || !entry.get("lastSeq").equals(last.get("seq")))) {
            run.fail(BundleDiagnosticCode.CHUNK_ORDER_INVALID, null, pointer,
                    "A chunk's first or last sequence differs from the manifest");
        }
        return records.size();
    }

    private static void checkUnexpectedFiles(Run run, Path directory, Set<String> listed) {
        int inspected = 0;
        try (DirectoryStream<Path> files = Files.newDirectoryStream(directory)) {
            for (Path file : files) {
                String name = file.getFileName().toString();
                if (++inspected > MAX_CHUNKS + 16) {
                    run.fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, null,
                            "The directory holds too many files to inspect");
                    return;
                }
                if (CHUNK_NAME.matcher(name).matches() && !listed.contains(name)) {
                    run.fail(BundleDiagnosticCode.CHUNK_UNEXPECTED, null, null,
                            "A chunk file exists that the manifest does not list");
                }
            }
        } catch (IOException exception) {
            throw new BundleVerifier.InputException("Set directory could not be listed", exception);
        }
    }

    /** Reads at most limit bytes; null means the file is larger than the limit. */
    private static byte[] readBounded(Path file, int limit) throws IOException {
        try (InputStream stream = Files.newInputStream(file)) {
            byte[] bytes = stream.readNBytes(limit + 1);
            return bytes.length > limit ? null : bytes;
        }
    }
}
