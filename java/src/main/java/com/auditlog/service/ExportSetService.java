package com.auditlog.service;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.core.crypto.V1Hashes;
import com.auditlog.domain.BundleCompleteness;
import com.auditlog.domain.BundleSelection;
import com.auditlog.store.AuditRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Bounded, complete bulk exports as signed audit-export-set-manifest/v1 sets of immutable chunks.
 *
 * <p>Phase 1 streams the selection from ONE read snapshot (fixed selection head) into chunk files
 * bounded by record count and bytes; memory never exceeds one chunk. Phase 2 appends the
 * BUNDLE_EXPORTED event and checkpoint in one write transaction and writes the signed manifest.
 * The set becomes READY only after the staging directory is atomically moved to ready/. Jobs and
 * files are filesystem state, so restart recovery reconciles each RUNNING job against the ledger.
 * Nothing is truncated silently: any limit breach FAILS the job with an explicit error code.
 */
public final class ExportSetService {

    public static final String MANIFEST_FORMAT = "audit-export-set-manifest/v1";
    public static final String CHUNK_FORMAT = "audit-export-chunk/v1";
    public static final String DESCRIPTOR_FORMAT = "audit-export-set-descriptor/v1";
    public static final String MANIFEST_NAME = "manifest.json";
    public static final Pattern CHUNK_NAME = Pattern.compile("chunk-[0-9]{6}\\.json");
    public static final int MAX_CHUNKS = 100_000;
    public static final int MAX_ACTIVE_JOBS = 16;
    /** Bytes reserved per chunk for the envelope around the records array. */
    static final int CHUNK_OVERHEAD = 512;

    private static final Pattern SET_ID =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long MAX_JOB_FILE_BYTES = 64 * 1024;

    /** Failure classes; the web layer maps these to HTTP statuses. */
    public enum Kind { INVALID, NOT_FOUND, NOT_READY, GONE, BUSY, FAILED }

    public static final class ExportSetException extends RuntimeException {
        private final Kind kind;
        private final String code;

        public ExportSetException(Kind kind, String code, String message) {
            super(message);
            this.kind = kind;
            this.code = code;
        }

        public Kind kind() {
            return kind;
        }

        public String code() {
            return code;
        }
    }

    /** Thrown by test hooks to simulate a process crash; never caught by the job runner. */
    static final class SimulatedCrash extends Error {
        private static final long serialVersionUID = 1L;
    }

    private final AuditRepository repository;
    private final AuditConfiguration configuration;
    private final CheckpointSigner signer;
    private final AppendEventService appendService;
    private final Clock clock;
    private final Executor executor;
    private final Path jobsDirectory;
    private final Path stagingDirectory;
    private final Path readyDirectory;
    private final AtomicInteger activeJobs = new AtomicInteger();
    /** Test hook invoked after the ledger commit and before publication. */
    volatile Runnable afterCommitHook;

    public ExportSetService(
            AuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService,
            Clock clock,
            Executor executor) {
        this.repository = repository;
        this.configuration = configuration;
        this.signer = signer;
        this.appendService = appendService;
        this.clock = clock;
        this.executor = executor;
        Path root = configuration.exportDirectory().toAbsolutePath().normalize();
        this.jobsDirectory = root.resolve("jobs");
        this.stagingDirectory = root.resolve("staging");
        this.readyDirectory = root.resolve("ready");
        try {
            Files.createDirectories(jobsDirectory);
            Files.createDirectories(stagingDirectory);
            Files.createDirectories(readyDirectory);
        } catch (IOException exception) {
            throw new UncheckedIOException("Export directory cannot be created", exception);
        }
        recover();
    }

    // ---------------------------------------------------------------- public API

    /** Creates a durable job and returns its descriptor (status RUNNING, or already READY/FAILED). */
    public Map<String, Object> create(BundleSelection selection, String requestedBy) {
        if (selection == null || requestedBy == null || requestedBy.isBlank()) {
            throw new IllegalArgumentException("selection and requestedBy are required");
        }
        if (selection.seqFrom() != null || selection.seqTo() != null) {
            throw new IllegalArgumentException("An export set does not accept sequence bounds");
        }
        if (activeJobs.incrementAndGet() > MAX_ACTIVE_JOBS) {
            activeJobs.decrementAndGet();
            throw new ExportSetException(Kind.BUSY, "EXPORT_SET_BUSY",
                    "Too many export jobs are running; retry later");
        }
        String id = UUID.randomUUID().toString();
        try {
            Map<String, Object> job = new LinkedHashMap<>();
            job.put("exportSetId", id);
            job.put("status", "RUNNING");
            job.put("requestedBy", requestedBy);
            job.put("selection", selection.toMap());
            job.put("createdAt", BundleSelection.normalizeTimestamp(
                    clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MICROS).toString()));
            writeJob(id, job);
        } catch (IOException exception) {
            activeJobs.decrementAndGet();
            throw new ExportSetException(Kind.FAILED, "EXPORT_IO_FAILURE", "Export job could not be stored");
        }
        try {
            executor.execute(() -> runJob(id, selection, requestedBy));
        } catch (RuntimeException exception) {
            activeJobs.decrementAndGet();
            fail(id, "EXPORT_REJECTED", "Export job could not be scheduled");
        }
        return describe(id);
    }

    /** Current descriptor of a job; READY sets past their expiry are purged and reported as gone. */
    public Map<String, Object> describe(String id) {
        Map<String, Object> job = readJob(requireId(id));
        if ("READY".equals(job.get("status")) && isExpired(job)) {
            expire(id, job);
            job = readJob(id);
        }
        Map<String, Object> descriptor = new LinkedHashMap<>();
        descriptor.put("format", DESCRIPTOR_FORMAT);
        descriptor.put("exportSetId", id);
        descriptor.put("status", job.get("status"));
        descriptor.put("purpose", "EXPORT");
        descriptor.put("requestedBy", job.get("requestedBy"));
        descriptor.put("selection", job.get("selection"));
        descriptor.put("createdAt", job.get("createdAt"));
        if ("READY".equals(job.get("status"))) {
            descriptor.put("expiresAt", job.get("expiresAt"));
            descriptor.put("totalRecords", job.get("totalRecords"));
            descriptor.put("chunkCount", job.get("chunkCount"));
            descriptor.put("selectionHeadSeq", job.get("selectionHeadSeq"));
            descriptor.put("postEventHeadSeq", job.get("postEventHeadSeq"));
            descriptor.put("manifestSha256", job.get("manifestSha256"));
            descriptor.put("manifestUrl", "/audit/export-sets/" + id + "/manifest");
            descriptor.put("chunkUrlTemplate", "/audit/export-sets/" + id + "/chunks/{name}");
            descriptor.put("chunkNamePattern", CHUNK_NAME.pattern());
        } else if ("FAILED".equals(job.get("status"))) {
            descriptor.put("errorCode", job.get("errorCode"));
            descriptor.put("message", job.get("message"));
        }
        return descriptor;
    }

    /** Resolves the manifest file of a READY set. */
    public Path manifestFile(String id) {
        Map<String, Object> job = requireReady(id);
        return safeFile(readyDirectory.resolve(id), MANIFEST_NAME, job);
    }

    /** Resolves a chunk file of a READY set after strict name, index and containment checks. */
    public Path chunkFile(String id, String name) {
        Map<String, Object> job = requireReady(id);
        if (name == null || !CHUNK_NAME.matcher(name).matches()) {
            throw new ExportSetException(Kind.NOT_FOUND, "NOT_FOUND", "Chunk not found");
        }
        long index = Long.parseLong(name.substring("chunk-".length(), "chunk-".length() + 6));
        if (index >= ((Number) job.get("chunkCount")).longValue()) {
            throw new ExportSetException(Kind.NOT_FOUND, "NOT_FOUND", "Chunk not found");
        }
        return safeFile(readyDirectory.resolve(id), name, job);
    }

    // ---------------------------------------------------------------- job execution

    private void runJob(String id, BundleSelection selection, String requestedBy) {
        boolean phaseTwo = false;
        try {
            StagedChunks staged = stage(id, selection);
            phaseTwo = true;
            commitAndSign(id, selection, requestedBy, staged);
            Runnable hook = afterCommitHook;
            if (hook != null) {
                hook.run();
            }
            publish(id);
        } catch (ExportSetException exception) {
            if (phaseTwo) {
                reconcile(id);
            } else {
                fail(id, exception.code(), exception.getMessage());
            }
        } catch (Exception exception) {
            if (phaseTwo) {
                reconcile(id);
            } else {
                fail(id, "EXPORT_FAILED", "The export set could not be produced");
            }
        } finally {
            activeJobs.decrementAndGet();
        }
    }

    private record StagedChunks(long throughSeq, String selectionHeadHash, List<Map<String, Object>> chunks,
            long total) { }

    private StagedChunks stage(String id, BundleSelection selection) throws SQLException {
        Path directory = stagingDirectory.resolve(id);
        try {
            Files.createDirectories(directory);
        } catch (IOException exception) {
            throw new ExportSetException(Kind.FAILED, "EXPORT_IO_FAILURE", "Staging area unavailable");
        }
        int chunkMaxRecords = configuration.exportChunkMaxRecords();
        int chunkMaxBytes = configuration.exportChunkMaxBytes();
        return repository.readSnapshot(connection -> {
            long through = 0;
            try (Statement statement = connection.createStatement();
                    ResultSet result = statement.executeQuery("SELECT MAX(seq) FROM audit_events")) {
                if (result.next()) {
                    through = result.getLong(1);
                }
            }
            String headHash = through == 0
                    ? V1Hashes.genesisHash(configuration.ledgerId()) : chainHashAt(connection, through);
            List<Map<String, Object>> chunks = new ArrayList<>();
            List<Map<String, Object>> buffer = new ArrayList<>();
            long bufferBytes = CHUNK_OVERHEAD;
            long total = 0;
            try (PreparedStatement statement =
                            ExportBundleService.prepareSelection(connection, selection, through, null);
                    ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Map<String, Object> record = ExportBundleService.readRecord(connection, rows);
                    long length = CanonicalJson.canonicalize(
                            record, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE).length + 1L;
                    if (CHUNK_OVERHEAD + length > chunkMaxBytes) {
                        throw new ExportSetException(Kind.INVALID, "EXPORT_RECORD_TOO_LARGE",
                                "A single record exceeds AUDIT_EXPORT_CHUNK_MAX_BYTES; no record is skipped");
                    }
                    if (!buffer.isEmpty()
                            && (buffer.size() >= chunkMaxRecords || bufferBytes + length > chunkMaxBytes)) {
                        chunks.add(writeChunk(directory, id, chunks.size(), buffer, chunkMaxBytes));
                        buffer.clear();
                        bufferBytes = CHUNK_OVERHEAD;
                    }
                    buffer.add(record);
                    bufferBytes += length;
                    total++;
                    if (total > configuration.exportSetMaxRecords()) {
                        throw new ExportSetException(Kind.INVALID, "EXPORT_SET_TOO_LARGE",
                                "Selection exceeds AUDIT_EXPORT_SET_MAX_RECORDS; narrow the selection");
                    }
                }
            }
            if (!buffer.isEmpty()) {
                chunks.add(writeChunk(directory, id, chunks.size(), buffer, chunkMaxBytes));
            }
            return new StagedChunks(through, headHash, chunks, total);
        });
    }

    private Map<String, Object> writeChunk(
            Path directory, String id, int index, List<Map<String, Object>> records, int maxBytes) {
        if (index >= MAX_CHUNKS) {
            throw new ExportSetException(Kind.INVALID, "EXPORT_TOO_MANY_CHUNKS",
                    "Selection needs more than " + MAX_CHUNKS + " chunks; narrow the selection");
        }
        Map<String, Object> chunk = new LinkedHashMap<>();
        chunk.put("format", CHUNK_FORMAT);
        chunk.put("exportSetId", id);
        chunk.put("index", index);
        chunk.put("records", records);
        byte[] bytes = CanonicalJson.canonicalize(chunk, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE);
        if (bytes.length > maxBytes) {
            throw new ExportSetException(Kind.INVALID, "EXPORT_RECORD_TOO_LARGE",
                    "A chunk exceeds AUDIT_EXPORT_CHUNK_MAX_BYTES");
        }
        String name = String.format("chunk-%06d.json", index);
        try {
            writeDurably(directory.resolve(name), bytes);
        } catch (IOException exception) {
            throw new ExportSetException(Kind.FAILED, "EXPORT_IO_FAILURE", "Chunk could not be written");
        }
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("index", index);
        meta.put("name", name);
        meta.put("recordCount", records.size());
        meta.put("firstSeq", records.get(0).get("seq"));
        meta.put("lastSeq", records.get(records.size() - 1).get("seq"));
        meta.put("bytes", bytes.length);
        meta.put("sha256", sha256Hex(bytes));
        return meta;
    }

    private void commitAndSign(String id, BundleSelection selection, String requestedBy, StagedChunks staged)
            throws SQLException {
        String chunksDigest = sha256Hex(CanonicalJson.canonicalize(
                staged.chunks(), CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE));
        repository.writeTransaction(connection -> {
            Map<String, Object> eventPayload = new LinkedHashMap<>();
            eventPayload.put("exportSetId", id);
            eventPayload.put("purpose", "EXPORT");
            eventPayload.put("throughSeq", staged.throughSeq());
            eventPayload.put("totalRecords", staged.total());
            eventPayload.put("chunkCount", staged.chunks().size());
            eventPayload.put("chunksDigest", chunksDigest);
            eventPayload.put("selectionDigest", sha256Hex(CanonicalJson.canonicalize(selection.toMap())));
            eventPayload.put("requestedBy", requestedBy);
            AppendedEvent event = appendService.appendSystemEvent(
                    connection, "BUNDLE_EXPORTED", requestedBy, "AUDIT_EXPORT", id, eventPayload);
            Map<String, Object> checkpoint = appendService.storeCheckpoint(
                    connection, event.seq(), event.chainHash(), event.timestamp());

            Map<String, Object> headCheckpoint = new LinkedHashMap<>();
            headCheckpoint.put("seq", event.seq());
            headCheckpoint.put("chainHash", event.chainHash());
            headCheckpoint.put("createdAt", event.timestamp());
            headCheckpoint.put("keyId", checkpoint.get("keyId"));
            headCheckpoint.put("signature", checkpoint.get("signature"));

            Map<String, Object> selectionHead = new LinkedHashMap<>();
            selectionHead.put("seq", staged.throughSeq());
            selectionHead.put("chainHash", staged.selectionHeadHash());

            Map<String, Object> limits = new LinkedHashMap<>();
            limits.put("maxRecords", configuration.exportChunkMaxRecords());
            limits.put("maxBytes", configuration.exportChunkMaxBytes());

            Map<String, Object> exclusions = new LinkedHashMap<>();
            exclusions.put("archivedRecords", "EXCLUDED");
            exclusions.put("nonMatchingRecords", "EXCLUDED");
            exclusions.put("recordsAfterSelectionHead", "EXCLUDED");
            exclusions.put("upstreamCoverage", "NOT_PROVEN");

            Map<String, Object> signerInfo = new LinkedHashMap<>();
            signerInfo.put("keyId", signer.keyId());
            signerInfo.put("publicKey", signer.publicKeyBase64());

            String createdAt = event.timestamp();
            String expiresAt = BundleSelection.normalizeTimestamp(
                    Instant.parse(createdAt).plusSeconds(configuration.exportSetTtlSeconds()).toString());

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("format", MANIFEST_FORMAT);
            body.put("exportSetId", id);
            body.put("purpose", "EXPORT");
            body.put("ledgerId", configuration.ledgerId());
            body.put("hashAlgorithm", "SHA-256");
            body.put("hashVersion", V1Hashes.HASH_VERSION);
            body.put("genesisHash", V1Hashes.genesisHash(configuration.ledgerId()));
            body.put("signatureAlgorithm", "Ed25519");
            body.put("createdAt", createdAt);
            body.put("expiresAt", expiresAt);
            body.put("exportedBy", requestedBy);
            body.put("selection", selection.toMap());
            body.put("completeness", new BundleCompleteness(staged.throughSeq()).toMap());
            body.put("selectionHead", selectionHead);
            body.put("headCheckpoint", headCheckpoint);
            body.put("totalRecords", staged.total());
            body.put("chunkCount", staged.chunks().size());
            body.put("chunkLimits", limits);
            body.put("chunks", staged.chunks());
            body.put("chunksDigest", chunksDigest);
            body.put("exclusions", exclusions);
            body.put("signer", signerInfo);
            Map<String, Object> manifest = new LinkedHashMap<>(body);
            manifest.put("signature", signer.signMessage(body, Integer.MAX_VALUE));
            byte[] bytes = CanonicalJson.canonicalize(
                    manifest, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE);
            try {
                writeDurably(stagingDirectory.resolve(id).resolve(MANIFEST_NAME), bytes);
            } catch (IOException exception) {
                throw new SQLException("Manifest could not be written", exception);
            }
            return null;
        });
    }

    /** Atomically publishes a fully staged set and records READY; idempotent for recovery. */
    private void publish(String id) throws IOException {
        Path staged = stagingDirectory.resolve(id);
        Path ready = readyDirectory.resolve(id);
        if (Files.isDirectory(staged)) {
            syncDirectory(staged);
            Files.move(staged, ready, StandardCopyOption.ATOMIC_MOVE);
            syncDirectory(readyDirectory);
        }
        markReady(id);
    }

    private void markReady(String id) throws IOException {
        Path manifestPath = readyDirectory.resolve(id).resolve(MANIFEST_NAME);
        byte[] bytes = Files.readAllBytes(manifestPath);
        Map<String, Object> manifest = MAPPER.readValue(bytes, new TypeReference<Map<String, Object>>() { });
        Map<String, Object> job = readJob(id);
        Map<String, Object> head = castMap(manifest.get("headCheckpoint"));
        Map<String, Object> selectionHead = castMap(manifest.get("selectionHead"));
        job.put("status", "READY");
        job.put("expiresAt", manifest.get("expiresAt"));
        job.put("totalRecords", manifest.get("totalRecords"));
        job.put("chunkCount", manifest.get("chunkCount"));
        job.put("selectionHeadSeq", selectionHead.get("seq"));
        job.put("postEventHeadSeq", head.get("seq"));
        job.put("manifestSha256", sha256Hex(bytes));
        job.remove("errorCode");
        job.remove("message");
        writeJob(id, job);
    }

    private void fail(String id, String code, String message) {
        deleteTree(stagingDirectory.resolve(id));
        try {
            Map<String, Object> job = readJob(id);
            job.put("status", "FAILED");
            job.put("errorCode", code);
            job.put("message", message);
            writeJob(id, job);
        } catch (IOException | ExportSetException exception) {
            // The job file stays RUNNING; recovery will reconcile it.
        }
    }

    // ---------------------------------------------------------------- recovery

    /**
     * Reconciles every unfinished job and removes orphaned or expired artifacts. A staged set whose
     * ledger commit exists is completed; otherwise the job FAILS as INTERRUPTED and its files are
     * removed. Called on construction (restart recovery) and safe to call repeatedly.
     */
    public synchronized void recover() {
        List<String> known = new ArrayList<>();
        try (DirectoryStream<Path> files = Files.newDirectoryStream(jobsDirectory)) {
            for (Path file : files) {
                String name = file.getFileName().toString();
                if (name.endsWith(".tmp")) {
                    Files.deleteIfExists(file);
                } else if (name.endsWith(".json") && SET_ID.matcher(name.substring(0, name.length() - 5)).matches()) {
                    known.add(name.substring(0, name.length() - 5));
                }
            }
        } catch (IOException exception) {
            throw new UncheckedIOException("Export jobs cannot be listed", exception);
        }
        for (String id : known) {
            Map<String, Object> job;
            try {
                job = readJob(id);
            } catch (ExportSetException exception) {
                continue;
            }
            if ("RUNNING".equals(job.get("status")) && activeJobs.get() == 0) {
                reconcile(id);
            } else if ("READY".equals(job.get("status")) && isExpired(job)) {
                expire(id, job);
            }
        }
        removeOrphans(stagingDirectory, known, "RUNNING");
        removeOrphans(readyDirectory, known, "READY");
    }

    private void removeOrphans(Path directory, List<String> known, String liveStatus) {
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
            for (Path entry : entries) {
                String name = entry.getFileName().toString();
                boolean live = false;
                if (known.contains(name)) {
                    try {
                        live = liveStatus.equals(readJob(name).get("status"));
                    } catch (ExportSetException exception) {
                        live = false;
                    }
                }
                if (!live) {
                    deleteTree(entry);
                }
            }
        } catch (IOException exception) {
            throw new UncheckedIOException("Export directory cannot be scanned", exception);
        }
    }

    private void reconcile(String id) {
        try {
            Path readyManifest = readyDirectory.resolve(id).resolve(MANIFEST_NAME);
            if (Files.isRegularFile(readyManifest, LinkOption.NOFOLLOW_LINKS)) {
                markReady(id);
                return;
            }
            Path stagedManifest = stagingDirectory.resolve(id).resolve(MANIFEST_NAME);
            if (Files.isRegularFile(stagedManifest, LinkOption.NOFOLLOW_LINKS)
                    && committedAndIntact(id, stagedManifest)) {
                publish(id);
                return;
            }
            fail(id, "EXPORT_INTERRUPTED", "The export job was interrupted before its ledger commit");
        } catch (IOException | SQLException | RuntimeException exception) {
            // Leave RUNNING: a later recovery pass retries without losing committed state.
        }
    }

    private boolean committedAndIntact(String id, Path manifestPath) throws IOException, SQLException {
        Map<String, Object> manifest;
        try {
            manifest = MAPPER.readValue(Files.readAllBytes(manifestPath), new TypeReference<Map<String, Object>>() { });
            Map<String, Object> head = castMap(manifest.get("headCheckpoint"));
            long seq = ((Number) head.get("seq")).longValue();
            String chainHash = (String) head.get("chainHash");
            boolean committed = repository.readSnapshot(connection -> {
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT chain_hash FROM audit_events WHERE seq = ?")) {
                    statement.setLong(1, seq);
                    try (ResultSet result = statement.executeQuery()) {
                        return result.next() && chainHash.equals(result.getString(1));
                    }
                }
            });
            if (!committed || !id.equals(manifest.get("exportSetId"))) {
                return false;
            }
        } catch (RuntimeException exception) {
            return false;
        }
        List<?> chunks = (List<?>) manifest.get("chunks");
        for (Object entry : chunks) {
            Map<String, Object> chunk = castMap(entry);
            String name = (String) chunk.get("name");
            if (!CHUNK_NAME.matcher(name).matches()) {
                return false;
            }
            Path file = stagingDirectory.resolve(id).resolve(name);
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                    || Files.size(file) != ((Number) chunk.get("bytes")).longValue()
                    || !chunk.get("sha256").equals(sha256File(file))) {
                return false;
            }
        }
        return true;
    }

    // ---------------------------------------------------------------- helpers

    private boolean isExpired(Map<String, Object> job) {
        return !clock.instant().isBefore(Instant.parse((String) job.get("expiresAt")));
    }

    private void expire(String id, Map<String, Object> job) {
        deleteTree(readyDirectory.resolve(id));
        try {
            job.put("status", "EXPIRED");
            writeJob(id, job);
        } catch (IOException exception) {
            // Files are already gone; the next access retries recording EXPIRED.
        }
    }

    private Map<String, Object> requireReady(String id) {
        Map<String, Object> job = readJob(requireId(id));
        if ("READY".equals(job.get("status")) && isExpired(job)) {
            expire(id, job);
            job = readJob(id);
        }
        String status = (String) job.get("status");
        return switch (status) {
            case "READY" -> job;
            case "EXPIRED" -> throw new ExportSetException(Kind.GONE, "EXPORT_SET_EXPIRED",
                    "The export set has expired and was removed");
            case "FAILED" -> throw new ExportSetException(Kind.NOT_READY, "EXPORT_SET_FAILED",
                    "The export set failed and has no artifacts");
            default -> throw new ExportSetException(Kind.NOT_READY, "EXPORT_SET_NOT_READY",
                    "The export set is not ready yet");
        };
    }

    private static Path safeFile(Path directory, String name, Map<String, Object> job) {
        Path file = directory.resolve(name).normalize();
        if (!file.startsWith(directory.normalize())
                || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new ExportSetException(Kind.NOT_FOUND, "NOT_FOUND", "Export set artifact not found");
        }
        return file;
    }

    private static String requireId(String id) {
        if (id == null || !SET_ID.matcher(id).matches()) {
            throw new ExportSetException(Kind.NOT_FOUND, "NOT_FOUND", "Export set not found");
        }
        return id;
    }

    private Map<String, Object> readJob(String id) {
        Path file = jobsDirectory.resolve(requireId(id) + ".json");
        try {
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.size(file) > MAX_JOB_FILE_BYTES) {
                throw new ExportSetException(Kind.NOT_FOUND, "NOT_FOUND", "Export set not found");
            }
            return MAPPER.readValue(Files.readAllBytes(file), new TypeReference<LinkedHashMap<String, Object>>() { });
        } catch (IOException exception) {
            throw new ExportSetException(Kind.FAILED, "EXPORT_IO_FAILURE", "Export job record is unreadable");
        }
    }

    private void writeJob(String id, Map<String, Object> job) throws IOException {
        writeDurably(jobsDirectory.resolve(id + ".json"), MAPPER.writeValueAsBytes(job));
    }

    private static String chainHashAt(Connection connection, long seq) throws SQLException {
        try (PreparedStatement statement =
                connection.prepareStatement("SELECT chain_hash FROM audit_events WHERE seq = ?")) {
            statement.setLong(1, seq);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("Selection head record is missing");
                }
                return result.getString(1);
            }
        }
    }

    /** Writes to a unique temporary file, forces it to disk, then atomically renames it. */
    static void writeDurably(Path target, byte[] bytes) throws IOException {
        Path temporary = target.resolveSibling(target.getFileName() + "." + UUID.randomUUID() + ".tmp");
        try (FileChannel channel = FileChannel.open(
                temporary, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
        try {
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException exception) {
            Files.deleteIfExists(temporary);
            throw exception;
        }
        syncDirectory(target.getParent());
    }

    /** Best effort: directories cannot be opened for sync on every platform (notably Windows). */
    static void syncDirectory(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException exception) {
            // Not supported on this filesystem.
        }
    }

    private static void deleteTree(Path path) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(path)) {
            walk.sorted(Comparator.reverseOrder()).forEach(entry -> {
                try {
                    Files.deleteIfExists(entry);
                } catch (IOException exception) {
                    // Leftovers are removed by the next recovery pass.
                }
            });
        } catch (IOException exception) {
            // Leftovers are removed by the next recovery pass.
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object value) {
        return (Map<String, Object>) value;
    }

    private static String sha256File(Path file) throws IOException {
        try (InputStream input = Files.newInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = input.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static String sha256Hex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
