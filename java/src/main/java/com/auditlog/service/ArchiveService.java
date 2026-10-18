package com.auditlog.service;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.core.crypto.V1Hashes;
import com.auditlog.domain.BundleCompleteness;
import com.auditlog.domain.BundlePurpose;
import com.auditlog.domain.BundleSelection;
import com.auditlog.store.JdbcAuditRepository;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
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
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Durable retention archive. Archives the expired, oldest, contiguous prefix of the live ledger.
 *
 * <p>Order of effects for one run: (1) a PREPARING job row is committed, (2) in ONE write
 * transaction the signed RETENTION_ARCHIVE bundle is written to a temp file, forced to disk,
 * atomically renamed to its final name and the directory is synced where the platform supports
 * it, and only then are the business columns and leaves of the prefix cleared, the
 * RECORDS_ARCHIVED authorization appended and the job marked COMMITTED. If publication or any
 * later step fails, the transaction rolls back and the live plaintext is untouched; the job is
 * marked FAILED and its files are removed by a retried, proof-checked cleanup.
 *
 * <p>Runs are serialized by an in-process lock. A second service process on the same database is
 * outside the supported model; the PREPARING row makes such overlap visible rather than silent.
 */
public final class ArchiveService {

    /** Points where tests may inject a failure to model a crash or a publication error. */
    public enum Stage { AFTER_JOB_RECORDED, AFTER_TEMP_FORCED, AFTER_PUBLISH, BEFORE_COMMIT, AFTER_COMMIT }

    public enum Kind { CONFLICT, INVALID, FAILED }

    public static final class ArchiveException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final transient Kind kind;
        private final String code;

        public ArchiveException(Kind kind, String code, String message) {
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

    public record ArchiveResult(
            boolean dryRun,
            String status,
            String cutoff,
            long effectiveRetentionDays,
            Long fromSeq,
            Long toSeq,
            int count,
            long estimatedBytes,
            boolean moreEligible,
            String bundleId,
            String archiveFile,
            String archiveSha256,
            Long archiveEventSeq,
            Boolean directorySynced,
            String walCheckpoint,
            String note) {
    }

    private static final String UUID_RE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    static final Pattern FINAL_NAME = Pattern.compile("archive-" + UUID_RE + "\\.json");
    static final Pattern TEMP_NAME = Pattern.compile("\\.archive-" + UUID_RE + "\\.tmp");
    private static final DateTimeFormatter UTC_MICROS =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'").withZone(ZoneOffset.UTC);
    private static final int ENVELOPE_HEADROOM_BYTES = 8 * 1024;
    private static final int MAX_LISTED = 100;

    private final JdbcAuditRepository repository;
    private final AuditConfiguration configuration;
    private final CheckpointSigner signer;
    private final AppendEventService appendService;
    private final Clock clock;
    private final Consumer<Stage> hook;
    private final ReentrantLock lock = new ReentrantLock();

    public ArchiveService(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService,
            Clock clock) {
        this(repository, configuration, signer, appendService, clock, stage -> { });
    }

    public ArchiveService(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService,
            Clock clock,
            Consumer<Stage> hook) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.signer = Objects.requireNonNull(signer, "signer");
        this.appendService = Objects.requireNonNull(appendService, "appendService");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.hook = Objects.requireNonNull(hook, "hook");
    }

    public Path archiveDirectory() {
        return configuration.archiveDirectory();
    }

    /**
     * Retention is configured as a positive, possibly fractional number of days. A RECORDS_ARCHIVED
     * authorization carries an integer, so the effective policy rounds UP, which is never less
     * conservative than the configured value.
     */
    public long effectiveRetentionDays() {
        return Math.max(1L, (long) Math.ceil(configuration.retentionDays()));
    }

    public ArchiveResult archive(boolean dryRun, String requestedBy) throws SQLException {
        if (requestedBy == null || requestedBy.isBlank()) {
            throw new IllegalArgumentException("requestedBy is required");
        }
        if (!lock.tryLock()) {
            throw new ArchiveException(Kind.CONFLICT, "ARCHIVE_IN_PROGRESS",
                    "Another archive or reconcile operation is running");
        }
        try {
            Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
            long days = effectiveRetentionDays();
            String cutoff = micros(now.minus(days, ChronoUnit.DAYS));
            Plan plan = repository.readSnapshot(connection -> plan(connection, cutoff));
            if (dryRun) {
                return summary(true, plan.count() == 0 ? "NOTHING_TO_ARCHIVE" : "DRY_RUN", cutoff, days, plan);
            }
            if (openJobCount() > 0) {
                throw new ArchiveException(Kind.CONFLICT, "ARCHIVE_JOB_INTERRUPTED",
                        "A previous archive job is unresolved; run archive reconciliation first");
            }
            if (plan.count() == 0) {
                return summary(false, "NOTHING_TO_ARCHIVE", cutoff, days, plan);
            }
            String bundleId = UUID.randomUUID().toString();
            insertJob(bundleId, requestedBy, micros(now));
            return runJob(bundleId, requestedBy, cutoff, days);
        } finally {
            lock.unlock();
        }
    }

    private ArchiveResult runJob(String bundleId, String requestedBy, String cutoff, long days)
            throws SQLException {
        try {
            hook.accept(Stage.AFTER_JOB_RECORDED);
            Committed committed = repository.writeTransaction(connection ->
                    commitArchive(connection, bundleId, requestedBy, cutoff, days));
            if (committed == null) {
                failJob(bundleId, "NOTHING_TO_ARCHIVE", false);
                return new ArchiveResult(false, "NOTHING_TO_ARCHIVE", cutoff, days, null, null, 0, 0,
                        false, null, null, null, null, null, null, "The eligible prefix disappeared");
            }
            hook.accept(Stage.AFTER_COMMIT);
            return new ArchiveResult(false, "ARCHIVED", cutoff, days, committed.fromSeq, committed.toSeq,
                    committed.count, committed.bytes, committed.more, bundleId, committed.fileName,
                    committed.sha256, committed.eventSeq, committed.directorySynced, walCheckpoint(),
                    "Archived records are excluded from normal queries and exports");
        } catch (SQLException | RuntimeException failure) {
            ArchiveResult alreadyCommitted = failJobOrRecover(bundleId, failure, cutoff, days);
            if (alreadyCommitted != null) {
                return alreadyCommitted;
            }
            throw failure;
        }
    }

    private Committed commitArchive(
            Connection connection, String bundleId, String requestedBy, String cutoff, long days)
            throws SQLException {
        Plan plan = plan(connection, cutoff);
        if (plan.count() == 0) {
            return null;
        }
        String createdAt = micros(clock.instant().truncatedTo(ChronoUnit.MICROS));
        Map<String, Object> checkpoint = appendService.storeCheckpoint(
                connection, plan.toSeq(), plan.lastChainHash(), createdAt);
        byte[] bundle = buildBundle(bundleId, requestedBy, createdAt, plan, checkpoint);
        if (bundle.length > configuration.archiveMaxBytes()) {
            throw new ArchiveException(Kind.INVALID, "ARCHIVE_TOO_LARGE",
                    "Archive bundle exceeds AUDIT_ARCHIVE_MAX_BYTES");
        }
        String sha256 = sha256Hex(bundle);
        String finalName = "archive-" + bundleId + ".json";
        boolean synced;
        try {
            synced = publish(bundleId, bundle);
        } catch (IOException exception) {
            throw new UncheckedIOException("Archive publication failed", exception);
        }
        hook.accept(Stage.AFTER_PUBLISH);

        try (PreparedStatement update = connection.prepareStatement("""
                UPDATE audit_events SET archived = 1, archived_at = ?, event_type = NULL,
                    actor_id = NULL, resource_type = NULL, resource_id = NULL, occurred_at = NULL,
                    source = NULL, payload_commitments = NULL
                WHERE seq BETWEEN ? AND ? AND archived = 0
                """)) {
            update.setString(1, createdAt);
            update.setLong(2, plan.fromSeq());
            update.setLong(3, plan.toSeq());
            if (update.executeUpdate() != plan.count()) {
                throw new IllegalStateException("Archived row count differs from the plan");
            }
        }
        try (PreparedStatement delete = connection.prepareStatement(
                "DELETE FROM payload_leaves WHERE seq BETWEEN ? AND ?")) {
            delete.setLong(1, plan.fromSeq());
            delete.setLong(2, plan.toSeq());
            delete.executeUpdate();
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("archivedThroughSeq", plan.toSeq());
        payload.put("fromSeq", plan.fromSeq());
        payload.put("toSeq", plan.toSeq());
        payload.put("count", plan.count());
        payload.put("cutoff", cutoff);
        payload.put("retentionDays", days);
        payload.put("lastArchivedChainHash", plan.lastChainHash());
        payload.put("archiveFile", finalName);
        payload.put("archiveSha256", sha256);
        payload.put("archiveBundleId", bundleId);
        payload.put("requestedBy", requestedBy);
        AppendedEvent event = appendService.appendSystemEvent(
                connection, "RECORDS_ARCHIVED", requestedBy, "AUDIT_ARCHIVE", bundleId, payload);

        try (PreparedStatement job = connection.prepareStatement("""
                UPDATE archive_jobs SET status = 'COMMITTED', updated_at = ?, from_seq = ?, to_seq = ?,
                    record_count = ?, cutoff = ?, retention_days = ?, archive_sha256 = ?,
                    archive_bytes = ?, directory_synced = ?, archive_event_seq = ?
                WHERE bundle_id = ? AND status = 'PREPARING'
                """)) {
            job.setString(1, event.timestamp());
            job.setLong(2, plan.fromSeq());
            job.setLong(3, plan.toSeq());
            job.setInt(4, plan.count());
            job.setString(5, cutoff);
            job.setLong(6, days);
            job.setString(7, sha256);
            job.setLong(8, bundle.length);
            job.setInt(9, synced ? 1 : 0);
            job.setLong(10, event.seq());
            job.setString(11, bundleId);
            if (job.executeUpdate() != 1) {
                throw new IllegalStateException("Archive job is not in PREPARING state");
            }
        }
        hook.accept(Stage.BEFORE_COMMIT);
        return new Committed(plan.fromSeq(), plan.toSeq(), plan.count(), bundle.length, plan.more(),
                finalName, sha256, event.seq(), synced);
    }

    private byte[] buildBundle(
            String bundleId, String requestedBy, String createdAt, Plan plan,
            Map<String, Object> checkpoint) {
        byte[] recordsCanonical = CanonicalJson.canonicalize(
                plan.records(), CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE);
        Map<String, Object> head = new LinkedHashMap<>();
        head.put("seq", plan.toSeq());
        head.put("chainHash", plan.lastChainHash());
        head.put("createdAt", createdAt);
        head.put("keyId", checkpoint.get("keyId"));
        head.put("signature", checkpoint.get("signature"));
        Map<String, Object> signerInfo = new LinkedHashMap<>();
        signerInfo.put("keyId", signer.keyId());
        signerInfo.put("publicKey", signer.publicKeyBase64());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("format", ExportBundleService.FORMAT);
        body.put("bundleId", bundleId);
        body.put("purpose", BundlePurpose.RETENTION_ARCHIVE.name());
        body.put("ledgerId", configuration.ledgerId());
        body.put("hashAlgorithm", "SHA-256");
        body.put("hashVersion", V1Hashes.HASH_VERSION);
        body.put("genesisHash", V1Hashes.genesisHash(configuration.ledgerId()));
        body.put("signatureAlgorithm", "Ed25519");
        body.put("exportedAt", createdAt);
        body.put("exportedBy", requestedBy);
        body.put("selection", BundleSelection.forSeqRange(plan.fromSeq(), plan.toSeq()).toMap());
        body.put("completeness", new BundleCompleteness(plan.toSeq()).toMap());
        body.put("recordCount", plan.records().size());
        body.put("recordsDigest", sha256Hex(recordsCanonical));
        body.put("records", plan.records());
        body.put("headCheckpoint", head);
        body.put("signer", signerInfo);
        Map<String, Object> bundle = new LinkedHashMap<>(body);
        bundle.put("signature", signer.signMessage(body, Integer.MAX_VALUE));
        return CanonicalJson.canonicalize(bundle, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE);
    }

    /** Writes, forces, atomically publishes and (where supported) directory-syncs the archive file. */
    private boolean publish(String bundleId, byte[] bundle) throws IOException {
        Path directory = archiveDirectory();
        Files.createDirectories(directory);
        Path temp = directory.resolve(".archive-" + bundleId + ".tmp");
        Path finalPath = directory.resolve("archive-" + bundleId + ".json");
        if (Files.exists(temp) || Files.exists(finalPath)) {
            throw new IOException("Archive target name already exists");
        }
        try (FileChannel channel = FileChannel.open(
                temp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            ByteBuffer buffer = ByteBuffer.wrap(bundle);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
        hook.accept(Stage.AFTER_TEMP_FORCED);
        Files.move(temp, finalPath, StandardCopyOption.ATOMIC_MOVE);
        if (Files.size(finalPath) != bundle.length) {
            throw new IOException("Published archive size differs from the prepared bundle");
        }
        return syncDirectory(directory);
    }

    /** Best effort: opening a directory for fsync is unsupported on Windows. */
    static boolean syncDirectory(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
            return true;
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            return false;
        }
    }

    private Plan plan(Connection connection, String cutoff) throws SQLException {
        Long first = null;
        try (Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery(
                        "SELECT MIN(seq) FROM audit_events WHERE archived = 0")) {
            if (result.next() && result.getObject(1) != null) {
                first = result.getLong(1);
            }
        }
        List<Map<String, Object>> records = new ArrayList<>();
        if (first == null) {
            return new Plan(0, 0, "", records, 0, false);
        }
        long budget = (long) configuration.archiveMaxBytes() - ENVELOPE_HEADROOM_BYTES;
        long bytes = 0;
        boolean more = false;
        long expected = first;
        String lastHash = "";
        try (PreparedStatement statement = ExportBundleService.prepareSelection(
                        connection, BundleSelection.forSeqRange(first, BundleSelection.MAX_SAFE),
                        BundleSelection.MAX_SAFE, (long) configuration.archiveMaxRecords() + 1);
                ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                if (result.getLong("seq") != expected
                        || result.getString("recorded_at").compareTo(cutoff) >= 0) {
                    break;
                }
                if (records.size() >= configuration.archiveMaxRecords()) {
                    more = true;
                    break;
                }
                Map<String, Object> record = ExportBundleService.readRecord(connection, result);
                long size = CanonicalJson.canonicalize(
                        record, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE).length + 1L;
                if (bytes + size > budget) {
                    if (records.isEmpty()) {
                        throw new ArchiveException(Kind.INVALID, "ARCHIVE_RECORD_TOO_LARGE",
                                "A single record exceeds AUDIT_ARCHIVE_MAX_BYTES");
                    }
                    more = true;
                    break;
                }
                bytes += size;
                records.add(record);
                lastHash = (String) record.get("chainHash");
                expected++;
            }
        }
        if (records.isEmpty()) {
            return new Plan(0, 0, "", records, 0, false);
        }
        return new Plan(first, first + records.size() - 1, lastHash, records, bytes, more);
    }

    private ArchiveResult summary(boolean dryRun, String status, String cutoff, long days, Plan plan) {
        boolean empty = plan.count() == 0;
        return new ArchiveResult(dryRun, status, cutoff, days,
                empty ? null : plan.fromSeq(), empty ? null : plan.toSeq(), plan.count(),
                plan.bytes(), plan.more(), null, null, null, null, null, null,
                dryRun ? "Dry run: no file was written and no data changed" : null);
    }

    private String walCheckpoint() {
        try {
            return repository.checkpointWalTruncate(configuration.cleanupBusyTimeoutMillis()).complete()
                    ? "COMPLETE" : "BUSY";
        } catch (SQLException exception) {
            return "ERROR";
        }
    }

    // ---- jobs -------------------------------------------------------------------------------

    private void insertJob(String bundleId, String requestedBy, String now) throws SQLException {
        repository.writeTransaction(connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO archive_jobs(bundle_id, status, temp_name, final_name, requested_by,
                        created_at, updated_at)
                    VALUES (?, 'PREPARING', ?, ?, ?, ?, ?)
                    """)) {
                statement.setString(1, bundleId);
                statement.setString(2, ".archive-" + bundleId + ".tmp");
                statement.setString(3, "archive-" + bundleId + ".json");
                statement.setString(4, requestedBy);
                statement.setString(5, now);
                statement.setString(6, now);
                statement.executeUpdate();
            }
            return null;
        });
    }

    private long openJobCount() throws SQLException {
        return repository.readSnapshot(connection -> {
            try (Statement statement = connection.createStatement();
                    ResultSet result = statement.executeQuery(
                            "SELECT COUNT(*) FROM archive_jobs WHERE status = 'PREPARING'")) {
                result.next();
                return result.getLong(1);
            }
        });
    }

    /** Marks a PREPARING job FAILED; returns false if the job already left PREPARING. */
    private boolean failJob(String bundleId, String code, boolean cleanup) throws SQLException {
        return repository.writeTransaction(connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE archive_jobs SET status = 'FAILED', failure_code = ?, cleanup_state = ?,
                        updated_at = ?
                    WHERE bundle_id = ? AND status = 'PREPARING'
                    """)) {
                statement.setString(1, code);
                statement.setString(2, cleanup ? "PENDING" : "NONE");
                statement.setString(3, micros(clock.instant().truncatedTo(ChronoUnit.MICROS)));
                statement.setString(4, bundleId);
                return statement.executeUpdate() == 1;
            }
        });
    }

    private ArchiveResult failJobOrRecover(
            String bundleId, Exception failure, String cutoff, long days) throws SQLException {
        String code = failure instanceof ArchiveException archive ? archive.code() : "PUBLICATION_FAILED";
        if (failJob(bundleId, code, true)) {
            cleanupJob(bundleId);
            return null;
        }
        // The job is no longer PREPARING: the commit actually succeeded despite the exception.
        Map<String, Object> job = readJob(bundleId);
        if (job != null && "COMMITTED".equals(job.get("status"))) {
            return new ArchiveResult(false, "ARCHIVED", cutoff, days, (Long) job.get("fromSeq"),
                    (Long) job.get("toSeq"), ((Long) job.get("recordCount")).intValue(),
                    (Long) job.get("archiveBytes"), false, bundleId, (String) job.get("archiveFile"),
                    (String) job.get("archiveSha256"), (Long) job.get("archiveEventSeq"),
                    (Boolean) job.get("directorySynced"), "UNKNOWN",
                    "Commit outcome was ambiguous; the job is recorded as COMMITTED");
        }
        return null;
    }

    private Map<String, Object> readJob(String bundleId) throws SQLException {
        List<Map<String, Object>> jobs = readJobs("WHERE bundle_id = ?", bundleId, 1);
        return jobs.isEmpty() ? null : jobs.get(0);
    }

    private List<Map<String, Object>> readJobs(String where, String parameter, int limit)
            throws SQLException {
        return repository.readSnapshot(connection -> {
            List<Map<String, Object>> jobs = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT id, bundle_id, status, temp_name, final_name, requested_by, created_at,
                        updated_at, from_seq, to_seq, record_count, cutoff, retention_days,
                        archive_sha256, archive_bytes, directory_synced, archive_event_seq,
                        failure_code, cleanup_state, cleanup_detail
                    FROM archive_jobs %s ORDER BY id DESC LIMIT ?
                    """.replace("%s", where))) {
                int index = 1;
                if (parameter != null) {
                    statement.setString(index++, parameter);
                }
                statement.setInt(index, limit);
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        jobs.add(jobRow(result));
                    }
                }
            }
            return jobs;
        });
    }

    private static Map<String, Object> jobRow(ResultSet result) throws SQLException {
        Map<String, Object> job = new LinkedHashMap<>();
        job.put("id", result.getLong("id"));
        job.put("bundleId", result.getString("bundle_id"));
        job.put("status", result.getString("status"));
        job.put("tempFile", result.getString("temp_name"));
        job.put("archiveFile", result.getString("final_name"));
        job.put("requestedBy", result.getString("requested_by"));
        job.put("createdAt", result.getString("created_at"));
        job.put("updatedAt", result.getString("updated_at"));
        job.put("fromSeq", nullableLong(result, "from_seq"));
        job.put("toSeq", nullableLong(result, "to_seq"));
        job.put("recordCount", nullableLong(result, "record_count"));
        job.put("cutoff", result.getString("cutoff"));
        job.put("retentionDays", nullableLong(result, "retention_days"));
        job.put("archiveSha256", result.getString("archive_sha256"));
        job.put("archiveBytes", nullableLong(result, "archive_bytes"));
        Long synced = nullableLong(result, "directory_synced");
        job.put("directorySynced", synced == null ? null : synced == 1L);
        job.put("archiveEventSeq", nullableLong(result, "archive_event_seq"));
        job.put("failureCode", result.getString("failure_code"));
        job.put("cleanupState", result.getString("cleanup_state"));
        job.put("cleanupDetail", result.getString("cleanup_detail"));
        return job;
    }

    private static Long nullableLong(ResultSet result, String column) throws SQLException {
        long value = result.getLong(column);
        return result.wasNull() ? null : value;
    }

    // ---- reconciliation and cleanup ----------------------------------------------------------

    /**
     * Resolves interrupted jobs. A PREPARING job can never have committed (the COMMITTED update
     * shares the archive transaction), so it is marked FAILED. Files of FAILED jobs are deleted
     * only when their names match the service pattern, belong to that job and no committed job or
     * live ledger event references them. Files without a job row are reported, never deleted.
     */
    public Map<String, Object> reconcile() throws SQLException {
        if (!lock.tryLock()) {
            throw new ArchiveException(Kind.CONFLICT, "ARCHIVE_IN_PROGRESS",
                    "Another archive or reconcile operation is running");
        }
        try {
            for (Map<String, Object> job : readJobs("WHERE status = 'PREPARING'", null, 1000)) {
                failJob((String) job.get("bundleId"), "INTERRUPTED", true);
            }
            for (Map<String, Object> job : readJobs(
                    "WHERE status = 'FAILED' AND cleanup_state = 'PENDING'", null, 1000)) {
                cleanupJob((String) job.get("bundleId"));
            }
            return status();
        } finally {
            lock.unlock();
        }
    }

    private void cleanupJob(String bundleId) throws SQLException {
        Map<String, Object> job = readJob(bundleId);
        if (job == null || !"FAILED".equals(job.get("status"))
                || !"PENDING".equals(job.get("cleanupState"))) {
            return;
        }
        String tempName = (String) job.get("tempFile");
        String finalName = (String) job.get("archiveFile");
        if (!TEMP_NAME.matcher(tempName).matches() || !FINAL_NAME.matcher(finalName).matches()
                || !tempName.equals(".archive-" + bundleId + ".tmp")
                || !finalName.equals("archive-" + bundleId + ".json")) {
            setCleanup(bundleId, "BLOCKED", "Job file names do not match the service pattern");
            return;
        }
        if (isReferenced(finalName)) {
            setCleanup(bundleId, "BLOCKED", "Archive file is referenced by a committed archive");
            return;
        }
        try {
            Files.deleteIfExists(archiveDirectory().resolve(tempName));
            Files.deleteIfExists(archiveDirectory().resolve(finalName));
            setCleanup(bundleId, "DONE", null);
        } catch (IOException | RuntimeException exception) {
            setCleanup(bundleId, "PENDING", "Delete failed: " + exception.getClass().getSimpleName());
        }
    }

    private boolean isReferenced(String finalName) throws SQLException {
        return repository.readSnapshot(connection -> {
            try (PreparedStatement jobs = connection.prepareStatement(
                    "SELECT 1 FROM archive_jobs WHERE final_name = ? AND status = 'COMMITTED'")) {
                jobs.setString(1, finalName);
                try (ResultSet result = jobs.executeQuery()) {
                    if (result.next()) {
                        return true;
                    }
                }
            }
            try (PreparedStatement leaves = connection.prepareStatement(
                    "SELECT 1 FROM payload_leaves WHERE pointer = '/archiveFile' AND value = ?")) {
                leaves.setString(1, "\"" + finalName + "\"");
                try (ResultSet result = leaves.executeQuery()) {
                    return result.next();
                }
            }
        });
    }

    private void setCleanup(String bundleId, String state, String detail) throws SQLException {
        repository.writeTransaction(connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE archive_jobs SET cleanup_state = ?, cleanup_detail = ?, updated_at = ?
                    WHERE bundle_id = ? AND status = 'FAILED'
                    """)) {
                statement.setString(1, state);
                statement.setString(2, detail);
                statement.setString(3, micros(clock.instant().truncatedTo(ChronoUnit.MICROS)));
                statement.setString(4, bundleId);
                statement.executeUpdate();
            }
            return null;
        });
    }

    /** Job table summary plus files in the archive directory that no job row accounts for. */
    public Map<String, Object> status() throws SQLException {
        List<Map<String, Object>> jobs = readJobs("", null, MAX_LISTED);
        Set<String> known = new HashSet<>();
        for (Map<String, Object> job : readAllNames()) {
            known.add((String) job.get("tempFile"));
            known.add((String) job.get("archiveFile"));
        }
        List<String> orphans = new ArrayList<>();
        long unrecognized = 0;
        Path directory = archiveDirectory();
        if (Files.isDirectory(directory)) {
            try (Stream<Path> entries = Files.list(directory)) {
                for (Path entry : (Iterable<Path>) entries::iterator) {
                    String name = String.valueOf(entry.getFileName());
                    if (known.contains(name)) {
                        continue;
                    }
                    if (FINAL_NAME.matcher(name).matches() || TEMP_NAME.matcher(name).matches()) {
                        if (orphans.size() < MAX_LISTED) {
                            orphans.add(name);
                        }
                    } else {
                        unrecognized++;
                    }
                }
            } catch (IOException exception) {
                throw new SQLException("Archive directory could not be listed", exception);
            }
        }
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("openJobs", openJobCount());
        status.put("jobs", jobs);
        status.put("orphanFiles", orphans);
        status.put("unrecognizedFileCount", unrecognized);
        status.put("note", "Orphans are reported only; the service never deletes files without a job row");
        return status;
    }

    private List<Map<String, Object>> readAllNames() throws SQLException {
        return repository.readSnapshot(connection -> {
            List<Map<String, Object>> names = new ArrayList<>();
            try (Statement statement = connection.createStatement();
                    ResultSet result = statement.executeQuery(
                            "SELECT temp_name, final_name FROM archive_jobs")) {
                while (result.next()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("tempFile", result.getString(1));
                    row.put("archiveFile", result.getString(2));
                    names.add(row);
                }
            }
            return names;
        });
    }

    // ---- helpers ----------------------------------------------------------------------------

    static String micros(Instant instant) {
        return UTC_MICROS.format(instant);
    }

    static String sha256Hex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private record Plan(
            long fromSeq, long toSeq, String lastChainHash, List<Map<String, Object>> records,
            long bytes, boolean more) {
        int count() {
            return records.size();
        }
    }

    private record Committed(
            long fromSeq, long toSeq, int count, long bytes, boolean more, String fileName,
            String sha256, long eventSeq, boolean directorySynced) {
    }
}
