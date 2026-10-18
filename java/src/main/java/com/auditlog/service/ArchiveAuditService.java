package com.auditlog.service;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.BundleDiagnostic;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.verifier.BundleVerifier;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Explicit audit of the archive files, separate from the ledger-chain verification. For every
 * committed archive it checks file presence (reported distinctly as ARCHIVE_FILE_MISSING), size,
 * SHA-256 against the authorized digest, the signed bundle with the pinned service key, the
 * bundle metadata, and every archived record against the preserved skeleton in the ledger.
 *
 * <p>Archive entries come from two independent sources that are merged by bundle id: the
 * {@code archive_jobs} table (which also covers archive events that were themselves archived) and
 * the validated live RECORDS_ARCHIVED events. This audit does NOT verify the ledger chain; use
 * {@code GET /audit/verify} for that.
 */
public final class ArchiveAuditService {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int MAX_ENTRIES = 10_000;

    private final JdbcAuditRepository repository;
    private final String ledgerId;
    private final Path archiveDirectory;
    private final int maxBytes;
    private final int maxRecords;
    private final String pinnedPublicKey;
    private final String keyId;
    private final Clock clock;

    public ArchiveAuditService(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            Clock clock) {
        this(repository, configuration.ledgerId(), configuration.archiveDirectory(),
                configuration.archiveMaxBytes(), configuration.archiveMaxRecords(),
                Objects.requireNonNull(signer, "signer").publicKeyBase64(), clock);
    }

    /** Standalone form: the caller supplies an out-of-band pinned raw Ed25519 key (Base64). */
    public ArchiveAuditService(
            JdbcAuditRepository repository,
            String ledgerId,
            Path archiveDirectory,
            int maxBytes,
            int maxRecords,
            String pinnedPublicKeyBase64,
            Clock clock) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.ledgerId = Objects.requireNonNull(ledgerId, "ledgerId");
        this.archiveDirectory = Objects.requireNonNull(archiveDirectory, "archiveDirectory");
        this.maxBytes = maxBytes;
        this.maxRecords = maxRecords;
        this.pinnedPublicKey = Objects.requireNonNull(pinnedPublicKeyBase64, "pinnedPublicKey");
        byte[] raw = java.util.Base64.getDecoder().decode(pinnedPublicKeyBase64);
        this.keyId = CheckpointSigner.keyIdFor(raw);
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Map<String, Object> audit() throws SQLException {
        List<Map<String, Object>> entries = repository.readSnapshot(this::collectEntries);
        long failures = 0;
        long missing = 0;
        long unavailable = 0;
        List<Map<String, Object>> results = new ArrayList<>();
        for (Map<String, Object> entry : entries) {
            Map<String, Object> result = repository.readSnapshot(connection -> check(connection, entry));
            String status = (String) result.get("status");
            if (!"OK".equals(status)) {
                failures++;
            }
            if ("ARCHIVE_FILE_MISSING".equals(status)) {
                missing++;
            }
            if ("ARCHIVE_FILE_MISSING".equals(status) || "ARCHIVE_FILE_UNREADABLE".equals(status)) {
                unavailable++;
            }
            results.add(result);
        }
        Map<String, Object> coverage = repository.readSnapshot(connection -> coverage(connection, entries));
        boolean coverageOk = Boolean.TRUE.equals(coverage.get("complete"));
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("auditedAt", ArchiveService.micros(clock.instant()));
        report.put("archiveCount", results.size());
        report.put("intact", failures == 0 && coverageOk);
        report.put("failedArchiveCount", failures);
        report.put("missingArchiveCount", missing);
        report.put("unavailableArchiveCount", unavailable);
        report.put("keyId", keyId);
        report.put("coverage", coverage);
        report.put("archives", results);
        report.put("scope", "Archive files only. The ledger chain is verified separately by GET /audit/verify; "
                + "a missing archive file is reported here and is not a chain break.");
        return report;
    }

    private List<Map<String, Object>> collectEntries(Connection connection) throws SQLException {
        Map<String, Map<String, Object>> byBundle = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT bundle_id, final_name, archive_sha256, from_seq, to_seq, record_count,
                    archive_bytes, archive_event_seq
                FROM archive_jobs WHERE status = 'COMMITTED' ORDER BY id LIMIT ?
                """)) {
            statement.setInt(1, MAX_ENTRIES);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("bundleId", result.getString("bundle_id"));
                    entry.put("archiveFile", result.getString("final_name"));
                    entry.put("archiveSha256", result.getString("archive_sha256"));
                    entry.put("fromSeq", result.getLong("from_seq"));
                    entry.put("toSeq", result.getLong("to_seq"));
                    entry.put("count", result.getLong("record_count"));
                    entry.put("eventSeq", result.getLong("archive_event_seq"));
                    entry.put("jobRecorded", true);
                    entry.put("ledgerEventPresent", false);
                    byBundle.put(result.getString("bundle_id"), entry);
                }
            }
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT seq FROM audit_events
                WHERE archived = 0 AND event_type = 'RECORDS_ARCHIVED' AND source = 'system'
                ORDER BY seq LIMIT ?
                """)) {
            statement.setInt(1, MAX_ENTRIES);
            List<Long> seqs = new ArrayList<>();
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    seqs.add(result.getLong(1));
                }
            }
            for (long seq : seqs) {
                Map<String, Object> payload = leafMap(connection, seq);
                Object bundleId = payload.get("archiveBundleId");
                if (!(bundleId instanceof String id)) {
                    continue;
                }
                Map<String, Object> entry = byBundle.computeIfAbsent(id, key -> new LinkedHashMap<>());
                boolean fromJob = Boolean.TRUE.equals(entry.get("jobRecorded"));
                if (!fromJob) {
                    entry.put("bundleId", id);
                    entry.put("archiveFile", payload.get("archiveFile"));
                    entry.put("archiveSha256", payload.get("archiveSha256"));
                    entry.put("fromSeq", payload.get("fromSeq"));
                    entry.put("toSeq", payload.get("toSeq"));
                    entry.put("count", payload.get("count"));
                    entry.put("eventSeq", seq);
                    entry.put("jobRecorded", false);
                } else if (!sameMetadata(entry, payload)) {
                    entry.put("metadataConflict", true);
                }
                entry.put("ledgerEventPresent", true);
            }
        }
        return new ArrayList<>(byBundle.values());
    }

    private static boolean sameMetadata(Map<String, Object> entry, Map<String, Object> payload) {
        return String.valueOf(entry.get("archiveFile")).equals(String.valueOf(payload.get("archiveFile")))
                && String.valueOf(entry.get("archiveSha256")).equals(String.valueOf(payload.get("archiveSha256")))
                && String.valueOf(entry.get("fromSeq")).equals(String.valueOf(payload.get("fromSeq")))
                && String.valueOf(entry.get("toSeq")).equals(String.valueOf(payload.get("toSeq")))
                && String.valueOf(entry.get("count")).equals(String.valueOf(payload.get("count")));
    }

    private static Map<String, Object> leafMap(Connection connection, long seq) throws SQLException {
        Map<String, Object> values = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pointer, value FROM payload_leaves WHERE seq = ?")) {
            statement.setLong(1, seq);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    String pointer = result.getString(1);
                    if (pointer.indexOf('/', 1) >= 0 || !pointer.startsWith("/")) {
                        continue;
                    }
                    try {
                        values.put(pointer.substring(1), MAPPER.readValue(result.getString(2), Object.class));
                    } catch (IOException exception) {
                        // A malformed stored leaf is simply not usable metadata.
                        continue;
                    }
                }
            }
        }
        return values;
    }

    private Map<String, Object> check(Connection connection, Map<String, Object> entry) throws SQLException {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("bundleId", entry.get("bundleId"));
        result.put("archiveFile", entry.get("archiveFile"));
        result.put("fromSeq", entry.get("fromSeq"));
        result.put("toSeq", entry.get("toSeq"));
        result.put("count", entry.get("count"));
        result.put("archiveEventSeq", entry.get("eventSeq"));
        result.put("jobRecorded", entry.get("jobRecorded"));
        result.put("ledgerEventPresent", entry.get("ledgerEventPresent"));
        String status = evaluate(connection, entry, result);
        result.put("status", status);
        return result;
    }

    private String evaluate(Connection connection, Map<String, Object> entry, Map<String, Object> result)
            throws SQLException {
        if (Boolean.TRUE.equals(entry.get("metadataConflict"))) {
            return "METADATA_MISMATCH";
        }
        if (!Boolean.TRUE.equals(entry.get("jobRecorded"))
                && !Boolean.TRUE.equals(entry.get("ledgerEventPresent"))) {
            return "METADATA_MISMATCH";
        }
        Object name = entry.get("archiveFile");
        if (!(name instanceof String fileName) || !ArchiveService.FINAL_NAME.matcher(fileName).matches()
                || !(entry.get("fromSeq") instanceof Number from)
                || !(entry.get("toSeq") instanceof Number to)
                || !(entry.get("count") instanceof Number count)
                || !(entry.get("archiveSha256") instanceof String expectedDigest)) {
            return "FILE_NAME_UNSAFE";
        }
        Path file = archiveDirectory.resolve(fileName);
        if (!Files.isRegularFile(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            return Files.exists(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    ? "FILE_NAME_UNSAFE" : "ARCHIVE_FILE_MISSING";
        }
        byte[] bytes;
        try {
            if (Files.size(file) > maxBytes) {
                return "DIGEST_MISMATCH";
            }
            try (java.io.InputStream stream = Files.newInputStream(file)) {
                bytes = stream.readNBytes(maxBytes + 1);
            }
            if (bytes.length > maxBytes) {
                return "DIGEST_MISMATCH";
            }
        } catch (IOException exception) {
            return "ARCHIVE_FILE_UNREADABLE";
        }
        String actualDigest = ArchiveService.sha256Hex(bytes);
        result.put("actualSha256", actualDigest);
        if (!actualDigest.equals(expectedDigest)) {
            return "DIGEST_MISMATCH";
        }
        BundleVerifier.Result verified = BundleVerifier.verify(bytes,
                BundleVerifier.Options.pinned(pinnedPublicKey).withLimits(maxBytes, maxRecords));
        if (verified.status() != BundleVerifier.Status.VERIFIED) {
            List<String> codes = new ArrayList<>();
            for (BundleDiagnostic diagnostic : verified.diagnostics()) {
                codes.add(diagnostic.code().name());
                if (codes.size() >= 5) {
                    break;
                }
            }
            result.put("bundleDiagnostics", codes);
            return "BUNDLE_INVALID";
        }
        Map<String, Object> bundle;
        try {
            bundle = MAPPER.readValue(bytes, new TypeReference<Map<String, Object>>() { });
        } catch (IOException exception) {
            return "BUNDLE_INVALID";
        }
        if (!"RETENTION_ARCHIVE".equals(bundle.get("purpose"))
                || !String.valueOf(entry.get("bundleId")).equals(bundle.get("bundleId"))
                || !String.valueOf(count.longValue()).equals(String.valueOf(bundle.get("recordCount")))) {
            return "METADATA_MISMATCH";
        }
        if (!ledgerId.equals(bundle.get("ledgerId"))
                || !(bundle.get("signer") instanceof Map<?, ?> signerInfo)
                || !keyId.equals(signerInfo.get("keyId"))
                || !(bundle.get("headCheckpoint") instanceof Map<?, ?> head)
                || !String.valueOf(to.longValue()).equals(String.valueOf(head.get("seq")))) {
            result.put("detail", "Bundle ledger, signer or head checkpoint does not match this ledger");
            return "METADATA_MISMATCH";
        }
        String eventStatus = checkArchiveEvent(connection, entry, to.longValue());
        if (eventStatus != null) {
            result.put("detail", eventStatus);
            return "METADATA_MISMATCH";
        }
        return compareSkeleton(connection, bundle, from.longValue(), to.longValue(), count.longValue());
    }

    /**
     * The authorizing RECORDS_ARCHIVED event must come after the archived range and exist. When it
     * is live it must have been found and validated as a service event; when it was itself
     * archived, a later archive must cover it (checked by the coverage test).
     */
    private static String checkArchiveEvent(Connection connection, Map<String, Object> entry, long to)
            throws SQLException {
        if (!(entry.get("eventSeq") instanceof Number eventSeq) || eventSeq.longValue() <= to) {
            return "Authorizing archive event does not follow the archived range";
        }
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT archived FROM audit_events WHERE seq = ?")) {
            statement.setLong(1, eventSeq.longValue());
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()) {
                    return "Authorizing archive event is not in the ledger";
                }
                if (row.getInt(1) == 0 && !Boolean.TRUE.equals(entry.get("ledgerEventPresent"))) {
                    return "Live archive event is missing or unreadable";
                }
            }
        }
        return null;
    }

    private static Map<String, Object> coverage(Connection connection, List<Map<String, Object>> entries)
            throws SQLException {
        long archivedRows;
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*) FROM audit_events WHERE archived = 1");
                ResultSet row = statement.executeQuery()) {
            row.next();
            archivedRows = row.getLong(1);
        }
        List<long[]> ranges = new ArrayList<>();
        for (Map<String, Object> entry : entries) {
            if (entry.get("fromSeq") instanceof Number from && entry.get("toSeq") instanceof Number to) {
                ranges.add(new long[] {from.longValue(), to.longValue()});
            }
        }
        ranges.sort((left, right) -> Long.compare(left[0], right[0]));
        boolean continuous = true;
        long covered = 0;
        long expectedFrom = 1;
        for (long[] range : ranges) {
            if (range[0] != expectedFrom || range[1] < range[0]) {
                continuous = false;
            }
            covered += Math.max(0, range[1] - range[0] + 1);
            expectedFrom = range[1] + 1;
        }
        Map<String, Object> coverage = new LinkedHashMap<>();
        coverage.put("archivedRecordsInLedger", archivedRows);
        coverage.put("recordsCoveredByArchives", covered);
        coverage.put("rangesContiguousFromSeq1", continuous);
        coverage.put("complete", continuous && covered == archivedRows);
        return coverage;
    }

    private static String compareSkeleton(
            Connection connection, Map<String, Object> bundle, long from, long to, long count)
            throws SQLException {
        if (from < 1 || to < from || to - from + 1 != count) {
            return "METADATA_MISMATCH";
        }
        Object rawRecords = bundle.get("records");
        if (!(rawRecords instanceof List<?> records) || records.size() != count) {
            return "METADATA_MISMATCH";
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT seq, event_id, recorded_at, hash_version, content_hash, prev_hash, chain_hash, archived
                FROM audit_events WHERE seq BETWEEN ? AND ? ORDER BY seq
                """)) {
            statement.setLong(1, from);
            statement.setLong(2, to);
            try (ResultSet rows = statement.executeQuery()) {
                long expected = from;
                for (Object item : records) {
                    if (!rows.next() || rows.getLong("seq") != expected
                            || !(item instanceof Map<?, ?> record)) {
                        return "SKELETON_MISMATCH";
                    }
                    boolean same = rows.getInt("archived") == 1
                            && String.valueOf(rows.getLong("seq")).equals(String.valueOf(record.get("seq")))
                            && rows.getString("event_id").equals(record.get("eventId"))
                            && rows.getString("recorded_at").equals(record.get("timestamp"))
                            && String.valueOf(rows.getInt("hash_version"))
                                    .equals(String.valueOf(record.get("hashVersion")))
                            && rows.getString("content_hash").equals(record.get("contentHash"))
                            && rows.getString("prev_hash").equals(record.get("prevHash"))
                            && rows.getString("chain_hash").equals(record.get("chainHash"));
                    if (!same) {
                        return "SKELETON_MISMATCH";
                    }
                    expected++;
                }
                if (rows.next()) {
                    return "SKELETON_MISMATCH";
                }
            }
        }
        return "OK";
    }
}
