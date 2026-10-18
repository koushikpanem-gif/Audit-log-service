package com.auditlog.service;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.core.crypto.V1Hashes;
import com.auditlog.domain.BundleCompleteness;
import com.auditlog.domain.BundlePurpose;
import com.auditlog.domain.BundleSelection;
import com.auditlog.store.AuditRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

/**
 * Builds signed audit-export-bundle/v1 documents. In ONE write transaction it captures the data
 * head (throughSeq), selects matching live records, appends BUNDLE_EXPORTED, signs a checkpoint at
 * the post-event head and signs the complete body. Any rejection throws inside the transaction so
 * the meta-event and checkpoint are rolled back.
 */
public final class ExportBundleService {

    public static final String FORMAT = "audit-export-bundle/v1";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AuditRepository repository;
    private final AuditConfiguration configuration;
    private final CheckpointSigner signer;
    private final AppendEventService appendService;
    private final int maxRecords;
    private final int maxBytes;

    public ExportBundleService(
            AuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService) {
        this(repository, configuration, signer, appendService,
                configuration.exportMaxRecords(), configuration.exportMaxBytes());
    }

    public ExportBundleService(
            AuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService,
            int maxRecords,
            int maxBytes) {
        if (maxRecords < 1 || maxRecords > AuditConfiguration.MAX_EXPORT_RECORDS
                || maxBytes < 1 || maxBytes > AuditConfiguration.MAX_EXPORT_BYTES) {
            throw new IllegalArgumentException("Export limits must be positive and within supported bounds");
        }
        this.repository = repository;
        this.configuration = configuration;
        this.signer = signer;
        this.appendService = appendService;
        this.maxRecords = maxRecords;
        this.maxBytes = maxBytes;
    }

    public int maxRecords() {
        return maxRecords;
    }

    public int maxBytes() {
        return maxBytes;
    }

    /** Normal export: returns the exact final JCS bytes of the signed bundle. */
    public byte[] export(BundleSelection selection, String exportedBy) throws SQLException {
        return export(BundlePurpose.EXPORT, selection, exportedBy);
    }

    /** Purpose-aware entry point reused by later archive and report actions. */
    public byte[] export(BundlePurpose purpose, BundleSelection selection, String exportedBy)
            throws SQLException {
        if (purpose == null || selection == null) {
            throw new IllegalArgumentException("purpose and selection are required");
        }
        if (exportedBy == null || exportedBy.isBlank()) {
            throw new IllegalArgumentException("exportedBy is required");
        }
        if (purpose == BundlePurpose.EXPORT
                && (selection.seqFrom() != null || selection.seqTo() != null
                        || (selection.actorId() == null && selection.resourceId() == null))) {
            throw new IllegalArgumentException(
                    "An export requires actorId or resourceId and uses no sequence bounds");
        }
        if (purpose == BundlePurpose.RETENTION_ARCHIVE
                && (selection.hasOrdinaryFilters()
                        || selection.seqFrom() == null || selection.seqTo() == null)) {
            throw new IllegalArgumentException(
                    "An archive export uses sequence bounds and no ordinary filters");
        }
        return repository.writeTransaction(connection ->
                exportLocked(connection, purpose, selection, exportedBy));
    }

    private byte[] exportLocked(
            Connection connection, BundlePurpose purpose, BundleSelection selection, String exportedBy)
            throws SQLException {
        long throughSeq = 0;
        try (Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("SELECT MAX(seq) FROM audit_events")) {
            if (result.next()) {
                throughSeq = result.getLong(1);
            }
        }

        List<Map<String, Object>> records = selectRecords(connection, selection, throughSeq);
        byte[] recordsCanonical = CanonicalJson.canonicalize(
                records, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE);
        String recordsDigest = sha256Hex(recordsCanonical);
        String bundleId = UUID.randomUUID().toString();

        Map<String, Object> eventPayload = new LinkedHashMap<>();
        eventPayload.put("bundleId", bundleId);
        eventPayload.put("purpose", purpose.name());
        eventPayload.put("throughSeq", throughSeq);
        eventPayload.put("recordCount", records.size());
        eventPayload.put("recordsDigest", recordsDigest);
        eventPayload.put("selectionDigest", sha256Hex(CanonicalJson.canonicalize(selection.toMap())));
        eventPayload.put("requestedBy", exportedBy);
        AppendedEvent exportEvent = appendService.appendSystemEvent(
                connection, "BUNDLE_EXPORTED", exportedBy, "AUDIT_EXPORT", bundleId, eventPayload);
        Map<String, Object> checkpoint = appendService.storeCheckpoint(
                connection, exportEvent.seq(), exportEvent.chainHash(), exportEvent.timestamp());

        Map<String, Object> bundle = signedBundle(
                purpose, bundleId, selection, throughSeq, records, recordsDigest, exportEvent, checkpoint,
                exportedBy);
        byte[] finalBytes = CanonicalJson.canonicalize(
                bundle, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE);
        if (finalBytes.length > maxBytes) {
            throw tooLarge();
        }
        return finalBytes;
    }

    /** Assembles and signs a v1 bundle body; shared by exports and compliance-report evidence. */
    Map<String, Object> signedBundle(
            BundlePurpose purpose,
            String bundleId,
            BundleSelection selection,
            long throughSeq,
            List<Map<String, Object>> records,
            String recordsDigest,
            AppendedEvent headEvent,
            Map<String, Object> checkpoint,
            String exportedBy) {
        Map<String, Object> headCheckpoint = new LinkedHashMap<>();
        headCheckpoint.put("seq", headEvent.seq());
        headCheckpoint.put("chainHash", headEvent.chainHash());
        headCheckpoint.put("createdAt", headEvent.timestamp());
        headCheckpoint.put("keyId", checkpoint.get("keyId"));
        headCheckpoint.put("signature", checkpoint.get("signature"));

        Map<String, Object> signerInfo = new LinkedHashMap<>();
        signerInfo.put("keyId", signer.keyId());
        signerInfo.put("publicKey", signer.publicKeyBase64());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("format", FORMAT);
        body.put("bundleId", bundleId);
        body.put("purpose", purpose.name());
        body.put("ledgerId", configuration.ledgerId());
        body.put("hashAlgorithm", "SHA-256");
        body.put("hashVersion", V1Hashes.HASH_VERSION);
        body.put("genesisHash", V1Hashes.genesisHash(configuration.ledgerId()));
        body.put("signatureAlgorithm", "Ed25519");
        body.put("exportedAt", headEvent.timestamp());
        body.put("exportedBy", exportedBy);
        body.put("selection", selection.toMap());
        body.put("completeness", new BundleCompleteness(throughSeq).toMap());
        body.put("recordCount", records.size());
        body.put("recordsDigest", recordsDigest);
        body.put("records", records);
        body.put("headCheckpoint", headCheckpoint);
        body.put("signer", signerInfo);

        Map<String, Object> bundle = new LinkedHashMap<>(body);
        bundle.put("signature", signer.signMessage(body, Integer.MAX_VALUE));
        return bundle;
    }

    private List<Map<String, Object>> selectRecords(
            Connection connection, BundleSelection selection, long throughSeq) throws SQLException {
        List<Map<String, Object>> records = new ArrayList<>();
        // Incremental budget on record bytes alone; the exact check is the final one on the bundle.
        long bytes = 0;
        try (PreparedStatement statement =
                        prepareSelection(connection, selection, throughSeq, (long) maxRecords + 1);
                ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                if (records.size() >= maxRecords) {
                    throw tooLarge();
                }
                Map<String, Object> record = readRecord(connection, result);
                bytes += CanonicalJson.canonicalize(
                        record, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE).length + 1L;
                if (bytes > maxBytes) {
                    throw tooLarge();
                }
                records.add(record);
            }
        }
        return records;
    }

    /** Shared by the small-bundle and export-set builders so both select identically. */
    static PreparedStatement prepareSelection(
            Connection connection, BundleSelection selection, long throughSeq, Long limit)
            throws SQLException {
        StringBuilder sql = new StringBuilder(
                "SELECT seq, event_id, event_type, actor_id, resource_type, resource_id, "
                        + "occurred_at, recorded_at, source, hash_version, payload_commitments, "
                        + "content_hash, prev_hash, chain_hash FROM audit_events "
                        + "WHERE archived = 0 AND seq <= ?");
        List<Object> parameters = new ArrayList<>();
        parameters.add(throughSeq);
        filter(sql, parameters, "actor_id = ?", selection.actorId());
        filter(sql, parameters, "resource_type = ?", selection.resourceType());
        filter(sql, parameters, "resource_id = ?", selection.resourceId());
        filter(sql, parameters, "event_type = ?", selection.eventType());
        filter(sql, parameters, "recorded_at >= ?", selection.from());
        filter(sql, parameters, "recorded_at <= ?", selection.to());
        filter(sql, parameters, "seq >= ?", selection.seqFrom());
        filter(sql, parameters, "seq <= ?", selection.seqTo());
        sql.append(" ORDER BY seq");
        if (limit != null) {
            sql.append(" LIMIT ?");
            parameters.add(limit);
        }
        PreparedStatement statement = connection.prepareStatement(sql.toString());
        try {
            for (int index = 0; index < parameters.size(); index++) {
                Object value = parameters.get(index);
                if (value instanceof Long number) {
                    statement.setLong(index + 1, number);
                } else {
                    statement.setString(index + 1, (String) value);
                }
            }
        } catch (SQLException | RuntimeException exception) {
            statement.close();
            throw exception;
        }
        return statement;
    }

    private static void filter(StringBuilder sql, List<Object> parameters, String clause, Object value) {
        if (value != null) {
            sql.append(" AND ").append(clause);
            parameters.add(value);
        }
    }

    private ExportLimitExceededException tooLarge() {
        return new ExportLimitExceededException(maxRecords, maxBytes);
    }

    static Map<String, Object> readRecord(Connection connection, ResultSet row) throws SQLException {
        long seq = row.getLong("seq");
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("seq", seq);
        record.put("eventId", row.getString("event_id"));
        record.put("eventType", row.getString("event_type"));
        record.put("actorId", row.getString("actor_id"));
        record.put("resourceType", row.getString("resource_type"));
        record.put("resourceId", row.getString("resource_id"));
        record.put("occurredAt", row.getString("occurred_at"));
        record.put("timestamp", row.getString("recorded_at"));
        record.put("source", row.getString("source"));
        record.put("hashVersion", row.getInt("hash_version"));
        try {
            record.put("payloadCommitments", MAPPER.readValue(
                    row.getString("payload_commitments"), new TypeReference<Map<String, Object>>() { }));
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Stored payload commitments are malformed", exception);
        }
        record.put("disclosedLeaves", readLeaves(connection, seq));
        record.put("contentHash", row.getString("content_hash"));
        record.put("prevHash", row.getString("prev_hash"));
        record.put("chainHash", row.getString("chain_hash"));
        return record;
    }

    private static Map<String, Object> readLeaves(Connection connection, long seq) throws SQLException {
        Map<String, Object> leaves = new TreeMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pointer, salt, value FROM payload_leaves WHERE seq = ? ORDER BY pointer")) {
            statement.setLong(1, seq);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    Map<String, Object> leaf = new LinkedHashMap<>();
                    leaf.put("salt", result.getString("salt"));
                    try {
                        leaf.put("value", MAPPER.readValue(result.getString("value"), Object.class));
                    } catch (JsonProcessingException exception) {
                        throw new IllegalStateException("Stored leaf value is malformed", exception);
                    }
                    leaves.put(result.getString("pointer"), leaf);
                }
            }
        }
        return leaves;
    }

    private static String sha256Hex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    /** Rejection of an oversized small export; carries only the configured limits, never data. */
    public static final class ExportLimitExceededException extends RuntimeException {
        private final int maxRecords;
        private final int maxBytes;

        public ExportLimitExceededException(int maxRecords, int maxBytes) {
            super("Selection exceeds the configured small-export limits; narrow the selection "
                    + "or create a chunked export set with POST /audit/export-sets");
            this.maxRecords = maxRecords;
            this.maxBytes = maxBytes;
        }

        public int maxRecords() {
            return maxRecords;
        }

        public int maxBytes() {
            return maxBytes;
        }
    }
}
