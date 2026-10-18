package com.auditlog.service;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.core.crypto.V1Hashes;
import com.auditlog.store.AuditRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
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
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

/**
 * Builds exact v1 signed export bundles for small selections. Selection, checkpoint signing and
 * the BUNDLE_EXPORTED event happen in one write transaction so the selection head and the
 * post-event head are both known and cannot be confused.
 */
public final class ExportBundleService {

    public static final int DEFAULT_MAX_RECORDS = 1000;
    public static final int DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
    public static final String FORMAT = "audit-export-bundle/v1";

    private static final DateTimeFormatter UTC_MICROS =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'")
                    .withZone(ZoneOffset.UTC);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AuditRepository repository;
    private final AuditConfiguration configuration;
    private final CheckpointSigner signer;
    private final AppendEventService appendService;
    private final Clock clock;
    private final int maxRecords;
    private final int maxBytes;

    public ExportBundleService(
            AuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService,
            Clock clock) {
        this(repository, configuration, signer, appendService, clock,
                DEFAULT_MAX_RECORDS, DEFAULT_MAX_BYTES);
    }

    public ExportBundleService(
            AuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService,
            Clock clock,
            int maxRecords,
            int maxBytes) {
        if (maxRecords < 1 || maxBytes < 1) {
            throw new IllegalArgumentException("Export limits must be positive");
        }
        this.repository = repository;
        this.configuration = configuration;
        this.signer = signer;
        this.appendService = appendService;
        this.clock = clock;
        this.maxRecords = maxRecords;
        this.maxBytes = maxBytes;
    }

    public Map<String, Object> export(String actorId, String resourceId, String exportedBy)
            throws SQLException {
        boolean byActor = actorId != null;
        if (byActor == (resourceId != null)) {
            throw new IllegalArgumentException("Provide exactly one of actorId or resourceId");
        }
        String selector = byActor ? actorId : resourceId;
        if (selector.isBlank() || selector.getBytes(StandardCharsets.UTF_8).length > 1024) {
            throw new IllegalArgumentException("Selection value must be non-empty and at most 1024 bytes");
        }
        CanonicalJson.canonicalize(Map.of("value", selector));
        if (exportedBy == null || exportedBy.isBlank()) {
            throw new IllegalArgumentException("exportedBy is required");
        }
        return repository.writeTransaction(connection ->
                exportLocked(connection, byActor, selector, exportedBy));
    }

    private Map<String, Object> exportLocked(
            Connection connection, boolean byActor, String selector, String exportedBy)
            throws SQLException {
        long headSeq;
        String headHash;
        try (Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery(
                        "SELECT seq, chain_hash FROM audit_events ORDER BY seq DESC LIMIT 1")) {
            if (!result.next()) {
                throw new EmptyLedgerException("An empty ledger has no checkpoint to export");
            }
            headSeq = result.getLong("seq");
            headHash = result.getString("chain_hash");
        }

        List<Map<String, Object>> records = selectRecords(connection, byActor, selector);
        byte[] recordsCanonical = CanonicalJson.canonicalize(
                records, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE);
        String recordsDigest = sha256Hex(recordsCanonical);

        Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
        String exportedAt = UTC_MICROS.format(now);
        Map<String, Object> checkpoint = appendService.storeCheckpoint(
                connection, headSeq, headHash, exportedAt);

        String bundleId = UUID.randomUUID().toString();
        Map<String, Object> eventPayload = new LinkedHashMap<>();
        eventPayload.put("bundleId", bundleId);
        eventPayload.put("purpose", "EXPORT");
        eventPayload.put("selectionType", byActor ? "ACTOR" : "RESOURCE");
        eventPayload.put("selectionHeadSeq", headSeq);
        eventPayload.put("selectionHeadChainHash", headHash);
        eventPayload.put("recordCount", records.size());
        eventPayload.put("recordsDigest", recordsDigest);
        eventPayload.put("requestedBy", exportedBy);
        AppendedEvent exportEvent = appendService.appendSystemEvent(
                connection, "BUNDLE_EXPORTED", exportedBy, "AUDIT_EXPORT", bundleId, eventPayload);

        Map<String, Object> criteria = new LinkedHashMap<>();
        criteria.put(byActor ? "actorId" : "resourceId", selector);
        Map<String, Object> selection = new LinkedHashMap<>();
        selection.put("criteria", criteria);
        selection.put("order", "seq-asc");
        selection.put("archivedRecords", "EXCLUDED");

        Map<String, Object> completeness = new LinkedHashMap<>();
        completeness.put("statement",
                "All live non-archived records matching the selection at selectionHead; "
                        + "no global inclusion proof, completeness is asserted by the signer");
        completeness.put("selectionHeadSeq", headSeq);
        completeness.put("selectionHeadChainHash", headHash);
        completeness.put("postEventSeq", exportEvent.seq());
        completeness.put("postEventChainHash", exportEvent.chainHash());
        completeness.put("exportEventId", exportEvent.eventId());

        Map<String, Object> headCheckpoint = new LinkedHashMap<>();
        headCheckpoint.put("seq", headSeq);
        headCheckpoint.put("chainHash", headHash);
        headCheckpoint.put("createdAt", exportedAt);
        headCheckpoint.put("keyId", checkpoint.get("keyId"));
        headCheckpoint.put("signature", checkpoint.get("signature"));

        Map<String, Object> signerInfo = new LinkedHashMap<>();
        signerInfo.put("keyId", signer.keyId());
        signerInfo.put("publicKey", signer.publicKeyBase64());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("format", FORMAT);
        body.put("bundleId", bundleId);
        body.put("purpose", "EXPORT");
        body.put("ledgerId", configuration.ledgerId());
        body.put("hashAlgorithm", "SHA-256");
        body.put("hashVersion", V1Hashes.HASH_VERSION);
        body.put("genesisHash", V1Hashes.genesisHash(configuration.ledgerId()));
        body.put("signatureAlgorithm", "Ed25519");
        body.put("exportedAt", exportedAt);
        body.put("exportedBy", exportedBy);
        body.put("selection", selection);
        body.put("completeness", completeness);
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
            Connection connection, boolean byActor, String selector) throws SQLException {
        String column = byActor ? "actor_id" : "resource_id";
        String sql = "SELECT seq, event_id, event_type, actor_id, resource_type, resource_id, "
                + "occurred_at, recorded_at, source, hash_version, payload_commitments, "
                + "content_hash, prev_hash, chain_hash FROM audit_events "
                + "WHERE archived = 0 AND " + column + " = ? ORDER BY seq LIMIT ?";
        List<Map<String, Object>> records = new ArrayList<>();
        long bytes = 0;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, selector);
            statement.setInt(2, maxRecords + 1);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    if (records.size() >= maxRecords) {
                        throw tooLarge();
                    }
                    Map<String, Object> record = readRecord(connection, result);
                    bytes += CanonicalJson.canonicalize(
                            record, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE).length;
                    if (bytes > maxBytes) {
                        throw tooLarge();
                    }
                    records.add(record);
                }
            }
        }
        return records;
    }

    private ExportTooLargeException tooLarge() {
        return new ExportTooLargeException(
                "Selection exceeds the small-export limit of " + maxRecords + " records or "
                        + maxBytes + " bytes; narrow the selection (export-set chunks are a later step)");
    }

    private Map<String, Object> readRecord(Connection connection, ResultSet row) throws SQLException {
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

    public static final class ExportTooLargeException extends RuntimeException {
        public ExportTooLargeException(String message) {
            super(message);
        }
    }

    public static final class EmptyLedgerException extends RuntimeException {
        public EmptyLedgerException(String message) {
            super(message);
        }
    }
}
