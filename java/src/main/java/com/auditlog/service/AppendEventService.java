package com.auditlog.service;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.core.crypto.PayloadCommitments;
import com.auditlog.core.crypto.V1Hashes;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.store.AuditRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

public final class AppendEventService {

    private static final DateTimeFormatter UTC_MICROS =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'")
                    .withZone(ZoneOffset.UTC);
    private static final Set<String> RESERVED_EVENT_TYPES = Set.of(
            "RECORD_REDACTED",
            "RECORDS_ARCHIVED",
            "BUNDLE_EXPORTED",
            "COMPLIANCE_REPORT_GENERATED");

    private final AuditRepository repository;
    private final AuditConfiguration configuration;
    private final CheckpointSigner signer;
    private final Clock clock;
    private final Supplier<UUID> eventIdSource;
    private final Supplier<byte[]> saltSource;

    public AppendEventService(
            AuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            Clock clock) {
        this(
                repository,
                configuration,
                signer,
                clock,
                UUID::randomUUID,
                PayloadCommitments::randomSalt);
    }

    public AppendEventService(
            AuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            Clock clock,
            Supplier<UUID> eventIdSource,
            Supplier<byte[]> saltSource) {
        this.repository = java.util.Objects.requireNonNull(repository, "repository");
        this.configuration = java.util.Objects.requireNonNull(configuration, "configuration");
        this.signer = java.util.Objects.requireNonNull(signer, "signer");
        this.clock = java.util.Objects.requireNonNull(clock, "clock");
        this.eventIdSource = java.util.Objects.requireNonNull(eventIdSource, "eventIdSource");
        this.saltSource = java.util.Objects.requireNonNull(saltSource, "saltSource");
    }

    public AppendedEvent append(AppendEventRequest request, String principalSource)
            throws SQLException {
        validateEnvelope(request, principalSource);
        Map<String, Object> payload = copyAndValidatePayload(request.payload());
        String occurredAt = normalizeOccurredAt(request.occurredAt());

        return repository.writeTransaction(connection -> appendLocked(
                connection, request, principalSource, payload, occurredAt));
    }

    private AppendedEvent appendLocked(
            Connection connection,
            AppendEventRequest request,
            String source,
            Map<String, Object> payload,
            String occurredAt) throws SQLException {
        Head head = readHead(connection);
        long seq = head.seq() + 1;
        if (seq <= 0 || seq > 9_007_199_254_740_991L) {
            throw new IllegalStateException("Ledger sequence exceeds the supported safe range");
        }

        Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
        if (occurredAt != null && Instant.parse(occurredAt).isAfter(now.plusSeconds(300))) {
            throw new IllegalArgumentException("occurredAt exceeds the 300-second future-skew limit");
        }
        Instant recordedInstant = head.recordedAt() == null
                ? now
                : max(now, Instant.parse(head.recordedAt()));
        String timestamp = UTC_MICROS.format(recordedInstant);
        String previousHash = head.chainHash() == null
                ? V1Hashes.genesisHash(configuration.ledgerId())
                : head.chainHash();
        String eventId = java.util.Objects.requireNonNull(
                eventIdSource.get(), "Event ID source returned null").toString();

        PayloadCommitments.CommitmentResult committed =
                PayloadCommitments.commit(payload, saltSource);
        String contentHash = V1Hashes.contentHash(V1Hashes.contentObject(
                seq,
                eventId,
                request.eventType(),
                request.actorId(),
                request.resourceType(),
                request.resourceId(),
                occurredAt,
                timestamp,
                source,
                committed.commitments()));
        String chainHash = V1Hashes.chainHash(previousHash, contentHash);

        insertEvent(connection, request, eventId, seq, timestamp, source, occurredAt,
                committed.commitments(), contentHash, previousHash, chainHash);
        insertLeaves(connection, seq, committed.leaves());
        if (seq % configuration.checkpointInterval() == 0) {
            insertCheckpoint(connection, seq, chainHash, timestamp);
        }

        return new AppendedEvent(
                request.eventType(),
                request.actorId(),
                request.resourceType(),
                request.resourceId(),
                payload,
                occurredAt,
                eventId,
                seq,
                timestamp,
                source,
                V1Hashes.HASH_VERSION,
                committed.commitments(),
                List.of(),
                contentHash,
                previousHash,
                chainHash);
    }

    private Map<String, Object> copyAndValidatePayload(Map<String, ?> payload) {
        byte[] canonical = CanonicalJson.canonicalize(payload);
        if (canonical.length > configuration.payloadLimitBytes()) {
            throw new IllegalArgumentException("Payload exceeds the configured byte limit");
        }
        JsonNode parsed = CanonicalJson.parse(canonical);
        if (!parsed.isObject()) {
            throw new IllegalArgumentException("Payload must be a JSON object");
        }
        Map<String, Object> copy = objectValue(parsed);
        validateConfiguredPayloadLimits(copy);
        return copy;
    }

    private void validateConfiguredPayloadLimits(Map<String, Object> payload) {
        List<PayloadFrame> pending = new ArrayList<>();
        payload.values().forEach(value -> pending.add(new PayloadFrame(value, 1)));
        int leaves = 0;
        while (!pending.isEmpty()) {
            PayloadFrame frame = pending.remove(pending.size() - 1);
            if (frame.value() instanceof Map<?, ?> object) {
                if (frame.depth() >= configuration.maxDepth()) {
                    throw new IllegalArgumentException("Payload nesting depth exceeds the configured limit");
                }
                object.values().forEach(value ->
                        pending.add(new PayloadFrame(value, frame.depth() + 1)));
            } else if (frame.value() instanceof List<?> array) {
                if (frame.depth() >= configuration.maxDepth()) {
                    throw new IllegalArgumentException("Payload nesting depth exceeds the configured limit");
                }
                array.forEach(value ->
                        pending.add(new PayloadFrame(value, frame.depth() + 1)));
            } else if (++leaves > configuration.maxLeaves()) {
                throw new IllegalArgumentException("Payload exceeds the configured scalar leaf limit");
            }
        }
    }

    private static Map<String, Object> objectValue(JsonNode node) {
        Map<String, Object> result = new LinkedHashMap<>();
        node.properties().forEach(entry -> result.put(entry.getKey(), jsonValue(entry.getValue())));
        return result;
    }

    private static Object jsonValue(JsonNode node) {
        if (node.isObject()) {
            return objectValue(node);
        }
        if (node.isArray()) {
            List<Object> result = new ArrayList<>();
            node.elements().forEachRemaining(value -> result.add(jsonValue(value)));
            return result;
        }
        if (node.isTextual()) {
            return node.textValue();
        }
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        if (node.isNull()) {
            return null;
        }
        if (node.isIntegralNumber()) {
            return node.bigIntegerValue();
        }
        if (node.isFloatingPointNumber()) {
            return node.doubleValue();
        }
        throw new IllegalArgumentException("Payload contains an unsupported JSON value");
    }

    private void validateEnvelope(AppendEventRequest request, String source) {
        if (request == null) {
            throw new IllegalArgumentException("Event request is required");
        }
        requireText(request.eventType(), "eventType");
        requireText(request.actorId(), "actorId");
        requireText(request.resourceType(), "resourceType");
        requireText(request.resourceId(), "resourceId");
        if (RESERVED_EVENT_TYPES.contains(request.eventType())) {
            throw new IllegalArgumentException("Reserved system event types cannot be submitted");
        }
        requireText(source, "principal source");
        if ("system".equals(source)) {
            throw new IllegalArgumentException("System source is reserved for internal events");
        }
        Map<String, Object> envelopeFields = new LinkedHashMap<>();
        envelopeFields.put("eventType", request.eventType());
        envelopeFields.put("actorId", request.actorId());
        envelopeFields.put("resourceType", request.resourceType());
        envelopeFields.put("resourceId", request.resourceId());
        if (request.occurredAt() != null) {
            envelopeFields.put("occurredAt", request.occurredAt());
        }
        int envelopeBytes = CanonicalJson.canonicalize(envelopeFields).length;
        int payloadBytes = CanonicalJson.canonicalize(request.payload()).length;
        if ((long) envelopeBytes + payloadBytes + 11 > configuration.requestLimitBytes()) {
            throw new IllegalArgumentException("Event request exceeds the configured byte limit");
        }
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()
                || value.getBytes(StandardCharsets.UTF_8).length > CanonicalJson.MAX_INPUT_BYTES) {
            throw new IllegalArgumentException(field + " must be non-empty and within the request limit");
        }
        CanonicalJson.canonicalize(Map.of("value", value));
    }

    private static String normalizeOccurredAt(String value) {
        if (value == null) {
            return null;
        }
        try {
            Instant instant = OffsetDateTime.parse(value).toInstant().truncatedTo(ChronoUnit.MICROS);
            return UTC_MICROS.format(instant);
        } catch (DateTimeException exception) {
            throw new IllegalArgumentException("occurredAt must be a valid ISO-8601 timestamp", exception);
        }
    }

    private static Instant max(Instant first, Instant second) {
        return first.isAfter(second) ? first : second;
    }

    private static Head readHead(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("""
                        SELECT seq, chain_hash, recorded_at
                        FROM audit_events
                        ORDER BY seq DESC
                        LIMIT 1
                        """)) {
            if (!result.next()) {
                return new Head(0, null, null);
            }
            return new Head(
                    result.getLong("seq"),
                    result.getString("chain_hash"),
                    result.getString("recorded_at"));
        }
    }

    private static void insertEvent(
            Connection connection,
            AppendEventRequest request,
            String eventId,
            long seq,
            String timestamp,
            String source,
            String occurredAt,
            Map<String, Object> commitments,
            String contentHash,
            String previousHash,
            String chainHash) throws SQLException {
        try (var statement = connection.prepareStatement("""
                INSERT INTO audit_events(
                    seq, event_id, event_type, actor_id, resource_type, resource_id,
                    occurred_at, recorded_at, source, payload_commitments, hash_version,
                    content_hash, prev_hash, chain_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setLong(1, seq);
            statement.setString(2, eventId);
            statement.setString(3, request.eventType());
            statement.setString(4, request.actorId());
            statement.setString(5, request.resourceType());
            statement.setString(6, request.resourceId());
            statement.setString(7, occurredAt);
            statement.setString(8, timestamp);
            statement.setString(9, source);
            statement.setString(10, new String(
                    CanonicalJson.canonicalize(commitments), StandardCharsets.UTF_8));
            statement.setInt(11, V1Hashes.HASH_VERSION);
            statement.setString(12, contentHash);
            statement.setString(13, previousHash);
            statement.setString(14, chainHash);
            statement.executeUpdate();
        }
    }

    private static void insertLeaves(
            Connection connection,
            long seq,
            Map<String, PayloadCommitments.PayloadLeaf> leaves) throws SQLException {
        try (var statement = connection.prepareStatement("""
                INSERT INTO payload_leaves(seq, pointer, salt, value)
                VALUES (?, ?, ?, ?)
                """)) {
            for (Map.Entry<String, PayloadCommitments.PayloadLeaf> entry : leaves.entrySet()) {
                statement.setLong(1, seq);
                statement.setString(2, entry.getKey());
                statement.setString(3, HexFormat.of().formatHex(entry.getValue().salt()));
                statement.setString(4, new String(
                        CanonicalJson.canonicalize(entry.getValue().value()), StandardCharsets.UTF_8));
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    private void insertCheckpoint(
            Connection connection, long seq, String chainHash, String createdAt) throws SQLException {
        Map<String, Object> checkpoint = signer.signCheckpoint(
                configuration.ledgerId(), seq, chainHash, createdAt);
        try (var statement = connection.prepareStatement("""
                INSERT INTO checkpoints(seq, chain_hash, created_at, key_id, signature)
                VALUES (?, ?, ?, ?, ?)
                """)) {
            statement.setLong(1, seq);
            statement.setString(2, chainHash);
            statement.setString(3, createdAt);
            statement.setString(4, (String) checkpoint.get("keyId"));
            statement.setString(5, (String) checkpoint.get("signature"));
            statement.executeUpdate();
        }
    }

    private record Head(long seq, String chainHash, String recordedAt) {
    }

    private record PayloadFrame(Object value, int depth) {
    }
}
