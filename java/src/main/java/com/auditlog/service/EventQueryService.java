package com.auditlog.service;

import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.PayloadCommitments;
import com.auditlog.store.AuditRepository;
import com.auditlog.web.ApiException;
import com.fasterxml.jackson.databind.JsonNode;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class EventQueryService {

    private static final DateTimeFormatter UTC_MICROS =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'")
                    .withZone(ZoneOffset.UTC);

    private final AuditRepository repository;
    private final byte[] cursorSigningKey;

    public EventQueryService(AuditRepository repository, byte[] cursorSigningKey) {
        this.repository = repository;
        this.cursorSigningKey = cursorSigningKey.clone();
    }

    public EventPage list(
            String actorId,
            String resourceType,
            String resourceId,
            String eventType,
            String from,
            String to,
            Integer requestedLimit,
            String requestedOrder,
            String cursor) throws SQLException {
        EventFilters filters = normalizeFilters(
                actorId, resourceType, resourceId, eventType, from, to);
        int limit = requestedLimit == null ? 50 : requestedLimit;
        if (limit < 1 || limit > 500) {
            throw invalid("limit must be between 1 and 500");
        }
        String order = requestedOrder == null ? "asc" : requestedOrder.toLowerCase(java.util.Locale.ROOT);
        if (!order.equals("asc") && !order.equals("desc")) {
            throw invalid("order must be asc or desc");
        }

        CursorState state = cursor == null
                ? null
                : decodeCursor(cursor, filters, order);
        return repository.readSnapshot(connection -> {
            long asOfSeq = state == null ? currentHead(connection) : state.asOfSeq();
            List<StoredEvent> selected = selectEvents(
                    connection,
                    filters,
                    order,
                    limit + 1,
                    asOfSeq,
                    state == null ? null : state.lastSeq());
            boolean more = selected.size() > limit;
            if (more) {
                selected = new ArrayList<>(selected.subList(0, limit));
            }
            List<EventView> items = new ArrayList<>(selected.size());
            for (StoredEvent event : selected) {
                items.add(toView(connection, event));
            }
            String nextCursor = more && !selected.isEmpty()
                    ? encodeCursor(filters, order, asOfSeq,
                            selected.get(selected.size() - 1).seq())
                    : null;
            return new EventPage(items, nextCursor);
        });
    }

    public EventView getById(String eventId) throws SQLException {
        if (eventId == null || eventId.isBlank() || eventId.length() > 256) {
            throw invalid("eventId must be non-empty and within 256 characters");
        }
        return repository.readSnapshot(connection -> {
            try (var statement = connection.prepareStatement("""
                    SELECT seq, event_id, event_type, actor_id, resource_type, resource_id,
                           occurred_at, recorded_at, source, payload_commitments, hash_version,
                           content_hash, prev_hash, chain_hash
                    FROM audit_events
                    WHERE event_id = ? AND archived = 0
                    """)) {
                statement.setString(1, eventId);
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        throw new ApiException(404, "NOT_FOUND", "Audit event was not found");
                    }
                    return toView(connection, readEvent(result));
                }
            }
        });
    }

    public List<CheckpointView> listCheckpoints(Integer requestedLimit) throws SQLException {
        int limit = requestedLimit == null ? 50 : requestedLimit;
        if (limit < 1 || limit > 500) {
            throw invalid("limit must be between 1 and 500");
        }
        return repository.readSnapshot(connection -> {
            List<CheckpointView> checkpoints = new ArrayList<>();
            try (var statement = connection.prepareStatement("""
                    SELECT seq, chain_hash, created_at, key_id, signature
                    FROM checkpoints
                    ORDER BY seq DESC
                    LIMIT ?
                    """)) {
                statement.setInt(1, limit);
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        checkpoints.add(new CheckpointView(
                                result.getLong("seq"),
                                result.getString("chain_hash"),
                                result.getString("created_at"),
                                result.getString("key_id"),
                                result.getString("signature")));
                    }
                }
            }
            return List.copyOf(checkpoints);
        });
    }

    private static EventFilters normalizeFilters(
            String actorId,
            String resourceType,
            String resourceId,
            String eventType,
            String from,
            String to) {
        String normalizedFrom = normalizeTimestamp(from, "from");
        String normalizedTo = normalizeTimestamp(to, "to");
        if (normalizedFrom != null && normalizedTo != null
                && Instant.parse(normalizedFrom).isAfter(Instant.parse(normalizedTo))) {
            throw invalid("from must not be later than to");
        }
        return new EventFilters(
                optionalFilter(actorId, "actorId"),
                optionalFilter(resourceType, "resourceType"),
                optionalFilter(resourceId, "resourceId"),
                optionalFilter(eventType, "eventType"),
                normalizedFrom,
                normalizedTo);
    }

    private static String optionalFilter(String value, String name) {
        if (value == null) {
            return null;
        }
        if (value.isBlank() || value.length() > 256) {
            throw invalid(name + " filter must be non-empty and at most 256 characters");
        }
        return value;
    }

    private static String normalizeTimestamp(String value, String field) {
        if (value == null) {
            return null;
        }
        try {
            Instant instant = OffsetDateTime.parse(value).toInstant().truncatedTo(ChronoUnit.MICROS);
            return UTC_MICROS.format(instant);
        } catch (DateTimeException exception) {
            throw invalid(field + " must be an ISO-8601 timestamp with an offset");
        }
    }

    private static long currentHead(Connection connection) throws SQLException {
        try (var statement = connection.createStatement();
                ResultSet result = statement.executeQuery("SELECT COALESCE(MAX(seq), 0) FROM audit_events")) {
            result.next();
            return result.getLong(1);
        }
    }

    private static List<StoredEvent> selectEvents(
            Connection connection,
            EventFilters filters,
            String order,
            int limit,
            long asOfSeq,
            Long lastSeq) throws SQLException {
        StringBuilder sql = new StringBuilder("""
                SELECT seq, event_id, event_type, actor_id, resource_type, resource_id,
                       occurred_at, recorded_at, source, payload_commitments, hash_version,
                       content_hash, prev_hash, chain_hash
                FROM audit_events
                WHERE archived = 0 AND seq <= ?
                """);
        List<Object> parameters = new ArrayList<>();
        parameters.add(asOfSeq);
        appendFilter(sql, parameters, "actor_id", filters.actorId());
        appendFilter(sql, parameters, "resource_type", filters.resourceType());
        appendFilter(sql, parameters, "resource_id", filters.resourceId());
        appendFilter(sql, parameters, "event_type", filters.eventType());
        appendRange(sql, parameters, "recorded_at", ">=", filters.from());
        appendRange(sql, parameters, "recorded_at", "<=", filters.to());
        if (lastSeq != null) {
            sql.append(order.equals("asc") ? " AND seq > ?" : " AND seq < ?");
            parameters.add(lastSeq);
        }
        sql.append(" ORDER BY seq ").append(order.toUpperCase(java.util.Locale.ROOT)).append(" LIMIT ?");
        parameters.add(limit);
        try (var statement = connection.prepareStatement(sql.toString())) {
            for (int index = 0; index < parameters.size(); index++) {
                statement.setObject(index + 1, parameters.get(index));
            }
            List<StoredEvent> events = new ArrayList<>();
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    events.add(readEvent(result));
                }
            }
            return events;
        }
    }

    private static void appendFilter(
            StringBuilder sql, List<Object> parameters, String column, String value) {
        if (value != null) {
            sql.append(" AND ").append(column).append(" = ?");
            parameters.add(value);
        }
    }

    private static void appendRange(
            StringBuilder sql, List<Object> parameters, String column, String operator, String value) {
        if (value != null) {
            sql.append(" AND ").append(column).append(' ').append(operator).append(" ?");
            parameters.add(value);
        }
    }

    private static StoredEvent readEvent(ResultSet result) throws SQLException {
        return new StoredEvent(
                result.getLong("seq"),
                result.getString("event_id"),
                result.getString("event_type"),
                result.getString("actor_id"),
                result.getString("resource_type"),
                result.getString("resource_id"),
                result.getString("occurred_at"),
                result.getString("recorded_at"),
                result.getString("source"),
                result.getString("payload_commitments"),
                result.getInt("hash_version"),
                result.getString("content_hash"),
                result.getString("prev_hash"),
                result.getString("chain_hash"));
    }

    private static EventView toView(Connection connection, StoredEvent event) throws SQLException {
        JsonNode parsed;
        try {
            parsed = CanonicalJson.parse(
                    event.payloadCommitments().getBytes(StandardCharsets.UTF_8));
        } catch (IllegalArgumentException exception) {
            throw new SQLException("Stored payload commitments are malformed", exception);
        }
        if (!parsed.isObject()) {
            throw new SQLException("Stored payload commitments are not a JSON object");
        }
        Map<String, Object> commitments = objectValue(parsed);
        Map<String, PayloadCommitments.PayloadLeaf> leaves = new LinkedHashMap<>();
        try (var statement = connection.prepareStatement("""
                SELECT pointer, salt, value FROM payload_leaves WHERE seq = ? ORDER BY pointer
                """)) {
            statement.setLong(1, event.seq());
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    byte[] salt = HexFormat.of().parseHex(result.getString("salt"));
                    JsonNode valueNode = CanonicalJson.parse(
                            result.getString("value").getBytes(StandardCharsets.UTF_8));
                    leaves.put(result.getString("pointer"),
                            new PayloadCommitments.PayloadLeaf(salt, jsonValue(valueNode)));
                }
            }
        } catch (IllegalArgumentException exception) {
            throw new SQLException("Stored payload leaf is malformed", exception);
        }
        PayloadCommitments.RevealResult revealed;
        try {
            revealed = PayloadCommitments.reveal(commitments, leaves);
        } catch (IllegalArgumentException exception) {
            throw new SQLException("Stored payload commitments do not match their leaves", exception);
        }
        return new EventView(
                event.eventType(),
                event.actorId(),
                event.resourceType(),
                event.resourceId(),
                revealed.payload(),
                event.occurredAt(),
                event.eventId(),
                event.seq(),
                event.recordedAt(),
                event.source(),
                event.hashVersion(),
                commitments,
                revealed.redactedPaths(),
                event.contentHash(),
                event.prevHash(),
                event.chainHash());
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
            List<Object> values = new ArrayList<>();
            node.elements().forEachRemaining(child -> values.add(jsonValue(child)));
            return values;
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
        throw new IllegalArgumentException("Stored JSON value is unsupported");
    }

    private String encodeCursor(
            EventFilters filters, String order, long asOfSeq, long lastSeq) {
        Map<String, Object> payload = cursorPayload(filters, order, asOfSeq, lastSeq);
        byte[] bytes = CanonicalJson.canonicalize(payload);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
                + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(bytes));
    }

    private CursorState decodeCursor(String token, EventFilters filters, String order) {
        if (token.length() > 4096) {
            throw invalid("cursor exceeds the supported length");
        }
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length != 2) {
                throw invalid("cursor is malformed");
            }
            byte[] bytes = Base64.getUrlDecoder().decode(parts[0]);
            byte[] signature = Base64.getUrlDecoder().decode(parts[1]);
            if (!java.security.MessageDigest.isEqual(signature, hmac(bytes))) {
                throw invalid("cursor signature is invalid");
            }
            JsonNode payload = CanonicalJson.parse(bytes);
            if (!payload.isObject() || payload.size() != 5
                    || payload.path("v").asInt(-1) != 1
                    || !order.equals(payload.path("order").asText())
                    || !payload.path("filters").equals(CanonicalJson.parse(
                            CanonicalJson.canonicalize(filterMap(filters))))) {
                throw invalid("cursor does not match these filters and order");
            }
            long asOfSeq = positiveOrZero(payload.path("asOfSeq").longValue(), "cursor head");
            long lastSeq = positiveOrZero(payload.path("lastSeq").longValue(), "cursor sequence");
            if (asOfSeq < lastSeq || lastSeq == 0) {
                throw invalid("cursor sequence is outside its snapshot");
            }
            return new CursorState(asOfSeq, lastSeq);
        } catch (IllegalArgumentException exception) {
            throw invalid("cursor is malformed");
        }
    }

    private byte[] hmac(byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(cursorSigningKey, "HmacSHA256"));
            return mac.doFinal(payload);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Cursor authentication failed", exception);
        }
    }

    private static Map<String, Object> cursorPayload(
            EventFilters filters, String order, long asOfSeq, long lastSeq) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("v", 1);
        payload.put("filters", filterMap(filters));
        payload.put("order", order);
        payload.put("asOfSeq", asOfSeq);
        payload.put("lastSeq", lastSeq);
        return payload;
    }

    private static Map<String, Object> filterMap(EventFilters filters) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("actorId", filters.actorId());
        map.put("resourceType", filters.resourceType());
        map.put("resourceId", filters.resourceId());
        map.put("eventType", filters.eventType());
        map.put("from", filters.from());
        map.put("to", filters.to());
        return map;
    }

    private static long positiveOrZero(long value, String field) {
        if (value < 0 || value > 9_007_199_254_740_991L) {
            throw invalid(field + " is outside the supported range");
        }
        return value;
    }

    private static ApiException invalid(String message) {
        return new ApiException(422, "INVALID_INPUT", message);
    }

    public record EventPage(List<EventView> items, String nextCursor) {
        public EventPage {
            items = List.copyOf(items);
        }
    }

    public record EventView(
            String eventType,
            String actorId,
            String resourceType,
            String resourceId,
            Map<String, Object> payload,
            String occurredAt,
            String eventId,
            long seq,
            String timestamp,
            String source,
            int hashVersion,
            Map<String, Object> payloadCommitments,
            List<String> redactedPaths,
            String contentHash,
            String prevHash,
            String chainHash) {
        public EventView {
            payload = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(payload));
            payloadCommitments = java.util.Collections.unmodifiableMap(
                    new LinkedHashMap<>(payloadCommitments));
            redactedPaths = List.copyOf(redactedPaths);
        }
    }

    public record CheckpointView(
            long seq, String chainHash, String createdAt, String keyId, String signature) {
    }

    private record EventFilters(
            String actorId,
            String resourceType,
            String resourceId,
            String eventType,
            String from,
            String to) {
    }

    private record CursorState(long asOfSeq, long lastSeq) {
    }

    private record StoredEvent(
            long seq,
            String eventId,
            String eventType,
            String actorId,
            String resourceType,
            String resourceId,
            String occurredAt,
            String recordedAt,
            String source,
            String payloadCommitments,
            int hashVersion,
            String contentHash,
            String prevHash,
            String chainHash) {
    }
}
