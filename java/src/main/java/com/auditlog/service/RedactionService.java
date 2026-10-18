package com.auditlog.service;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.PayloadCommitments;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.web.ApiException;
import com.fasterxml.jackson.databind.JsonNode;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Atomic redaction. In one write transaction this appends a RECORD_REDACTED system event, deletes
 * the selected leaf values and salts, and enqueues a durable cleanup job. Commitment trees and all
 * hashes of the target stay unchanged, so the chain still verifies. Cleanup of the WAL happens
 * after commit and never undoes the committed deletion.
 */
public final class RedactionService {

    public static final String EVENT_TYPE = "RECORD_REDACTED";
    public static final String RESOURCE_TYPE = "AUDIT_EVENT";

    private static final Pattern POINTER = Pattern.compile("(/([^~/]|~[01])*)*");
    private static final Set<String> RESERVED_TYPES = Set.of(
            "RECORD_REDACTED", "RECORDS_ARCHIVED", "BUNDLE_EXPORTED", "COMPLIANCE_REPORT_GENERATED");
    private static final int MAX_REQUEST_PATHS = 500;
    private static final int MAX_REASON = 1000;
    private static final int MAX_TICKET = 128;
    private static final int MIN_GUARDED_VALUE = 4;
    // targetSeq, targetEventId, reason, ticketId, requestedBy are leaves of the authorization payload
    private static final int METADATA_LEAVES = 5;

    private final JdbcAuditRepository repository;
    private final AppendEventService appendService;
    private final RedactionCleanupService cleanupService;
    private final int maxRedactedLeaves;

    public RedactionService(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            AppendEventService appendService,
            RedactionCleanupService cleanupService) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.appendService = Objects.requireNonNull(appendService, "appendService");
        this.cleanupService = Objects.requireNonNull(cleanupService, "cleanupService");
        this.maxRedactedLeaves = Math.min(
                Objects.requireNonNull(configuration, "configuration").maxLeaves(),
                PayloadCommitments.MAX_SCALAR_LEAVES) - METADATA_LEAVES;
    }

    /** Outcome of a committed redaction; carries no payload values. */
    public record RedactionResult(
            String redactionEventId,
            long redactionSeq,
            String timestamp,
            String contentHash,
            String chainHash,
            long targetSeq,
            String targetEventId,
            List<String> redactedPaths,
            String cleanupStatus,
            int cleanupAttempts,
            String note) { }

    public RedactionResult redact(
            String eventId, List<String> paths, String reason, String ticketId, String requestedBy)
            throws SQLException {
        validateRequest(eventId, paths, reason, ticketId, requestedBy);

        Committed committed = repository.writeTransaction(connection ->
                redactLocked(connection, eventId, paths, reason, ticketId, requestedBy));

        RedactionCleanupService.Summary summary = cleanupService.runPending();
        String status = committed.cleanupJobId() > 0 && summary.pendingJobs() == 0
                ? RedactionCleanupService.COMPLETE
                : RedactionCleanupService.PENDING;
        AppendedEvent event = committed.event();
        return new RedactionResult(
                event.eventId(), event.seq(), event.timestamp(), event.contentHash(), event.chainHash(),
                committed.targetSeq(), eventId, committed.leaves(), status, summary.attempts(),
                RedactionCleanupService.LIMITATIONS);
    }

    private record Committed(AppendedEvent event, long targetSeq, List<String> leaves, long cleanupJobId) { }

    private Committed redactLocked(
            Connection connection, String eventId, List<String> paths, String reason,
            String ticketId, String requestedBy) throws SQLException {
        long targetSeq;
        Map<String, Object> commitments;
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT seq, event_type, source, archived, payload_commitments
                FROM audit_events WHERE event_id = ?
                """)) {
            statement.setString(1, eventId);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new ApiException(404, "NOT_FOUND", "Audit event was not found");
                }
                targetSeq = rows.getLong("seq");
                if (rows.getInt("archived") != 0) {
                    throw new ApiException(409, "CONFLICT", "Archived events cannot be redacted");
                }
                String type = rows.getString("event_type");
                if ("system".equals(rows.getString("source")) || RESERVED_TYPES.contains(type)) {
                    throw new ApiException(409, "CONFLICT", "System events cannot be redacted");
                }
                commitments = parseCommitments(rows.getString("payload_commitments"));
            }
        }

        TreeSet<String> expanded = new TreeSet<>();
        for (String path : paths) {
            // An unknown pointer raises IllegalArgumentException, reported as 422.
            expanded.addAll(PayloadCommitments.expandSubtreePointer(commitments, path));
        }
        Map<String, String> present = presentLeaves(connection, targetSeq);
        List<String> leaves = new ArrayList<>();
        for (String pointer : expanded) {
            if (present.containsKey(pointer)) {
                leaves.add(pointer);
            }
        }
        if (leaves.isEmpty()) {
            throw new ApiException(409, "CONFLICT", "Nothing to redact: the selected values are already redacted");
        }
        if (leaves.size() > maxRedactedLeaves) {
            throw new ApiException(422, "INVALID_INPUT",
                    "A single redaction may remove at most " + maxRedactedLeaves
                            + " values; redact smaller subtrees separately");
        }
        rejectEchoedValues(reason, ticketId, leaves, present);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("targetSeq", targetSeq);
        payload.put("targetEventId", eventId);
        payload.put("paths", List.copyOf(leaves));
        payload.put("reason", reason);
        payload.put("ticketId", ticketId);
        payload.put("requestedBy", requestedBy);
        AppendedEvent event = appendService.appendSystemEvent(
                connection, EVENT_TYPE, requestedBy, RESOURCE_TYPE, eventId, payload);

        try (PreparedStatement delete = connection.prepareStatement(
                "DELETE FROM payload_leaves WHERE seq = ? AND pointer = ?")) {
            for (String pointer : leaves) {
                delete.setLong(1, targetSeq);
                delete.setString(2, pointer);
                if (delete.executeUpdate() != 1) {
                    throw new SQLException("Redaction expected to delete exactly one leaf");
                }
            }
        }
        long jobId = cleanupService.enqueue(connection, event.seq(), targetSeq, leaves.size());
        return new Committed(event, targetSeq, List.copyOf(leaves), jobId);
    }

    private static void validateRequest(
            String eventId, List<String> paths, String reason, String ticketId, String requestedBy) {
        requireText(eventId, "eventId", 128);
        requireText(reason, "reason", MAX_REASON);
        requireText(ticketId, "ticketId", MAX_TICKET);
        requireText(requestedBy, "requestedBy", 256);
        if (paths == null || paths.isEmpty()) {
            throw new IllegalArgumentException("paths must contain at least one JSON Pointer");
        }
        if (paths.size() > MAX_REQUEST_PATHS) {
            throw new IllegalArgumentException("paths exceeds the maximum of " + MAX_REQUEST_PATHS);
        }
        for (String path : paths) {
            if (path == null || path.length() > 4096 || !POINTER.matcher(path).matches()) {
                throw new IllegalArgumentException("paths must contain valid RFC 6901 JSON Pointers");
            }
        }
    }

    private static void requireText(String value, String name, int max) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        if (value.length() > max) {
            throw new IllegalArgumentException(name + " exceeds " + max + " characters");
        }
    }

    /**
     * Best-effort guard: free text copied into the permanent authorization event must not repeat a
     * value being redacted. It cannot detect paraphrases, so callers remain responsible.
     */
    private static void rejectEchoedValues(
            String reason, String ticketId, List<String> leaves, Map<String, String> present) {
        for (String pointer : leaves) {
            String text = scalarText(present.get(pointer));
            if (text.length() >= MIN_GUARDED_VALUE
                    && (reason.contains(text) || ticketId.contains(text))) {
                throw new IllegalArgumentException(
                        "reason and ticketId must not repeat the values being redacted");
            }
        }
    }

    private static String scalarText(String json) {
        try {
            JsonNode node = CanonicalJson.parse(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return node.isTextual() ? node.textValue() : node.toString();
        } catch (IllegalArgumentException exception) {
            return "";
        }
    }

    private static Map<String, String> presentLeaves(Connection connection, long seq) throws SQLException {
        Map<String, String> result = new TreeMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pointer, value FROM payload_leaves WHERE seq = ?")) {
            statement.setLong(1, seq);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    result.put(rows.getString(1), rows.getString(2));
                }
            }
        }
        return result;
    }

    private static Map<String, Object> parseCommitments(String json) throws SQLException {
        if (json == null) {
            throw new SQLException("Stored payload commitments are malformed");
        }
        try {
            JsonNode node = CanonicalJson.parse(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (!node.isObject()) {
                throw new SQLException("Stored payload commitments are not a JSON object");
            }
            return objectValue(node);
        } catch (IllegalArgumentException exception) {
            throw new SQLException("Stored payload commitments are malformed", exception);
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
        throw new IllegalArgumentException("Commitment tree contains a non-string scalar");
    }
}
