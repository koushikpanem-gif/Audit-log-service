package com.auditlog.domain;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Normalized v1 bundle selection: exactly eight keys, always present. All non-null filters are
 * ANDed and bounds are inclusive. Archived records are never selected regardless of the filters.
 */
public record BundleSelection(
        String actorId,
        String resourceType,
        String resourceId,
        String eventType,
        String from,
        String to,
        Long seqFrom,
        Long seqTo) {

    public static final long MAX_SAFE = 9_007_199_254_740_991L;
    public static final int MAX_TEXT_BYTES = 1024;
    public static final Set<String> KEYS = Set.of(
            "actorId", "resourceType", "resourceId", "eventType", "from", "to", "seqFrom", "seqTo");

    private static final DateTimeFormatter UTC_MICROS =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'").withZone(ZoneOffset.UTC);

    public BundleSelection {
        text("actorId", actorId);
        text("resourceType", resourceType);
        text("resourceId", resourceId);
        text("eventType", eventType);
        if (from != null && !isCanonicalTimestamp(from)) {
            throw new IllegalArgumentException("from must be a UTC microsecond timestamp");
        }
        if (to != null && !isCanonicalTimestamp(to)) {
            throw new IllegalArgumentException("to must be a UTC microsecond timestamp");
        }
        if (from != null && to != null && from.compareTo(to) > 0) {
            throw new IllegalArgumentException("from must not be after to");
        }
        safePositive("seqFrom", seqFrom);
        safePositive("seqTo", seqTo);
        if (seqFrom != null && seqTo != null && seqFrom > seqTo) {
            throw new IllegalArgumentException("seqFrom must not be greater than seqTo");
        }
    }

    /** Selection for the normal export endpoint: needs actorId or resourceId, seq bounds are null. */
    public static BundleSelection forExport(
            String actorId, String resourceType, String resourceId, String eventType,
            String from, String to) {
        if (actorId == null && resourceId == null) {
            throw new IllegalArgumentException("An export requires actorId or resourceId");
        }
        return new BundleSelection(actorId, resourceType, resourceId, eventType,
                normalizeTimestamp(from), normalizeTimestamp(to), null, null);
    }

    /** Selection used by internal archive exports: sequence bounds and no ordinary filters. */
    public static BundleSelection forSeqRange(long seqFrom, long seqTo) {
        return new BundleSelection(null, null, null, null, null, null, seqFrom, seqTo);
    }

    /** Parses a selection object strictly: exactly the eight keys, correct scalar types. */
    public static BundleSelection fromMap(Map<?, ?> map) {
        if (!map.keySet().equals(KEYS)) {
            throw new IllegalArgumentException("selection must have exactly the eight v1 keys");
        }
        return new BundleSelection(
                string(map.get("actorId")), string(map.get("resourceType")),
                string(map.get("resourceId")), string(map.get("eventType")),
                string(map.get("from")), string(map.get("to")),
                integer(map.get("seqFrom")), integer(map.get("seqTo")));
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("actorId", actorId);
        map.put("resourceType", resourceType);
        map.put("resourceId", resourceId);
        map.put("eventType", eventType);
        map.put("from", from);
        map.put("to", to);
        map.put("seqFrom", seqFrom);
        map.put("seqTo", seqTo);
        return map;
    }

    /** True if the record fields satisfy every non-null filter. */
    public boolean matches(
            long seq, String recordActorId, String recordResourceType, String recordResourceId,
            String recordEventType, String timestamp) {
        return (actorId == null || actorId.equals(recordActorId))
                && (resourceType == null || resourceType.equals(recordResourceType))
                && (resourceId == null || resourceId.equals(recordResourceId))
                && (eventType == null || eventType.equals(recordEventType))
                && (from == null || (timestamp != null && timestamp.compareTo(from) >= 0))
                && (to == null || (timestamp != null && timestamp.compareTo(to) <= 0))
                && (seqFrom == null || seq >= seqFrom)
                && (seqTo == null || seq <= seqTo);
    }

    public boolean hasOrdinaryFilters() {
        return actorId != null || resourceType != null || resourceId != null
                || eventType != null || from != null || to != null;
    }

    public static boolean isCanonicalTimestamp(String value) {
        try {
            return UTC_MICROS.format(Instant.parse(value)).equals(value);
        } catch (DateTimeParseException exception) {
            return false;
        }
    }

    /** Normalizes an ISO-8601 instant to the canonical microsecond form; null stays null. */
    public static String normalizeTimestamp(String value) {
        if (value == null) {
            return null;
        }
        try {
            Instant instant = Instant.parse(value);
            if (instant.getNano() % 1000 != 0) {
                throw new IllegalArgumentException("Timestamps are limited to microsecond precision");
            }
            return UTC_MICROS.format(instant);
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException("Timestamp must be an ISO-8601 UTC instant");
        }
    }

    private static void text(String name, String value) {
        if (value == null) {
            return;
        }
        if (value.isEmpty()
                || value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_TEXT_BYTES) {
            throw new IllegalArgumentException(
                    name + " must be null or a non-empty string of at most 1024 bytes");
        }
    }

    private static void safePositive(String name, Long value) {
        if (value != null && (value < 1 || value > MAX_SAFE)) {
            throw new IllegalArgumentException(name + " must be null or a safe positive integer");
        }
    }

    private static String string(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String text) {
            return text;
        }
        throw new IllegalArgumentException("selection text and timestamp fields must be strings or null");
    }

    private static Long integer(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Long || value instanceof Integer) {
            return ((Number) value).longValue();
        }
        throw new IllegalArgumentException("selection sequence bounds must be integers or null");
    }
}
