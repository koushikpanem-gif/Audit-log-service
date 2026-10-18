package com.auditlog.service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record AppendedEvent(
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

    public AppendedEvent {
        payload = Collections.unmodifiableMap(new LinkedHashMap<>(payload));
        payloadCommitments = Map.copyOf(payloadCommitments);
        redactedPaths = List.copyOf(redactedPaths);
    }
}
