package com.auditlog.domain;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnySetter;

public record AppendEventRequest(
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Map<String, ?> payload,
        String occurredAt) {

    public AppendEventRequest {
        if (payload == null) {
            throw new IllegalArgumentException("Payload must be a JSON object");
        }
        payload = Collections.unmodifiableMap(new LinkedHashMap<>(payload));
    }

    @JsonAnySetter
    public void rejectUnknownInputField(String field, Object ignored) {
        throw new IllegalArgumentException("Unknown event input field: " + field);
    }
}
