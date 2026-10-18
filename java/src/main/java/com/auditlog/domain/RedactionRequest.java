package com.auditlog.domain;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import java.util.List;

public record RedactionRequest(String eventId, List<String> paths, String reason, String ticketId) {

    @JsonAnySetter
    public void rejectUnknownInputField(String field, Object ignored) {
        throw new IllegalArgumentException("Unknown redaction input field");
    }
}
