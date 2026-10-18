package com.auditlog.domain;

import com.fasterxml.jackson.annotation.JsonAnySetter;

/** Body of POST /audit/admin/archive. dryRun is mandatory so a destructive run is never implicit. */
public record ArchiveRequest(Boolean dryRun) {

    @JsonAnySetter
    public void rejectUnknownInputField(String field, Object ignored) {
        throw new IllegalArgumentException("Unknown archive input field");
    }
}
