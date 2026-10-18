package com.auditlog.web;

import java.util.List;

public final class ApiException extends RuntimeException {

    private final int status;
    private final String code;
    private final List<Object> details;

    public ApiException(int status, String code, String message) {
        this(status, code, message, List.of());
    }

    public ApiException(int status, String code, String message, List<Object> details) {
        super(message);
        this.status = status;
        this.code = code;
        this.details = List.copyOf(details);
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    public List<Object> details() {
        return details;
    }
}
