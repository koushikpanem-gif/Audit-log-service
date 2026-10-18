package com.auditlog.web;

import java.util.List;

public record ApiErrorResponse(Error error) {
    public record Error(String code, String message, List<Object> details) {
        public Error {
            details = List.copyOf(details);
        }
    }

    public static ApiErrorResponse of(String code, String message) {
        return new ApiErrorResponse(new Error(code, message, List.of()));
    }
}
