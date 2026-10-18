package com.auditlog.web;

import com.auditlog.service.ArchiveService;
import com.auditlog.service.ExportBundleService;
import com.auditlog.service.ExportSetService;
import com.auditlog.store.StorageBusyException;
import java.sql.SQLException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiErrorResponse> api(ApiException exception) {
        return error(exception.status(), exception.code(), exception.getMessage());
    }

    @ExceptionHandler(ExportBundleService.ExportLimitExceededException.class)
    public ResponseEntity<ApiErrorResponse> exportLimit(
            ExportBundleService.ExportLimitExceededException exception) {
        return ResponseEntity.status(422).body(new ApiErrorResponse(new ApiErrorResponse.Error(
                "EXPORT_LIMIT_EXCEEDED", exception.getMessage(),
                java.util.List.of(
                        java.util.Map.of("limit", "AUDIT_EXPORT_MAX_RECORDS", "value", exception.maxRecords()),
                        java.util.Map.of("limit", "AUDIT_EXPORT_MAX_BYTES", "value", exception.maxBytes())))));
    }

    @ExceptionHandler(ExportSetService.ExportSetException.class)
    public ResponseEntity<ApiErrorResponse> exportSet(ExportSetService.ExportSetException exception) {
        int status = switch (exception.kind()) {
            case INVALID -> 422;
            case NOT_FOUND -> 404;
            case NOT_READY -> 409;
            case GONE -> 410;
            case BUSY -> 429;
            case FAILED -> 500;
        };
        return error(status, exception.code(), exception.getMessage());
    }

    @ExceptionHandler(ArchiveService.ArchiveException.class)
    public ResponseEntity<ApiErrorResponse> archive(ArchiveService.ArchiveException exception) {
        int status = switch (exception.kind()) {
            case CONFLICT -> 409;
            case INVALID -> 422;
            case FAILED -> 500;
        };
        return error(status, exception.code(), exception.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiErrorResponse> invalidInput(IllegalArgumentException exception) {
        return error(422, "INVALID_INPUT", exception.getMessage());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiErrorResponse> unreadableBody() {
        return error(422, "INVALID_REQUEST", "Request body does not match the required schema");
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiErrorResponse> missingParameter() {
        return error(422, "INVALID_INPUT", "A required query parameter is missing");
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiErrorResponse> invalidParameterType() {
        return error(422, "INVALID_INPUT", "A query parameter has an invalid value");
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ApiErrorResponse> unsupportedMediaType() {
        return error(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiErrorResponse> methodNotAllowed() {
        return error(405, "METHOD_NOT_ALLOWED", "HTTP method is not supported for this resource");
    }

    @ExceptionHandler(StorageBusyException.class)
    public ResponseEntity<ApiErrorResponse> storageBusy(StorageBusyException exception) {
        return error(503, "STORAGE_BUSY", "Audit storage is temporarily unavailable");
    }

    @ExceptionHandler(SQLException.class)
    public ResponseEntity<ApiErrorResponse> storageFailure(SQLException exception) {
        if ((exception.getErrorCode() & 0xff) == 19) {
            return error(409, "CONFLICT", "The requested change conflicts with existing audit data");
        }
        return error(500, "INTERNAL_ERROR", "The audit operation could not be completed");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> unexpected() {
        return error(500, "INTERNAL_ERROR", "The request could not be completed");
    }

    private static ResponseEntity<ApiErrorResponse> error(
            int status, String code, String message) {
        return ResponseEntity.status(status).body(ApiErrorResponse.of(code, message));
    }
}
