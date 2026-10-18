package com.auditlog.web;

import com.auditlog.web.ApiKeyAuthenticator.AuthenticatedPrincipal;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import org.springframework.web.servlet.HandlerInterceptor;

public final class ApiSecurityInterceptor implements HandlerInterceptor {

    public static final String PRINCIPAL_ATTRIBUTE =
            ApiSecurityInterceptor.class.getName() + ".principal";

    private static final Set<String> READ_ROLES = Set.of("reader", "auditor", "admin");
    private static final Set<String> AUDITOR_ROLES = Set.of("auditor", "admin");
    private static final Set<String> ADMIN_ROLES = Set.of("admin");
    private static final Set<String> WRITE_ROLES = Set.of("writer", "admin");

    private final ApiKeyAuthenticator authenticator;
    private final ObjectMapper objectMapper;

    public ApiSecurityInterceptor(ApiKeyAuthenticator authenticator, ObjectMapper objectMapper) {
        this.authenticator = authenticator;
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean preHandle(
            HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        if (isPublic(request)) {
            return true;
        }

        AuthenticatedPrincipal principal = authenticator.authenticate(request.getHeader("X-API-Key"));
        if (principal == null) {
            writeError(response, 401, "UNAUTHORIZED", "Valid X-API-Key credentials are required");
            return false;
        }

        Set<String> required = requiredRoles(request);
        if (required != null && principal.roles().stream().noneMatch(required::contains)) {
            writeError(response, 403, "FORBIDDEN", "The principal does not have permission for this operation");
            return false;
        }
        request.setAttribute(PRINCIPAL_ATTRIBUTE, principal);
        return true;
    }

    private static boolean isPublic(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.equals("/health")
                || path.equals("/audit/public-key")
                || path.equals("/openapi.json")
                || path.equals("/v3/api-docs")
                || path.startsWith("/v3/api-docs/")
                || path.equals("/docs")
                || path.startsWith("/swagger-ui/")
                || path.startsWith("/webjars/");
    }

    private static Set<String> requiredRoles(HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();
        if (path.equals("/audit/events") && method.equals("POST")) {
            return WRITE_ROLES;
        }
        if ((path.equals("/audit/events") || path.startsWith("/audit/events/"))
                && method.equals("GET")) {
            return READ_ROLES;
        }
        if ((path.equals("/audit/checkpoints") || path.equals("/audit/verify")
                || path.equals("/audit/export") || path.equals("/audit/archive-audit"))
                && method.equals("GET")) {
            return AUDITOR_ROLES;
        }
        if (path.startsWith("/audit/admin/")) {
            return ADMIN_ROLES;
        }
        if (path.equals("/audit/export-sets") || path.startsWith("/audit/export-sets/")) {
            return AUDITOR_ROLES;
        }
        return null;
    }

    private void writeError(
            HttpServletResponse response, int status, String code, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(), ApiErrorResponse.of(code, message));
    }
}
