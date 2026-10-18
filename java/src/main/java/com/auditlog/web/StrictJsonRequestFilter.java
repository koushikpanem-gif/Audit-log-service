package com.auditlog.web;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.web.filter.OncePerRequestFilter;

public final class StrictJsonRequestFilter extends OncePerRequestFilter {

    private final AuditConfiguration configuration;
    private final ObjectMapper objectMapper;

    public StrictJsonRequestFilter(AuditConfiguration configuration, ObjectMapper objectMapper) {
        this.configuration = configuration;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!hasJsonBody(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        int limit = Math.min(configuration.requestLimitBytes(), CanonicalJson.MAX_INPUT_BYTES);
        if (request.getContentLengthLong() > limit) {
            writeError(response, 413, "REQUEST_TOO_LARGE", "Request body exceeds the configured byte limit");
            return;
        }
        byte[] body = request.getInputStream().readNBytes(limit + 1);
        if (body.length > limit) {
            writeError(response, 413, "REQUEST_TOO_LARGE", "Request body exceeds the configured byte limit");
            return;
        }
        try {
            CanonicalJson.parse(body, configuration.maxDepth() + 2);
        } catch (IllegalArgumentException exception) {
            writeError(response, 422, "INVALID_JSON", "Request body is not valid strict JSON");
            return;
        }
        filterChain.doFilter(new CachedBodyRequest(request, body), response);
    }

    private static boolean hasJsonBody(HttpServletRequest request) {
        String contentType = request.getContentType();
        return request.getContentLengthLong() != 0
                && contentType != null
                && contentType.toLowerCase(java.util.Locale.ROOT).startsWith("application/json");
    }

    private void writeError(
            HttpServletResponse response, int status, String code, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getOutputStream(), ApiErrorResponse.of(code, message));
    }

    private static final class CachedBodyRequest extends HttpServletRequestWrapper {

        private final byte[] body;

        private CachedBodyRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public jakarta.servlet.ServletInputStream getInputStream() {
            ByteArrayInputStream input = new ByteArrayInputStream(body);
            return new jakarta.servlet.ServletInputStream() {
                @Override
                public int read() {
                    return input.read();
                }

                @Override
                public boolean isFinished() {
                    return input.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(jakarta.servlet.ReadListener readListener) {
                    throw new UnsupportedOperationException("Async request bodies are not supported");
                }
            };
        }
    }
}
