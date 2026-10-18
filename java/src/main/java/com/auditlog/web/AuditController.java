package com.auditlog.web;

import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.service.AppendedEvent;
import com.auditlog.service.AppendEventService;
import com.auditlog.service.EventQueryService;
import com.auditlog.service.EventQueryService.CheckpointView;
import com.auditlog.service.EventQueryService.EventPage;
import com.auditlog.service.EventQueryService.EventView;
import com.auditlog.service.ExportBundleService;
import com.auditlog.verify.LedgerVerifier;
import com.auditlog.verify.VerificationReport;
import com.auditlog.web.ApiKeyAuthenticator.AuthenticatedPrincipal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "Audit events", description = "Append and query tamper-evident audit events")
public class AuditController {

    private final AppendEventService appendService;
    private final EventQueryService queryService;
    private final CheckpointSigner signer;
    private final LedgerVerifier verifier;
    private final ExportBundleService exportService;

    public AuditController(
            AppendEventService appendService,
            EventQueryService queryService,
            CheckpointSigner signer,
            LedgerVerifier verifier,
            ExportBundleService exportService) {
        this.appendService = appendService;
        this.queryService = queryService;
        this.signer = signer;
        this.verifier = verifier;
        this.exportService = exportService;
    }

    @GetMapping("/audit/export")
    @Operation(summary = "Export a signed v1 bundle for one actor or resource")
    @SecurityRequirement(name = "apiKeyAuth")
    public Map<String, Object> export(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceId,
            HttpServletRequest httpRequest) throws SQLException {
        return exportService.export(actorId, resourceId, principal(httpRequest).name());
    }

    @GetMapping("/audit/verify")
    @Operation(summary = "Verify the full ledger in one snapshot")
    @SecurityRequirement(name = "apiKeyAuth")
    public VerificationReport verify() throws SQLException {
        return verifier.verify();
    }

    @PostMapping("/audit/events")
    @Operation(summary = "Append an audit event")
    @SecurityRequirement(name = "apiKeyAuth")
    public ResponseEntity<AppendedEvent> append(
            @RequestBody AppendEventRequest request,
            HttpServletRequest httpRequest) throws SQLException {
        AuthenticatedPrincipal principal = principal(httpRequest);
        AppendedEvent appended = appendService.append(request, principal.name());
        return ResponseEntity.created(URI.create("/audit/events/" + appended.eventId()))
                .body(appended);
    }

    @GetMapping("/audit/events")
    @Operation(summary = "Query audit events")
    @SecurityRequirement(name = "apiKeyAuth")
    public EventPage list(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false) String order,
            @RequestParam(required = false) String cursor) throws SQLException {
        return queryService.list(
                actorId, resourceType, resourceId, eventType,
                from, to, limit, order, cursor);
    }

    @GetMapping("/audit/events/{eventId}")
    @Operation(summary = "Get one retained audit event")
    @SecurityRequirement(name = "apiKeyAuth")
    public EventView get(@PathVariable String eventId) throws SQLException {
        return queryService.getById(eventId);
    }

    @GetMapping("/audit/checkpoints")
    @Operation(summary = "List signed checkpoints")
    @SecurityRequirement(name = "apiKeyAuth")
    public List<CheckpointView> checkpoints(
            @RequestParam(required = false) Integer limit) throws SQLException {
        return queryService.listCheckpoints(limit);
    }

    @GetMapping("/audit/public-key")
    @Operation(summary = "Get the public checkpoint verification key")
    public Map<String, String> publicKey() {
        return Map.of(
                "signatureAlgorithm", "Ed25519",
                "keyId", signer.keyId(),
                "publicKey", signer.publicKeyBase64());
    }

    private static AuthenticatedPrincipal principal(HttpServletRequest request) {
        Object principal = request.getAttribute(ApiSecurityInterceptor.PRINCIPAL_ATTRIBUTE);
        if (principal instanceof AuthenticatedPrincipal authenticatedPrincipal) {
            return authenticatedPrincipal;
        }
        throw new ApiException(
                HttpStatus.UNAUTHORIZED.value(), "UNAUTHORIZED",
                "Valid X-API-Key credentials are required");
    }
}
