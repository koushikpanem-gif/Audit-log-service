package com.auditlog.web;

import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.domain.BundleSelection;
import com.auditlog.domain.ArchiveRequest;
import com.auditlog.domain.RedactionRequest;
import com.auditlog.service.ArchiveAuditService;
import com.auditlog.service.ArchiveService;
import com.auditlog.service.RedactionCleanupService;
import com.auditlog.service.RedactionService;
import com.auditlog.service.AppendedEvent;
import com.auditlog.service.AppendEventService;
import com.auditlog.service.EventQueryService;
import com.auditlog.service.EventQueryService.CheckpointView;
import com.auditlog.service.EventQueryService.EventPage;
import com.auditlog.service.EventQueryService.EventView;
import com.auditlog.service.ExportBundleService;
import com.auditlog.service.ExportSetService;
import com.auditlog.verify.LedgerVerifier;
import com.auditlog.verify.VerificationReport;
import com.auditlog.web.ApiKeyAuthenticator.AuthenticatedPrincipal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
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
    private final ExportSetService exportSetService;
    private final RedactionService redactionService;
    private final RedactionCleanupService cleanupService;
    private final ArchiveService archiveService;
    private final ArchiveAuditService archiveAuditService;
    private final com.auditlog.service.AccountAccessReportService reportService;
    public AuditController(
            AppendEventService appendService,
            EventQueryService queryService,
            CheckpointSigner signer,
            LedgerVerifier verifier,
            ExportBundleService exportService,
            ExportSetService exportSetService,
            RedactionService redactionService,
            RedactionCleanupService cleanupService,
            ArchiveService archiveService,
            ArchiveAuditService archiveAuditService,
            com.auditlog.service.AccountAccessReportService reportService) {
        this.reportService = reportService;
        this.archiveService = archiveService;
        this.archiveAuditService = archiveAuditService;
        this.redactionService = redactionService;
        this.cleanupService = cleanupService;
        this.appendService = appendService;
        this.queryService = queryService;
        this.signer = signer;
        this.verifier = verifier;
        this.exportService = exportService;
        this.exportSetService = exportSetService;
    }

    @GetMapping(value = "/audit/export", produces = "application/json")
    @Operation(summary = "Export a signed small v1 bundle (needs actorId or resourceId)")
    @SecurityRequirement(name = "apiKeyAuth")
    public ResponseEntity<byte[]> export(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            HttpServletRequest httpRequest) throws SQLException {
        BundleSelection selection = BundleSelection.forExport(
                actorId, resourceType, resourceId, eventType, from, to);
        byte[] canonical = exportService.export(selection, principal(httpRequest).name());
        return ResponseEntity.ok()
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(canonical);
    }

    @PostMapping(value = "/audit/export-sets", produces = "application/json")
    @Operation(summary = "Start a bounded, complete, chunked export set; returns an export-set descriptor")
    @SecurityRequirement(name = "apiKeyAuth")
    public ResponseEntity<Map<String, Object>> createExportSet(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            HttpServletRequest httpRequest) {
        BundleSelection selection = new BundleSelection(
                actorId, resourceType, resourceId, eventType,
                BundleSelection.normalizeTimestamp(from), BundleSelection.normalizeTimestamp(to), null, null);
        Map<String, Object> descriptor = exportSetService.create(selection, principal(httpRequest).name());
        return ResponseEntity.accepted()
                .location(URI.create("/audit/export-sets/" + descriptor.get("exportSetId")))
                .body(descriptor);
    }

    @GetMapping(value = "/audit/export-sets/{id}", produces = "application/json")
    @Operation(summary = "Export-set descriptor and job status")
    @SecurityRequirement(name = "apiKeyAuth")
    public Map<String, Object> exportSet(@PathVariable String id) {
        return exportSetService.describe(id);
    }

    @GetMapping(value = "/audit/export-sets/{id}/manifest", produces = "application/json")
    @Operation(summary = "Download the signed export-set manifest")
    @SecurityRequirement(name = "apiKeyAuth")
    public ResponseEntity<Resource> exportSetManifest(@PathVariable String id) throws IOException {
        return file(exportSetService.manifestFile(id));
    }

    @GetMapping(value = "/audit/export-sets/{id}/chunks/{name}", produces = "application/json")
    @Operation(summary = "Download one export-set chunk named in the manifest")
    @SecurityRequirement(name = "apiKeyAuth")
    public ResponseEntity<Resource> exportSetChunk(@PathVariable String id, @PathVariable String name)
            throws IOException {
        return file(exportSetService.chunkFile(id, name));
    }

    private static ResponseEntity<Resource> file(Path path) throws IOException {
        return ResponseEntity.ok()
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .contentLength(Files.size(path))
                .body(new FileSystemResource(path));
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

    @PostMapping("/audit/admin/redactions")
    @Operation(summary = "Redact leaf values atomically (admin); cleanup may be PENDING")
    @SecurityRequirement(name = "apiKeyAuth")
    public ResponseEntity<RedactionService.RedactionResult> redact(
            @RequestBody RedactionRequest request,
            HttpServletRequest httpRequest) throws SQLException {
        RedactionService.RedactionResult result = redactionService.redact(
                request.eventId(), request.paths(), request.reason(), request.ticketId(),
                principal(httpRequest).name());
        return ResponseEntity.created(URI.create("/audit/events/" + result.redactionEventId()))
                .body(result);
    }

    @PostMapping("/audit/admin/archive")
    @Operation(summary = "Archive the expired oldest live prefix (admin); dryRun changes nothing")
    @SecurityRequirement(name = "apiKeyAuth")
    public ArchiveService.ArchiveResult archive(
            @RequestBody ArchiveRequest request,
            HttpServletRequest httpRequest) throws SQLException {
        if (request == null || request.dryRun() == null) {
            throw new IllegalArgumentException("dryRun must be specified as true or false");
        }
        return archiveService.archive(request.dryRun(), principal(httpRequest).name());
    }

    @GetMapping("/audit/admin/archive-jobs")
    @Operation(summary = "Archive job status and orphan files (admin)")
    @SecurityRequirement(name = "apiKeyAuth")
    public Map<String, Object> archiveJobs() throws SQLException {
        return archiveService.status();
    }

    @PostMapping("/audit/admin/archive-jobs/reconcile")
    @Operation(summary = "Resolve interrupted archive jobs and clean proven-failed files (admin)")
    @SecurityRequirement(name = "apiKeyAuth")
    public Map<String, Object> reconcileArchives() throws SQLException {
        return archiveService.reconcile();
    }

    @GetMapping("/compliance/account-access-report")
    @Operation(summary = "Account-access report for one account or actor and an explicit period (auditor). "
            + "Appends a COMPLIANCE_REPORT_GENERATED event and checkpoint; capped at 10000 events.")
    @SecurityRequirement(name = "apiKeyAuth")
    public Map<String, Object> accountAccessReport(
            @RequestParam(required = false) String accountId,
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            HttpServletRequest httpRequest) throws SQLException {
        return reportService.generate(accountId, actorId, from, to, principal(httpRequest).name());
    }

    @GetMapping("/audit/archive-audit")
    @Operation(summary = "Audit archive files against signed bundles and the ledger skeleton (auditor)")
    @SecurityRequirement(name = "apiKeyAuth")
    public Map<String, Object> archiveAudit() throws SQLException {
        return archiveAuditService.audit();
    }

    @GetMapping("/audit/admin/redaction-cleanups")
    @Operation(summary = "Redaction cleanup job status (admin)")
    @SecurityRequirement(name = "apiKeyAuth")
    public Map<String, Object> cleanupStatus() throws SQLException {
        return cleanupService.status(100);
    }

    @PostMapping("/audit/admin/redaction-cleanups/retry")
    @Operation(summary = "Retry pending redaction cleanup (admin)")
    @SecurityRequirement(name = "apiKeyAuth")
    public Map<String, Object> retryCleanup() throws SQLException {
        cleanupService.runPending();
        return cleanupService.status(100);
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
