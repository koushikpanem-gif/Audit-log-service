package com.auditlog.config;

import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.service.AppendEventService;
import com.auditlog.service.ArchiveAuditService;
import com.auditlog.service.ArchiveService;
import com.auditlog.service.EventQueryService;
import com.auditlog.service.ExportBundleService;
import com.auditlog.service.ExportSetService;
import com.auditlog.service.RedactionCleanupService;
import com.auditlog.service.RedactionService;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.verify.LedgerVerifier;
import com.auditlog.web.ApiKeyAuthenticator;
import com.auditlog.web.ApiSecurityInterceptor;
import com.auditlog.web.StrictJsonRequestFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.sql.SQLException;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

@Configuration
public class AuditWebConfiguration {

    @Bean
    public AuditConfiguration auditConfiguration(Environment environment) {
        Map<String, String> values = new HashMap<>(System.getenv());
        for (String name : new String[] {
            "AUDIT_ENV",
            "AUDIT_LEDGER_ID",
            "AUDIT_DB_PATH",
            "AUDIT_RETENTION_DAYS",
            "AUDIT_CHECKPOINT_INTERVAL",
            "AUDIT_REQUEST_LIMIT_BYTES",
            "AUDIT_PAYLOAD_LIMIT_BYTES",
            "AUDIT_MAX_DEPTH",
            "AUDIT_MAX_LEAVES",
            "AUDIT_EXPORT_MAX_RECORDS",
            "AUDIT_EXPORT_MAX_BYTES",
            "AUDIT_EXPORT_DIR",
            "AUDIT_EXPORT_CHUNK_MAX_RECORDS",
            "AUDIT_EXPORT_CHUNK_MAX_BYTES",
            "AUDIT_EXPORT_SET_MAX_RECORDS",
            "AUDIT_EXPORT_SET_TTL_SECONDS",
            "AUDIT_CLEANUP_MAX_ATTEMPTS",
            "AUDIT_CLEANUP_BUSY_TIMEOUT_MS",
            "AUDIT_ARCHIVE_DIR",
            "AUDIT_ARCHIVE_MAX_RECORDS",
            "AUDIT_ARCHIVE_MAX_BYTES",
            "AUDIT_SIGNING_PRIVATE_KEY",
            "AUDIT_SIGNING_PUBLIC_KEY",
            "AUDIT_API_KEYS_FILE"
        }) {
            String value = environment.getProperty(name);
            if (value != null) {
                values.put(name, value);
            }
        }
        return AuditConfiguration.fromEnvironment(values);
    }

    @Bean
    public CheckpointSigner checkpointSigner(AuditConfiguration configuration) throws IOException {
        return configuration.loadSigner();
    }

    @Bean
    public JdbcAuditRepository auditRepository(AuditConfiguration configuration) throws SQLException {
        return new JdbcAuditRepository(configuration.databasePath(), configuration.ledgerId());
    }

    @Bean
    public ApiKeyAuthenticator apiKeyAuthenticator(AuditConfiguration configuration) throws IOException {
        return new ApiKeyAuthenticator(configuration);
    }

    @Bean
    public ApiSecurityInterceptor apiSecurityInterceptor(
            ApiKeyAuthenticator authenticator, ObjectMapper objectMapper) {
        return new ApiSecurityInterceptor(authenticator, objectMapper);
    }

    @Bean
    public FilterRegistrationBean<StrictJsonRequestFilter> strictJsonRequestFilter(
            AuditConfiguration configuration, ObjectMapper objectMapper) {
        FilterRegistrationBean<StrictJsonRequestFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new StrictJsonRequestFilter(configuration, objectMapper));
        registration.setOrder(-100);
        return registration;
    }

    @Bean
    public AppendEventService appendEventService(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            Clock auditClock) {
        return new AppendEventService(repository, configuration, signer, auditClock);
    }

    @Bean
    public EventQueryService eventQueryService(
            JdbcAuditRepository repository, ApiKeyAuthenticator authenticator) {
        return new EventQueryService(
                repository, authenticator.cursorSigningKey());
    }

    @Bean
    public ExportBundleService exportBundleService(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService) {
        return new ExportBundleService(repository, configuration, signer, appendService);
    }

    @Bean
    public ExportSetService exportSetService(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService,
            Clock auditClock) {
        Executor executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "export-set-worker");
            thread.setDaemon(true);
            return thread;
        });
        return new ExportSetService(repository, configuration, signer, appendService, auditClock, executor);
    }

    @Bean
    public RedactionCleanupService redactionCleanupService(
            JdbcAuditRepository repository, AuditConfiguration configuration, Clock auditClock) {
        RedactionCleanupService service = new RedactionCleanupService(repository, configuration, auditClock);
        service.recover();
        return service;
    }

    @Bean
    public RedactionService redactionService(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            AppendEventService appendService,
            RedactionCleanupService cleanupService) {
        return new RedactionService(repository, configuration, appendService, cleanupService);
    }

    @Bean
    public ArchiveService archiveService(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService,
            Clock auditClock) throws SQLException {
        ArchiveService service = new ArchiveService(repository, configuration, signer, appendService, auditClock);
        service.reconcile();
        return service;
    }

    @Bean
    public ArchiveAuditService archiveAuditService(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            Clock auditClock) {
        return new ArchiveAuditService(repository, configuration, signer, auditClock);
    }

    @Bean
    public com.auditlog.service.AccountAccessReportService accountAccessReportService(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService,
            ExportBundleService exportBundleService,
            LedgerVerifier ledgerVerifier) {
        return new com.auditlog.service.AccountAccessReportService(
                repository, configuration, signer, appendService, exportBundleService, ledgerVerifier);
    }

    @Bean
    public LedgerVerifier ledgerVerifier(
            JdbcAuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            Clock auditClock) {
        return new LedgerVerifier(
                repository, configuration.ledgerId(), signer.publicKeyBase64(), auditClock);
    }

    @Bean
    public Clock auditClock() {
        return Clock.systemUTC();
    }

}
