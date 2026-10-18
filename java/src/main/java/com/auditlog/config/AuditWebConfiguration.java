package com.auditlog.config;

import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.service.AppendEventService;
import com.auditlog.service.EventQueryService;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.web.ApiKeyAuthenticator;
import com.auditlog.web.ApiSecurityInterceptor;
import com.auditlog.web.StrictJsonRequestFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.sql.SQLException;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
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
    public Clock auditClock() {
        return Clock.systemUTC();
    }

}
