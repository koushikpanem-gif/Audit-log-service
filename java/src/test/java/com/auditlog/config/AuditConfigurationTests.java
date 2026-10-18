package com.auditlog.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.auditlog.core.crypto.CheckpointSigner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuditConfigurationTests {

    @Test
    void loadsDefaultsAndValidProductionConfiguration(@TempDir Path tempDir) throws Exception {
        AuditConfiguration defaults = AuditConfiguration.fromEnvironment(Map.of());
        assertDoesNotThrow(defaults::validateApiKeys);
        assertEquals(Path.of("audit-data/audit.db"), defaults.databasePath());
        assertEquals(500_000,
                AuditConfiguration.fromEnvironment(Map.of("AUDIT_RETENTION_DAYS", "500000"))
                        .retentionDays());

        Path apiKeys = tempDir.resolve("api-keys.json");
        Files.writeString(apiKeys, """
                {"sample-writer":{"keyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","roles":["writer"]}}
                """);
        AuditConfiguration production = AuditConfiguration.fromEnvironment(Map.of(
                "AUDIT_ENV", "prod",
                "AUDIT_API_KEYS_FILE", apiKeys.toString(),
                "AUDIT_RETENTION_DAYS", "1"));
        assertDoesNotThrow(production::validateApiKeys);

        Path privateKey = tempDir.resolve("signing-private.pem");
        Path publicKey = tempDir.resolve("signing-public.b64");
        String expectedKeyId = CheckpointSigner.fromFiles(privateKey, publicKey, "dev").keyId();
        AuditConfiguration fullyConfiguredProduction = AuditConfiguration.fromEnvironment(Map.of(
                "AUDIT_ENV", "prod",
                "AUDIT_API_KEYS_FILE", apiKeys.toString(),
                "AUDIT_RETENTION_DAYS", "1",
                "AUDIT_SIGNING_PRIVATE_KEY", privateKey.toString(),
                "AUDIT_SIGNING_PUBLIC_KEY", publicKey.toString()));
        assertEquals(expectedKeyId, fullyConfiguredProduction.loadSigner().keyId());
    }

    @Test
    void cleanupSettingsHaveDefaultsAndAreBounded() {
        AuditConfiguration defaults = AuditConfiguration.fromEnvironment(Map.of());
        assertEquals(3, defaults.cleanupMaxAttempts());
        assertEquals(1000, defaults.cleanupBusyTimeoutMillis());
        AuditConfiguration custom = AuditConfiguration.fromEnvironment(Map.of(
                "AUDIT_CLEANUP_MAX_ATTEMPTS", "10", "AUDIT_CLEANUP_BUSY_TIMEOUT_MS", "30000"));
        assertEquals(10, custom.cleanupMaxAttempts());
        assertEquals(30000, custom.cleanupBusyTimeoutMillis());
        for (String value : new String[] {"0", "-1", "11", "x", ""}) {
            assertThrows(IllegalArgumentException.class,
                    () -> AuditConfiguration.fromEnvironment(Map.of("AUDIT_CLEANUP_MAX_ATTEMPTS", value)));
        }
        for (String value : new String[] {"0", "-5", "30001", "x"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> AuditConfiguration.fromEnvironment(Map.of("AUDIT_CLEANUP_BUSY_TIMEOUT_MS", value)));
        }
    }

    @Test
    void rejectsInvalidEnvironmentRetentionAndPositiveBounds(@TempDir Path tempDir) {
        assertThrows(IllegalArgumentException.class,
                () -> AuditConfiguration.fromEnvironment(Map.of("AUDIT_ENV", "stage")));
        for (String retention : new String[] {
            "0", "-1", "NaN", "Infinity", "1e309", "1e-400", "1000000000000000",
            "500001", "nope"
        }) {
            assertThrows(IllegalArgumentException.class,
                    () -> AuditConfiguration.fromEnvironment(Map.of("AUDIT_RETENTION_DAYS", retention)));
        }
        for (Map.Entry<String, String> entry : Map.of(
                "AUDIT_CHECKPOINT_INTERVAL", "0",
                "AUDIT_CHECKPOINT_INTERVAL_TOO_LARGE", "1000001",
                "AUDIT_REQUEST_LIMIT_BYTES", "-1",
                "AUDIT_PAYLOAD_LIMIT_BYTES", "262145",
                "AUDIT_MAX_DEPTH", "11",
                "AUDIT_MAX_LEAVES", "501").entrySet()) {
            String variable = entry.getKey().equals("AUDIT_CHECKPOINT_INTERVAL_TOO_LARGE")
                    ? "AUDIT_CHECKPOINT_INTERVAL" : entry.getKey();
            assertThrows(IllegalArgumentException.class,
                    () -> AuditConfiguration.fromEnvironment(Map.of(variable, entry.getValue())));
        }
        assertThrows(IllegalArgumentException.class,
                () -> AuditConfiguration.fromEnvironment(Map.of("AUDIT_ENV", "prod")));
        assertThrows(IllegalArgumentException.class,
                () -> AuditConfiguration.fromEnvironment(Map.of("AUDIT_DB_PATH", " ")));
        assertThrows(IllegalArgumentException.class,
                () -> AuditConfiguration.fromEnvironment(Map.of("AUDIT_API_KEYS_FILE", "")));
        assertThrows(IllegalArgumentException.class,
                () -> AuditConfiguration.fromEnvironment(Map.of(
                        "AUDIT_ENV", "prod",
                        "AUDIT_API_KEYS_FILE", tempDir.resolve("keys").toString(),
                        "AUDIT_RETENTION_DAYS", "0.5")));
    }

    @Test
    void rejectsInvalidApiKeyFiles(@TempDir Path tempDir) throws Exception {
        Path apiKeys = tempDir.resolve("api-keys.json");
        AuditConfiguration config = AuditConfiguration.fromEnvironment(
                Map.of("AUDIT_API_KEYS_FILE", apiKeys.toString()));
        for (String content : new String[] {
            "{}",
            "{\"reader\":{\"keyHash\":\"xyz\",\"roles\":[\"reader\"]}}",
            "{\"reader\":{\"keyHash\":\"" + "a".repeat(64) + "\",\"roles\":[]}}",
            "{\"reader\":{\"keyHash\":\"" + "a".repeat(64) + "\",\"roles\":[\"root\"]}}",
            "{\"reader\":{\"keyHash\":\"" + "a".repeat(64)
                    + "\",\"roles\":[\"reader\"],\"apiKey\":\"secret\"}}"
        }) {
            Files.writeString(apiKeys, content);
            assertThrows(IllegalArgumentException.class, config::validateApiKeys);
        }
    }
}
