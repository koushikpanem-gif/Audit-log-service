package com.auditlog.config;

import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.core.crypto.CanonicalJson;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public record AuditConfiguration(
        String environment,
        String ledgerId,
        double retentionDays,
        int checkpointInterval,
        int requestLimitBytes,
        int payloadLimitBytes,
        int maxDepth,
        int maxLeaves,
        Path signingPrivateKey,
        Path signingPublicKey,
        Path apiKeysFile) {

    private static final BigDecimal MAX_RETENTION_DAYS = BigDecimal.valueOf(500_000);
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
    private static final Set<String> ALLOWED_ROLES = Set.of("writer", "reader", "auditor", "admin");
    private static final int MAX_API_KEY_FILE_BYTES = 64 * 1024;

    public static AuditConfiguration fromEnvironment(Map<String, String> values) {
        String environment = get(values, "AUDIT_ENV", "dev");
        if (!environment.equals("dev") && !environment.equals("prod")) {
            throw new IllegalArgumentException("AUDIT_ENV must be 'dev' or 'prod'");
        }

        String ledgerId = get(values, "AUDIT_LEDGER_ID", "development-ledger");
        if (!java.nio.charset.StandardCharsets.UTF_8.newEncoder().canEncode(ledgerId)) {
            throw new IllegalArgumentException("AUDIT_LEDGER_ID must contain valid Unicode");
        }
        byte[] ledgerIdBytes = ledgerId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (ledgerId.isBlank() || ledgerIdBytes.length > 256) {
            throw new IllegalArgumentException("AUDIT_LEDGER_ID must be 1 to 256 UTF-8 bytes");
        }

        BigDecimal retention;
        try {
            retention = new BigDecimal(get(values, "AUDIT_RETENTION_DAYS", "2555"));
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("AUDIT_RETENTION_DAYS must be a finite number", exception);
        }
        double retentionDays = retention.doubleValue();
        if (retention.signum() <= 0
                || retention.compareTo(MAX_RETENTION_DAYS) > 0
                || !Double.isFinite(retentionDays)
                || retentionDays <= 0
                || (environment.equals("prod") && retention.compareTo(BigDecimal.ONE) < 0)) {
            throw new IllegalArgumentException("AUDIT_RETENTION_DAYS is outside safe bounds");
        }

        int checkpointInterval = positiveInt(values, "AUDIT_CHECKPOINT_INTERVAL", 100);
        int requestLimitBytes = positiveInt(values, "AUDIT_REQUEST_LIMIT_BYTES", 256 * 1024);
        int payloadLimitBytes = positiveInt(values, "AUDIT_PAYLOAD_LIMIT_BYTES", 64 * 1024);
        int maxDepth = positiveInt(values, "AUDIT_MAX_DEPTH", 10);
        int maxLeaves = positiveInt(values, "AUDIT_MAX_LEAVES", 500);
        bounded("AUDIT_CHECKPOINT_INTERVAL", checkpointInterval, 1_000_000);
        bounded("AUDIT_REQUEST_LIMIT_BYTES", requestLimitBytes, 1024 * 1024);
        bounded("AUDIT_PAYLOAD_LIMIT_BYTES", payloadLimitBytes, requestLimitBytes);
        bounded("AUDIT_MAX_DEPTH", maxDepth, 10);
        bounded("AUDIT_MAX_LEAVES", maxLeaves, 500);

        String apiKeysValue = values.get("AUDIT_API_KEYS_FILE");
        Path apiKeys = apiKeysValue == null || apiKeysValue.isEmpty() ? null : Path.of(apiKeysValue);
        if (environment.equals("prod") && apiKeys == null) {
            throw new IllegalArgumentException("Production requires AUDIT_API_KEYS_FILE");
        }
        return new AuditConfiguration(
                environment,
                ledgerId,
                retentionDays,
                checkpointInterval,
                requestLimitBytes,
                payloadLimitBytes,
                maxDepth,
                maxLeaves,
                Path.of(get(values, "AUDIT_SIGNING_PRIVATE_KEY", "audit-data/signing-private.pem")),
                Path.of(get(values, "AUDIT_SIGNING_PUBLIC_KEY", "audit-data/signing-public.b64")),
                apiKeys);
    }

    public CheckpointSigner loadSigner() throws IOException {
        validateApiKeys();
        return CheckpointSigner.fromFiles(signingPrivateKey, signingPublicKey, environment);
    }

    public void validateApiKeys() throws IOException {
        if (apiKeysFile == null) {
            if (environment.equals("prod")) {
                throw new IllegalArgumentException("Production requires AUDIT_API_KEYS_FILE");
            }
            return;
        }
        if (Files.size(apiKeysFile) > MAX_API_KEY_FILE_BYTES) {
            throw new IllegalArgumentException("API-key file is empty or exceeds 64 KiB");
        }
        byte[] raw;
        try (var input = Files.newInputStream(apiKeysFile)) {
            raw = input.readNBytes(MAX_API_KEY_FILE_BYTES + 1);
        }
        if (raw.length == 0 || raw.length > MAX_API_KEY_FILE_BYTES) {
            throw new IllegalArgumentException("API-key file is empty or exceeds 64 KiB");
        }
        validateApiKeys(CanonicalJson.parse(raw));
    }

    private static void validateApiKeys(JsonNode principals) {
        if (!principals.isObject() || principals.size() == 0 || principals.size() > 10_000) {
            throw new IllegalArgumentException("API-key file must be a non-empty principal object");
        }
        principals.fields().forEachRemaining(principal -> {
            if (principal.getKey().isBlank() || principal.getKey().length() > 128
                    || !principal.getValue().isObject()) {
                throw new IllegalArgumentException("API-key file contains an invalid principal");
            }
            JsonNode entry = principal.getValue();
            Set<String> entryFields = new HashSet<>();
            entry.fieldNames().forEachRemaining(entryFields::add);
            if (!entryFields.equals(Set.of("keyHash", "roles"))) {
                throw new IllegalArgumentException("API-key entries require exactly keyHash and roles");
            }
            JsonNode keyHash = entry.get("keyHash");
            JsonNode roles = entry.get("roles");
            if (!keyHash.isTextual() || !SHA256.matcher(keyHash.textValue()).matches()) {
                throw new IllegalArgumentException("API-key entries must contain lowercase SHA-256 hashes");
            }
            if (!roles.isArray() || roles.size() == 0) {
                throw new IllegalArgumentException("API-key entries require one or more roles");
            }
            Set<String> uniqueRoles = new HashSet<>();
            roles.forEach(role -> {
                if (!role.isTextual() || !ALLOWED_ROLES.contains(role.textValue())
                        || !uniqueRoles.add(role.textValue())) {
                    throw new IllegalArgumentException("API-key entries contain invalid roles");
                }
            });
        });
    }

    private static int positiveInt(Map<String, String> values, String name, int fallback) {
        String raw = get(values, name, Integer.toString(fallback));
        try {
            int result = Integer.parseInt(raw);
            if (result <= 0) {
                throw new IllegalArgumentException(name + " must be a positive integer");
            }
            return result;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(name + " must be a positive integer", exception);
        }
    }

    private static void bounded(String name, int value, int maximum) {
        if (value > maximum) {
            throw new IllegalArgumentException(name + " exceeds its supported maximum");
        }
    }

    private static String get(Map<String, String> values, String name, String fallback) {
        return values.getOrDefault(name, fallback);
    }
}
