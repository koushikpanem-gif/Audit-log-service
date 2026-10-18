package com.auditlog.web;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class ApiKeyAuthenticator {

    private static final Map<String, Set<String>> DEVELOPMENT_ROLES = Map.of(
            "dev-writer", Set.of("writer"),
            "dev-reader", Set.of("reader"),
            "dev-auditor", Set.of("auditor"),
            "dev-admin", Set.of("admin", "writer", "reader", "auditor"));

    private static final Map<String, String> DEVELOPMENT_HASHES = Map.of(
            "dev-writer", "469a1f393460157d3dfb2d2210e03fc40d30869efd06e9e6b4d85a34f4ceb802",
            "dev-reader", "c0662461952624f51ddb16a15d818f2d0f98897d88acc6089c6062e51c84315d",
            "dev-auditor", "97e970584eec0376b698e47aab5d6c57375032d102e948505979c84d3025c912",
            "dev-admin", "33d791b3399bc60ca2ac26ac5aba3ba02efda2052576091bab53ced197463fda");

    private final List<ApiPrincipal> principals;
    private final byte[] cursorSigningKey;

    public ApiKeyAuthenticator(AuditConfiguration configuration) throws IOException {
        List<ApiPrincipal> loaded = configuration.apiKeysFile() == null
                ? developmentPrincipals(configuration)
                : filePrincipals(configuration);
        this.principals = List.copyOf(loaded);
        this.cursorSigningKey = deriveCursorSigningKey(loaded);
    }

    public AuthenticatedPrincipal authenticate(String presentedKey) {
        byte[] candidateHash = sha256(
                presentedKey == null ? new byte[0] : presentedKey.getBytes(StandardCharsets.UTF_8));
        ApiPrincipal match = null;
        boolean ambiguous = false;
        for (ApiPrincipal principal : principals) {
            boolean equal = MessageDigest.isEqual(candidateHash, principal.keyHash());
            if (equal) {
                ambiguous |= match != null;
                match = principal;
            }
        }
        if (presentedKey == null || presentedKey.isBlank() || match == null || ambiguous) {
            return null;
        }
        return new AuthenticatedPrincipal(match.name(), match.roles());
    }

    public byte[] cursorSigningKey() {
        return cursorSigningKey.clone();
    }

    private static List<ApiPrincipal> developmentPrincipals(AuditConfiguration configuration) {
        if (!"dev".equals(configuration.environment())) {
            throw new IllegalArgumentException("Production requires an API-key file");
        }
        List<ApiPrincipal> result = new ArrayList<>();
        DEVELOPMENT_HASHES.forEach((name, hash) ->
                result.add(new ApiPrincipal(name, HexFormat.of().parseHex(hash),
                        DEVELOPMENT_ROLES.get(name))));
        return result;
    }

    private static List<ApiPrincipal> filePrincipals(AuditConfiguration configuration)
            throws IOException {
        configuration.validateApiKeys();
        byte[] bytes;
        try (var input = java.nio.file.Files.newInputStream(configuration.apiKeysFile())) {
            bytes = input.readNBytes(64 * 1024 + 1);
        }
        if (bytes.length > 64 * 1024) {
            throw new IOException("API-key file exceeds its configured size limit");
        }
        JsonNode root = CanonicalJson.parse(bytes);
        List<ApiPrincipal> result = new ArrayList<>();
        Set<String> hashes = new HashSet<>();
        root.fields().forEachRemaining(entry -> {
            String keyHash = entry.getValue().get("keyHash").textValue();
            if (!hashes.add(keyHash)) {
                throw new IllegalArgumentException("API-key principals must have unique key hashes");
            }
            Set<String> roles = new java.util.HashSet<>();
            entry.getValue().get("roles").forEach(role -> roles.add(role.textValue()));
            result.add(new ApiPrincipal(
                    entry.getKey(),
                    HexFormat.of().parseHex(keyHash),
                    Set.copyOf(roles)));
        });
        return result;
    }

    private static byte[] deriveCursorSigningKey(List<ApiPrincipal> principals) {
        List<ApiPrincipal> sorted = principals.stream()
                .sorted(java.util.Comparator.comparing(ApiPrincipal::name))
                .toList();
        StringBuilder material = new StringBuilder("audit-log/query-cursor/v1");
        for (ApiPrincipal principal : sorted) {
            material.append('\u0000')
                    .append(principal.name())
                    .append('\u0000')
                    .append(HexFormat.of().formatHex(principal.keyHash()));
        }
        return sha256(material.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private record ApiPrincipal(String name, byte[] keyHash, Set<String> roles) {
        private ApiPrincipal {
            keyHash = keyHash.clone();
            roles = Set.copyOf(roles);
        }

        @Override
        public byte[] keyHash() {
            return keyHash.clone();
        }
    }

    public record AuthenticatedPrincipal(String name, Set<String> roles) {
        public AuthenticatedPrincipal {
            roles = Set.copyOf(roles);
        }
    }
}
