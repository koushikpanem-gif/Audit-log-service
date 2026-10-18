package com.auditlog.core.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.util.HexFormat;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

class V1HashesTests {

    @Test
    void matchesSharedIndependentHashVectors() throws IOException {
        JsonNode hashes = vectors().path("hashes");
        String genesis = V1Hashes.genesisHash(hashes.path("ledgerId").textValue());
        assertEquals(hashes.path("genesisHash").textValue(), genesis);

        JsonNode leaf = hashes.path("leaf");
        assertEquals(
                leaf.path("hash").textValue(),
                V1Hashes.leafHash(
                        HexFormat.of().parseHex(leaf.path("saltHex").textValue()),
                        leaf.path("pointer").textValue(),
                        leaf.path("value").textValue()));

        String contentHash = V1Hashes.contentHash(V1Hashes.contentObject(
                1,
                "evt-1",
                "TEST",
                "alice",
                "ACCOUNT",
                "acct-1",
                null,
                "2026-01-02T03:04:05.000000Z",
                "writer",
                Map.of("ok", "a".repeat(64))));
        assertEquals(hashes.path("content").path("hash").textValue(), contentHash);
        assertEquals(hashes.path("chainHash").textValue(), V1Hashes.chainHash(genesis, contentHash));
    }

    @Test
    void contentObjectHasExactFieldsAndExplicitNullOccurredAt() {
        Map<String, Object> content = V1Hashes.contentObject(
                1,
                "evt-1",
                "TEST",
                "alice",
                "ACCOUNT",
                "acct-1",
                null,
                "2026-01-02T03:04:05.000000Z",
                "writer",
                Map.of("ok", "a".repeat(64)));
        assertEquals(11, content.size());
        assertEquals(1, content.get("v"));
        assertEquals(1L, content.get("seq"));
        assertEquals(null, content.get("occurredAt"));
        assertEquals("2026-01-02T03:04:05.000000Z", content.get("recordedAt"));
    }

    @Test
    void rejectsInvalidLeafAndChainHashInputs() {
        assertThrows(
                IllegalArgumentException.class,
                () -> V1Hashes.leafHash(new byte[31], "/x", "value"));
        assertThrows(
                IllegalArgumentException.class,
                () -> V1Hashes.leafHash(new byte[32], "/x", Map.of("nested", true)));
        assertThrows(
                IllegalArgumentException.class,
                () -> V1Hashes.chainHash("A".repeat(64), "0".repeat(64)));
        assertThrows(
                IllegalArgumentException.class,
                () -> V1Hashes.chainHash("0".repeat(64), "0".repeat(63)));
    }

    @Test
    void rejectsContentWithMissingOrExtraFields() {
        assertThrows(
                IllegalArgumentException.class,
                () -> V1Hashes.contentHash(Map.of("v", 1)));
    }

    @Test
    void rejectsUncommittedPayloadScalars() {
        assertThrows(
                IllegalArgumentException.class,
                () -> V1Hashes.contentObject(
                        1,
                        "evt-1",
                        "TEST",
                        "alice",
                        "ACCOUNT",
                        "acct-1",
                        null,
                        "2026-01-02T03:04:05.000000Z",
                        "writer",
                        Map.of("secret", "plaintext")));
    }

    private JsonNode vectors() throws IOException {
        try (InputStream input = getClass().getClassLoader()
                .getResourceAsStream("test-vectors/jcs-v1.json")) {
            if (input == null) {
                throw new IOException("Shared hash vector file is missing");
            }
            return CanonicalJson.parse(input.readAllBytes());
        }
    }
}
