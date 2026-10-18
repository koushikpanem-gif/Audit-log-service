package com.auditlog.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

class CanonicalJsonTests {

    @Test
    void matchesSharedRfc8785GoldenVectors() throws IOException {
        JsonNode vectors = vectors();
        for (JsonNode vector : vectors.path("canonicalization")) {
            byte[] actual = CanonicalJson.canonicalize(vector.path("input").textValue());
            assertArrayEquals(
                    vector.path("expected").textValue().getBytes(StandardCharsets.UTF_8),
                    actual,
                    vector.path("name").textValue());
        }
    }

    @Test
    void rejectsDuplicateKeysIncludingEscapedEquivalentKeys() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CanonicalJson.parse("{\"x\":null,\"x\":1}".getBytes(StandardCharsets.UTF_8)));
        assertThrows(
                IllegalArgumentException.class,
                () -> CanonicalJson.parse(
                        "{\"x\":1,\"\\u0078\":2}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void rejectsUnsafeIntegersNonFiniteNumbersAndTrailingValues() {
        for (String invalid : new String[] {
                "9007199254740992",
                "-9007199254740992",
                "NaN",
                "Infinity",
                "-Infinity",
                "1e400",
                "{\"x\":1} false"
        }) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> CanonicalJson.parse(invalid.getBytes(StandardCharsets.UTF_8)),
                    invalid);
        }
    }

    @Test
    void rejectsInvalidUnicodeUtf8AndDepthBeforeCanonicalization() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CanonicalJson.parse("{\"x\":\"\\uD800\"}".getBytes(StandardCharsets.UTF_8)));
        assertThrows(
                IllegalArgumentException.class,
                () -> CanonicalJson.parse(new byte[] {'"', (byte) 0xc3, '(', '"'}));
        assertThrows(
                IllegalArgumentException.class,
                () -> CanonicalJson.parse(("[".repeat(11) + "0" + "]".repeat(11))
                        .getBytes(StandardCharsets.UTF_8)));
        assertThrows(
                IllegalArgumentException.class,
                () -> CanonicalJson.parse(new byte[CanonicalJson.MAX_INPUT_BYTES + 1]));
    }

    @Test
    void validatesProgrammaticValuesBeforeSerialization() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CanonicalJson.canonicalize(9_007_199_254_740_992L));
        assertThrows(
                IllegalArgumentException.class,
                () -> CanonicalJson.canonicalize(Double.POSITIVE_INFINITY));
        assertThrows(
                IllegalArgumentException.class,
                () -> CanonicalJson.canonicalize(Double.NaN));
        assertThrows(
                IllegalArgumentException.class,
                () -> CanonicalJson.canonicalize("\ud800"));
    }

    private JsonNode vectors() throws IOException {
        try (InputStream input = getClass().getClassLoader()
                .getResourceAsStream("test-vectors/jcs-v1.json")) {
            if (input == null) {
                throw new IOException("Shared JCS vector file is missing");
            }
            return CanonicalJson.parse(input.readAllBytes());
        }
    }
}
