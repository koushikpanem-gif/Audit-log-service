package com.auditlog.core.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

class PayloadCommitmentsTests {

    @Test
    void commitsScalarsAndPreservesNullsAndEmptyContainers() {
        Map<String, Object> payload = mixedPayload();
        AtomicInteger nextSalt = new AtomicInteger(1);
        PayloadCommitments.CommitmentResult result = PayloadCommitments.commit(
                payload,
                () -> {
                    byte[] salt = new byte[32];
                    salt[31] = (byte) nextSalt.getAndIncrement();
                    return salt;
                });

        assertTrue(result.commitments().get("a/b") instanceof Map<?, ?>);
        Map<?, ?> branch = (Map<?, ?>) result.commitments().get("a/b");
        Map<?, ?> keyed = (Map<?, ?>) branch.get("~key");
        List<?> values = (List<?>) keyed.get("items");
        assertEquals("{}", branch.get("empty").toString());
        assertEquals(List.of(), keyed.get("emptyArray"));
        assertEquals(5, values.size());
        assertEquals(4, result.leaves().size());
        assertTrue(values.get(0) instanceof String);
        assertEquals(
                List.of("/a~1b/~0key/items/0", "/a~1b/~0key/items/1",
                        "/a~1b/~0key/items/2", "/tail"),
                result.leaves().keySet().stream().sorted().toList());
        assertNull(result.leaves().get("/a~1b/~0key/items/0").value());
    }

    @Test
    void revealsLeavesAndMarksMissingValuesWithSortedPaths() {
        PayloadCommitments.CommitmentResult result =
                PayloadCommitments.commit(mixedPayload(), () -> new byte[32]);
        assertEquals(mixedPayload(), PayloadCommitments.reveal(
                result.commitments(), result.leaves()).payload());

        Map<String, PayloadCommitments.PayloadLeaf> disclosed =
                new LinkedHashMap<>(result.leaves());
        disclosed.remove("/tail");
        disclosed.remove("/a~1b/~0key/items/1");
        PayloadCommitments.RevealResult reveal =
                PayloadCommitments.reveal(result.commitments(), disclosed);
        assertEquals(
                List.of("/a~1b/~0key/items/1", "/tail"),
                reveal.redactedPaths());
        assertEquals(PayloadCommitments.REDACTED_VALUE, reveal.payload().get("tail"));

        PayloadCommitments.RevealResult utf16Sorted = PayloadCommitments.reveal(
                Map.of("\ue000", "0".repeat(64), "\ud800\udc00", "0".repeat(64)),
                Map.of());
        assertEquals(List.of("/\ud800\udc00", "/\ue000"), utf16Sorted.redactedPaths());
    }

    @Test
    void expandsRootAndEscapedSubtreePointers() {
        Map<String, Object> payload = mixedPayload();
        assertEquals(
                List.of("/a~1b/~0key/items/0", "/a~1b/~0key/items/1",
                        "/a~1b/~0key/items/2", "/tail"),
                PayloadCommitments.expandSubtreePointer(payload, ""));
        assertEquals(
                List.of("/a~1b/~0key/items/0", "/a~1b/~0key/items/1",
                        "/a~1b/~0key/items/2"),
                PayloadCommitments.expandSubtreePointer(payload, "/a~1b/~0key"));
        assertEquals(
                List.of("/a~1b/~0key/items/1"),
                PayloadCommitments.expandSubtreePointer(payload, "/a~1b/~0key/items/1"));
        assertEquals(
                List.of(),
                PayloadCommitments.expandSubtreePointer(payload, "/a~1b/empty"));
    }

    @Test
    void rejectsMalformedPointersAndNoncanonicalArrayIndices() {
        Map<String, Object> payload = mixedPayload();
        for (String pointer : List.of(
                "a",
                "/a~",
                "/a~2b",
                "/a~1b/~0key/items/01",
                "/a~1b/~0key/items/-",
                "/a~1b/~0key/items/99",
                "/missing")) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> PayloadCommitments.expandSubtreePointer(payload, pointer),
                    pointer);
        }
    }

    @Test
    void usesFreshSaltsAndRejectsInvalidOrMismatchedLeafData() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new PayloadCommitments.PayloadLeaf(new byte[31], "value"));
        Map<String, Object> payload = Map.of("secret", "same");
        PayloadCommitments.CommitmentResult first = PayloadCommitments.commit(payload);
        PayloadCommitments.CommitmentResult second = PayloadCommitments.commit(payload);
        assertFalse(Arrays.equals(
                first.leaves().get("/secret").salt(),
                second.leaves().get("/secret").salt()));
        assertNotEquals(first.commitments().get("secret"), second.commitments().get("secret"));

        Map<String, PayloadCommitments.PayloadLeaf> altered =
                new LinkedHashMap<>(first.leaves());
        altered.put("/secret", new PayloadCommitments.PayloadLeaf(
                first.leaves().get("/secret").salt(), "different"));
        assertThrows(
                IllegalArgumentException.class,
                () -> PayloadCommitments.reveal(first.commitments(), altered));
    }

    @Test
    void enforcesLeafDepthAndPayloadSizeBeforeGeneratingSalts() {
        AtomicInteger calls = new AtomicInteger();
        java.util.function.Supplier<byte[]> saltSource = () -> {
            calls.incrementAndGet();
            return new byte[32];
        };
        Map<String, Object> tooManyLeaves = new LinkedHashMap<>();
        for (int index = 0; index <= PayloadCommitments.MAX_SCALAR_LEAVES; index++) {
            tooManyLeaves.put(Integer.toString(index), index);
        }
        assertThrows(
                IllegalArgumentException.class,
                () -> PayloadCommitments.commit(tooManyLeaves, saltSource));

        Object nested = 1;
        for (int index = 0; index < 10; index++) {
            nested = List.of(nested);
        }
        Object tooDeep = nested;
        assertThrows(
                IllegalArgumentException.class,
                () -> PayloadCommitments.commit(Map.of("deep", tooDeep), saltSource));
        assertThrows(
                IllegalArgumentException.class,
                () -> PayloadCommitments.commit(
                        Map.of("large", "x".repeat(PayloadCommitments.MAX_PAYLOAD_BYTES)),
                        saltSource));
        List<Object> cyclic = new ArrayList<>();
        cyclic.add(cyclic);
        assertThrows(
                IllegalArgumentException.class,
                () -> PayloadCommitments.commit(Map.of("cycle", cyclic), saltSource));
        assertEquals(0, calls.get());

        Map<String, Object> atLeafLimit = new LinkedHashMap<>();
        for (int index = 0; index < PayloadCommitments.MAX_SCALAR_LEAVES; index++) {
            atLeafLimit.put(Integer.toString(index), index);
        }
        assertEquals(
                PayloadCommitments.MAX_SCALAR_LEAVES,
                PayloadCommitments.commit(atLeafLimit, () -> new byte[32]).leaves().size());

        Object atDepthLimit = "ok";
        for (int index = 0; index < CanonicalJson.MAX_NESTING_DEPTH - 1; index++) {
            atDepthLimit = List.of(atDepthLimit);
        }
        assertEquals(
                1,
                PayloadCommitments.commit(
                        Map.of("deep", atDepthLimit), () -> new byte[32]).leaves().size());

        String exactLimit = "x".repeat(PayloadCommitments.MAX_PAYLOAD_BYTES - 8);
        assertEquals(
                PayloadCommitments.MAX_PAYLOAD_BYTES,
                CanonicalJson.canonicalize(Map.of("x", exactLimit)).length);
        assertEquals(
                exactLimit,
                PayloadCommitments.commit(Map.of("x", exactLimit), () -> new byte[32])
                        .leaves().get("/x").value());
    }

    @Test
    void matchesSharedFixedSaltCommitmentVectors() throws IOException {
        JsonNode vectors = payloadVectors();
        JsonNode expectedLeaves = vectors.path("leaves");
        List<byte[]> salts = new ArrayList<>();
        for (JsonNode leaf : expectedLeaves) {
            salts.add(HexFormat.of().parseHex(leaf.path("saltHex").textValue()));
        }
        AtomicInteger index = new AtomicInteger();
        PayloadCommitments.CommitmentResult result = PayloadCommitments.commit(
                vectorPayload(),
                () -> salts.get(index.getAndIncrement()));

        org.junit.jupiter.api.Assertions.assertArrayEquals(
                CanonicalJson.canonicalize(vectors.path("commitments").toString()),
                CanonicalJson.canonicalize(result.commitments()));
        for (JsonNode expected : expectedLeaves) {
            String pointer = expected.path("pointer").textValue();
            PayloadCommitments.PayloadLeaf leaf = result.leaves().get(pointer);
            assertEquals(expected.path("saltHex").textValue(), HexFormat.of().formatHex(leaf.salt()));
            assertEquals(expected.path("hash").textValue(),
                    V1Hashes.leafHash(leaf.salt(), pointer, leaf.value()));
        }
        assertNull(result.leaves().get("/a~1b/~0key/0").value());
        assertEquals("text", result.leaves().get("/a~1b/~0key/1").value());
        assertEquals(true, result.leaves().get("/enabled").value());
    }

    private Map<String, Object> mixedPayload() {
        Map<String, Object> keyed = new LinkedHashMap<>();
        ArrayList<Object> items = new ArrayList<>();
        items.add(null);
        items.add("text");
        items.add(7);
        items.add(Map.of());
        items.add(List.of());
        keyed.put("items", items);
        keyed.put("emptyArray", List.of());
        Map<String, Object> branch = new LinkedHashMap<>();
        branch.put("~key", keyed);
        branch.put("empty", Map.of());
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("a/b", branch);
        payload.put("tail", true);
        return payload;
    }

    private Map<String, Object> vectorPayload() {
        ArrayList<Object> items = new ArrayList<>();
        items.add(null);
        items.add("text");
        Map<String, Object> branch = new LinkedHashMap<>();
        branch.put("~key", items);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("a/b", branch);
        payload.put("empty", Map.of());
        payload.put("emptyArray", List.of());
        payload.put("enabled", true);
        return payload;
    }

    private JsonNode payloadVectors() throws IOException {
        try (InputStream input = getClass().getClassLoader()
                .getResourceAsStream("test-vectors/payload-commitments-v1.json")) {
            if (input == null) {
                throw new IOException("Shared payload commitment vector is missing");
            }
            return CanonicalJson.parse(input.readAllBytes());
        }
    }
}
