package com.auditlog.core.crypto;

import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

public final class PayloadCommitments {

    public static final int MAX_PAYLOAD_BYTES = 64 * 1024;
    public static final int MAX_SCALAR_LEAVES = 500;
    public static final String REDACTED_VALUE = "[REDACTED]";

    private static final SecureRandom RANDOM = new SecureRandom();

    private PayloadCommitments() {
    }

    public static CommitmentResult commit(Map<String, ?> payload) {
        return commit(payload, PayloadCommitments::randomSalt);
    }

    static CommitmentResult commit(Map<String, ?> payload, Supplier<byte[]> saltSource) {
        int expectedLeafCount = validatePayloadSize(payload);

        Map<String, Object> commitments = new LinkedHashMap<>();
        Map<String, PayloadLeaf> leaves = new LinkedHashMap<>();
        Deque<BuildFrame> pending = new ArrayDeque<>();
        List<Map.Entry<String, ?>> rootEntries = new ArrayList<>(payload.entrySet());
        for (int index = rootEntries.size() - 1; index >= 0; index--) {
            Map.Entry<String, ?> entry = rootEntries.get(index);
            pending.push(new BuildFrame(entry.getValue(), commitments, null,
                    entry.getKey(), null, 0, childPointer("", entry.getKey())));
        }

        while (!pending.isEmpty()) {
            BuildFrame frame = pending.pop();
            if (frame.value() instanceof Map<?, ?> source) {
                Map<String, Object> child = new LinkedHashMap<>();
                assign(frame, child);
                List<Map.Entry<?, ?>> entries = new ArrayList<>(source.entrySet());
                for (int index = entries.size() - 1; index >= 0; index--) {
                    Map.Entry<?, ?> entry = entries.get(index);
                    if (!(entry.getKey() instanceof String key)) {
                        throw new IllegalArgumentException("Payload object keys must be strings");
                    }
                    pending.push(new BuildFrame(entry.getValue(), child, null,
                            key, null, frame.depth() + 1, childPointer(frame.pointer(), key)));
                }
            } else if (frame.value() instanceof List<?> source) {
                List<Object> child = new ArrayList<>(Collections.nCopies(source.size(), null));
                assign(frame, child);
                for (int index = source.size() - 1; index >= 0; index--) {
                    pending.push(new BuildFrame(source.get(index), null, child,
                            null, index, frame.depth() + 1,
                            childPointer(frame.pointer(), Integer.toString(index))));
                }
            } else {
                byte[] salt = saltSource.get();
                if (salt == null || salt.length != 32) {
                    throw new IllegalArgumentException("Salt source must return exactly 32 bytes");
                }
                byte[] storedSalt = salt.clone();
                leaves.put(frame.pointer(), new PayloadLeaf(storedSalt, frame.value()));
                assign(frame, V1Hashes.leafHash(storedSalt, frame.pointer(), frame.value()));
            }
        }

        if (leaves.size() != expectedLeafCount) {
            throw new IllegalStateException("Payload leaf count changed during commitment");
        }
        return new CommitmentResult(commitments, leaves);
    }

    public static RevealResult reveal(
            Map<String, ?> commitments,
            Map<String, PayloadLeaf> leaves) {
        if (commitments == null || leaves == null) {
            throw new IllegalArgumentException("Commitments and stored leaves are required");
        }
        validateCommitmentTree(commitments);
        Map<String, Object> payload = new LinkedHashMap<>();
        Deque<RevealFrame> pending = new ArrayDeque<>();
        List<Map.Entry<String, ?>> rootEntries = new ArrayList<>(commitments.entrySet());
        for (int index = rootEntries.size() - 1; index >= 0; index--) {
            Map.Entry<String, ?> entry = rootEntries.get(index);
            pending.push(new RevealFrame(entry.getValue(), payload, null, entry.getKey(),
                    null, childPointer("", entry.getKey())));
        }

        Set<String> redactedPaths = new TreeSet<>();
        Set<String> usedLeaves = new TreeSet<>();
        while (!pending.isEmpty()) {
            RevealFrame frame = pending.pop();
            if (frame.value() instanceof Map<?, ?> source) {
                Map<String, Object> child = new LinkedHashMap<>();
                assign(frame, child);
                List<Map.Entry<?, ?>> entries = new ArrayList<>(source.entrySet());
                for (int index = entries.size() - 1; index >= 0; index--) {
                    Map.Entry<?, ?> entry = entries.get(index);
                    if (!(entry.getKey() instanceof String key)) {
                        throw new IllegalArgumentException("Malformed payload commitment object");
                    }
                    pending.push(new RevealFrame(entry.getValue(), child, null, key, null,
                            childPointer(frame.pointer(), key)));
                }
            } else if (frame.value() instanceof List<?> source) {
                List<Object> child = new ArrayList<>(Collections.nCopies(source.size(), null));
                assign(frame, child);
                for (int index = source.size() - 1; index >= 0; index--) {
                    pending.push(new RevealFrame(source.get(index), null, child, null, index,
                            childPointer(frame.pointer(), Integer.toString(index))));
                }
            } else if (frame.value() instanceof String hash && hash.matches("[0-9a-f]{64}")) {
                PayloadLeaf leaf = leaves.get(frame.pointer());
                if (leaf == null) {
                    assign(frame, REDACTED_VALUE);
                    redactedPaths.add(frame.pointer());
                } else {
                    if (!V1Hashes.leafHash(leaf.salt(), frame.pointer(), leaf.value()).equals(hash)) {
                        throw new IllegalArgumentException(
                                "Payload leaf commitment mismatch at " + frame.pointer());
                    }
                    usedLeaves.add(frame.pointer());
                    assign(frame, leaf.value());
                }
            } else {
                throw new IllegalArgumentException(
                        "Malformed payload commitment tree at " + frame.pointer());
            }
        }
        if (!usedLeaves.equals(leaves.keySet())) {
            throw new IllegalArgumentException("Stored payload leaves do not match the commitment tree");
        }
        return new RevealResult(payload, List.copyOf(redactedPaths));
    }

    public static List<String> expandSubtreePointer(Map<String, ?> payload, String pointer) {
        validatePayloadSize(payload);
        List<String> tokens = parsePointer(pointer);
        Object node = payload;
        String currentPointer = "";
        for (String token : tokens) {
            node = resolveChild(node, token);
            currentPointer = childPointer(currentPointer, token);
        }

        List<String> leafPointers = new ArrayList<>();
        Deque<PointerFrame> pending = new ArrayDeque<>();
        pending.push(new PointerFrame(node, currentPointer));
        while (!pending.isEmpty()) {
            PointerFrame frame = pending.pop();
            if (frame.value() instanceof Map<?, ?> object) {
                List<Map.Entry<?, ?>> entries = new ArrayList<>(object.entrySet());
                for (int index = entries.size() - 1; index >= 0; index--) {
                    Map.Entry<?, ?> entry = entries.get(index);
                    if (!(entry.getKey() instanceof String key)) {
                        throw new IllegalArgumentException("Payload object keys must be strings");
                    }
                    pending.push(new PointerFrame(
                            entry.getValue(), childPointer(frame.pointer(), key)));
                }
            } else if (frame.value() instanceof List<?> array) {
                for (int index = array.size() - 1; index >= 0; index--) {
                    pending.push(new PointerFrame(
                            array.get(index),
                            childPointer(frame.pointer(), Integer.toString(index))));
                }
            } else {
                leafPointers.add(frame.pointer());
            }
        }
        leafPointers.sort(Comparator.naturalOrder());
        return List.copyOf(leafPointers);
    }

    private static int validatePayloadSize(Map<String, ?> payload) {
        int leafCount = validatePayload(payload);
        if (CanonicalJson.canonicalize(payload).length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("Payload exceeds the byte limit");
        }
        return leafCount;
    }

    private static int validatePayload(Map<String, ?> payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload must be a JSON object");
        }
        if (payload.size() > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("Payload exceeds the byte limit");
        }
        Deque<ValidationFrame> pending = new ArrayDeque<>();
        for (Map.Entry<?, ?> entry : payload.entrySet()) {
            if (!(entry.getKey() instanceof String)) {
                throw new IllegalArgumentException("Payload object keys must be strings");
            }
        }
        long textBytes = payload.keySet().stream()
                .mapToLong(PayloadCommitments::utf8Length)
                .sum();
        requirePayloadSize(textBytes);
        payload.values().forEach(value -> pending.push(new ValidationFrame(value, 1, false)));
        IdentityHashMap<Object, Boolean> activeContainers = new IdentityHashMap<>();
        int nodeCount = 0;
        int leafCount = 0;
        while (!pending.isEmpty()) {
            ValidationFrame frame = pending.pop();
            if (frame.exiting()) {
                activeContainers.remove(frame.value());
                continue;
            }
            if (++nodeCount > MAX_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("Payload exceeds the byte limit");
            }
            if (frame.value() instanceof Map<?, ?> object) {
                if (frame.depth() >= CanonicalJson.MAX_NESTING_DEPTH) {
                    throw new IllegalArgumentException("Payload nesting depth exceeds the limit");
                }
                if (activeContainers.put(frame.value(), Boolean.TRUE) != null) {
                    throw new IllegalArgumentException("Cyclic payload is not JSON serializable");
                }
                pending.push(new ValidationFrame(frame.value(), frame.depth(), true));
                if (object.size() > MAX_PAYLOAD_BYTES) {
                    throw new IllegalArgumentException("Payload exceeds the byte limit");
                }
                for (Map.Entry<?, ?> entry : object.entrySet()) {
                    if (!(entry.getKey() instanceof String key)) {
                        throw new IllegalArgumentException("Payload object keys must be strings");
                    }
                    textBytes += utf8Length(key);
                    requirePayloadSize(textBytes);
                    pending.push(new ValidationFrame(
                            entry.getValue(), frame.depth() + 1, false));
                }
            } else if (frame.value() instanceof List<?> array) {
                if (frame.depth() >= CanonicalJson.MAX_NESTING_DEPTH) {
                    throw new IllegalArgumentException("Payload nesting depth exceeds the limit");
                }
                if (activeContainers.put(frame.value(), Boolean.TRUE) != null) {
                    throw new IllegalArgumentException("Cyclic payload is not JSON serializable");
                }
                pending.push(new ValidationFrame(frame.value(), frame.depth(), true));
                if (array.size() > MAX_PAYLOAD_BYTES) {
                    throw new IllegalArgumentException("Payload exceeds the byte limit");
                }
                for (Object value : array) {
                    pending.push(new ValidationFrame(value, frame.depth() + 1, false));
                }
            } else {
                if (frame.value() instanceof String text) {
                    textBytes += utf8Length(text);
                    requirePayloadSize(textBytes);
                }
                if (++leafCount > MAX_SCALAR_LEAVES) {
                    throw new IllegalArgumentException("Payload exceeds the scalar leaf limit");
                }
            }
        }
        return leafCount;
    }

    private static void validateCommitmentTree(Map<String, ?> commitments) {
        if (commitments.size() > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("Payload exceeds the byte limit");
        }
        Deque<ValidationFrame> pending = new ArrayDeque<>();
        for (Map.Entry<?, ?> entry : commitments.entrySet()) {
            if (!(entry.getKey() instanceof String)) {
                throw new IllegalArgumentException("Payload object keys must be strings");
            }
        }
        long textBytes = commitments.keySet().stream()
                .mapToLong(PayloadCommitments::utf8Length)
                .sum();
        requirePayloadSize(textBytes);
        commitments.values().forEach(value -> pending.push(new ValidationFrame(value, 1, false)));
        IdentityHashMap<Object, Boolean> activeContainers = new IdentityHashMap<>();
        int nodeCount = 0;
        int leafCount = 0;
        while (!pending.isEmpty()) {
            ValidationFrame frame = pending.pop();
            if (frame.exiting()) {
                activeContainers.remove(frame.value());
                continue;
            }
            if (++nodeCount > MAX_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("Payload exceeds the byte limit");
            }
            if (frame.value() instanceof Map<?, ?> object) {
                if (frame.depth() >= CanonicalJson.MAX_NESTING_DEPTH) {
                    throw new IllegalArgumentException("Payload nesting depth exceeds the limit");
                }
                if (activeContainers.put(frame.value(), Boolean.TRUE) != null) {
                    throw new IllegalArgumentException("Cyclic payload is not JSON serializable");
                }
                pending.push(new ValidationFrame(frame.value(), frame.depth(), true));
                if (object.size() > MAX_PAYLOAD_BYTES) {
                    throw new IllegalArgumentException("Payload exceeds the byte limit");
                }
                for (Map.Entry<?, ?> entry : object.entrySet()) {
                    if (!(entry.getKey() instanceof String key)) {
                        throw new IllegalArgumentException("Payload object keys must be strings");
                    }
                    textBytes += utf8Length(key);
                    requirePayloadSize(textBytes);
                    pending.push(new ValidationFrame(
                            entry.getValue(), frame.depth() + 1, false));
                }
            } else if (frame.value() instanceof List<?> array) {
                if (frame.depth() >= CanonicalJson.MAX_NESTING_DEPTH) {
                    throw new IllegalArgumentException("Payload nesting depth exceeds the limit");
                }
                if (activeContainers.put(frame.value(), Boolean.TRUE) != null) {
                    throw new IllegalArgumentException("Cyclic payload is not JSON serializable");
                }
                pending.push(new ValidationFrame(frame.value(), frame.depth(), true));
                if (array.size() > MAX_PAYLOAD_BYTES) {
                    throw new IllegalArgumentException("Payload exceeds the byte limit");
                }
                for (Object child : array) {
                    pending.push(new ValidationFrame(child, frame.depth() + 1, false));
                }
            } else if (frame.value() instanceof String hash && hash.matches("[0-9a-f]{64}")) {
                if (++leafCount > MAX_SCALAR_LEAVES) {
                    throw new IllegalArgumentException("Payload exceeds the scalar leaf limit");
                }
            } else {
                throw new IllegalArgumentException("Malformed payload commitment tree");
            }
        }
        if (CanonicalJson.canonicalize(commitments).length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("Payload exceeds the byte limit");
        }
    }

    private static List<String> parsePointer(String pointer) {
        if (pointer == null) {
            throw new IllegalArgumentException("JSON Pointer is required");
        }
        if (utf8Length(pointer) > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("JSON Pointer exceeds the byte limit");
        }
        if (pointer.isEmpty()) {
            return List.of();
        }
        if (!pointer.startsWith("/")) {
            throw new IllegalArgumentException("JSON Pointer must be empty or start with '/'");
        }
        List<String> tokens = new ArrayList<>();
        for (String raw : pointer.substring(1).split("/", -1)) {
            StringBuilder token = new StringBuilder();
            for (int index = 0; index < raw.length(); index++) {
                char character = raw.charAt(index);
                if (character != '~') {
                    token.append(character);
                } else if (index + 1 < raw.length()
                        && (raw.charAt(index + 1) == '0' || raw.charAt(index + 1) == '1')) {
                    token.append(raw.charAt(++index) == '0' ? '~' : '/');
                } else {
                    throw new IllegalArgumentException("JSON Pointer contains an invalid escape");
                }
            }
            tokens.add(token.toString());
        }
        return List.copyOf(tokens);
    }

    private static Object resolveChild(Object value, String token) {
        if (value instanceof Map<?, ?> object) {
            if (!object.containsKey(token)) {
                throw new IllegalArgumentException("JSON Pointer path does not exist");
            }
            return object.get(token);
        }
        if (value instanceof List<?> array) {
            if (!token.matches("(?:0|[1-9][0-9]*)")) {
                throw new IllegalArgumentException("JSON Pointer array index is not canonical");
            }
            String size = Integer.toString(array.size());
            if (token.length() > size.length()
                    || (token.length() == size.length() && token.compareTo(size) >= 0)) {
                throw new IllegalArgumentException("JSON Pointer path does not exist");
            }
            int index = Integer.parseInt(token);
            if (index >= array.size()) {
                throw new IllegalArgumentException("JSON Pointer path does not exist");
            }
            return array.get(index);
        }
        throw new IllegalArgumentException("JSON Pointer path does not exist");
    }

    private static String childPointer(String parent, String token) {
        return parent + "/" + token.replace("~", "~0").replace("/", "~1");
    }

    private static byte[] randomSalt() {
        byte[] salt = new byte[32];
        RANDOM.nextBytes(salt);
        return salt;
    }

    private static long utf8Length(String value) {
        long length = 0;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 >= value.length()
                        || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    throw new IllegalArgumentException("JSON strings must contain valid Unicode");
                }
                length += 4;
                index++;
            } else if (Character.isLowSurrogate(character)) {
                throw new IllegalArgumentException("JSON strings must contain valid Unicode");
            } else if (character <= 0x7F) {
                length++;
            } else if (character <= 0x7FF) {
                length += 2;
            } else {
                length += 3;
            }
            requirePayloadSize(length);
        }
        return length;
    }

    private static void requirePayloadSize(long size) {
        if (size > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("Payload exceeds the byte limit");
        }
    }

    private static void assign(BuildFrame frame, Object value) {
        if (frame.parentMap() != null) {
            frame.parentMap().put(frame.mapKey(), value);
        } else {
            frame.parentList().set(frame.listIndex(), value);
        }
    }

    private static void assign(RevealFrame frame, Object value) {
        if (frame.parentMap() != null) {
            frame.parentMap().put(frame.mapKey(), value);
        } else {
            frame.parentList().set(frame.listIndex(), value);
        }
    }

    public record PayloadLeaf(byte[] salt, Object value) {
        public PayloadLeaf {
            if (salt == null || salt.length != 32) {
                throw new IllegalArgumentException("Leaf salt must contain exactly 32 bytes");
            }
            if (value instanceof Map<?, ?> || value instanceof List<?>) {
                throw new IllegalArgumentException("Stored payload leaf must be a JSON scalar");
            }
            salt = salt.clone();
        }

        @Override
        public byte[] salt() {
            return salt.clone();
        }
    }

    public record CommitmentResult(
            Map<String, Object> commitments,
            Map<String, PayloadLeaf> leaves) {
        public CommitmentResult {
            commitments = Collections.unmodifiableMap(new LinkedHashMap<>(commitments));
            leaves = Collections.unmodifiableMap(new LinkedHashMap<>(leaves));
        }
    }

    public record RevealResult(Map<String, Object> payload, List<String> redactedPaths) {
        public RevealResult {
            payload = Collections.unmodifiableMap(new LinkedHashMap<>(payload));
            redactedPaths = List.copyOf(redactedPaths);
        }
    }

    private record BuildFrame(
            Object value,
            Map<String, Object> parentMap,
            List<Object> parentList,
            String mapKey,
            Integer listIndex,
            int depth,
            String pointer) {
    }

    private record RevealFrame(
            Object value,
            Map<String, Object> parentMap,
            List<Object> parentList,
            String mapKey,
            Integer listIndex,
            String pointer) {
    }

    private record ValidationFrame(Object value, int depth, boolean exiting) {
    }

    private record PointerFrame(Object value, String pointer) {
    }
}
