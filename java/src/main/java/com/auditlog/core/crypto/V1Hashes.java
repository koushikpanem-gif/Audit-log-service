package com.auditlog.core.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class V1Hashes {

    public static final int HASH_VERSION = 1;
    private static final BigInteger MAX_SAFE_INTEGER = BigInteger.valueOf(9_007_199_254_740_991L);
    private static final Set<String> CONTENT_KEYS = Set.of(
            "v", "seq", "eventId", "eventType", "actorId", "resourceType",
            "resourceId", "occurredAt", "recordedAt", "source", "payload");

    private V1Hashes() {
    }

    public static String genesisHash(String ledgerId) {
        return hashDomain("audit-log/genesis/v1", utf8(ledgerId));
    }

    public static String leafHash(byte[] salt, String pointer, Object value) {
        if (salt == null || salt.length != 32) {
            throw new IllegalArgumentException("Leaf salt must contain exactly 32 bytes");
        }
        if (value instanceof Map<?, ?> || value instanceof Iterable<?>) {
            throw new IllegalArgumentException("Leaf commitment value must be a JSON scalar");
        }
        byte[] canonicalValue = CanonicalJson.canonicalize(value);
        return hashDomain("audit-log/leaf/v1", salt, new byte[] {0},
                utf8(pointer), new byte[] {0}, canonicalValue);
    }

    public static Map<String, Object> contentObject(
            long seq,
            String eventId,
            String eventType,
            String actorId,
            String resourceType,
            String resourceId,
            String occurredAt,
            String timestamp,
            String source,
            Map<String, Object> payload) {
        Map<String, Object> content = new LinkedHashMap<>();
        content.put("v", HASH_VERSION);
        content.put("seq", seq);
        content.put("eventId", eventId);
        content.put("eventType", eventType);
        content.put("actorId", actorId);
        content.put("resourceType", resourceType);
        content.put("resourceId", resourceId);
        content.put("occurredAt", occurredAt);
        content.put("recordedAt", timestamp);
        content.put("source", source);
        content.put("payload", payload);
        validateContent(content);
        return Collections.unmodifiableMap(content);
    }

    public static String contentHash(Map<String, ?> content) {
        validateContent(content);
        return hashDomain("audit-log/content/v1", CanonicalJson.canonicalize(content));
    }

    public static String chainHash(String previousHash, String contentHash) {
        byte[] previous = decodeHash(previousHash);
        byte[] content = decodeHash(contentHash);
        return hashDomain("audit-log/chain/v1", previous, content);
    }

    private static void validateContent(Map<String, ?> content) {
        if (content == null || !content.keySet().equals(CONTENT_KEYS)) {
            throw new IllegalArgumentException("V1 content must have exactly the required keys");
        }
        if (!(content.get("v") instanceof Number version) || version.longValue() != HASH_VERSION
                || !isSafePositiveInteger(version)) {
            throw new IllegalArgumentException("Unsupported content hash version");
        }
        Object seq = content.get("seq");
        if (!(seq instanceof Number number) || !isSafePositiveInteger(number)) {
            throw new IllegalArgumentException("Content sequence must be a positive safe integer");
        }
        for (String key : Set.of(
                "eventId", "eventType", "actorId", "resourceType", "resourceId",
                "recordedAt", "source")) {
            if (!(content.get(key) instanceof String)) {
                throw new IllegalArgumentException("Content field must be a string: " + key);
            }
        }
        if (content.get("occurredAt") != null && !(content.get("occurredAt") instanceof String)) {
            throw new IllegalArgumentException("occurredAt must be a string or null");
        }
        if (!(content.get("payload") instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("Content payload must be a JSON object");
        }
        validateCommitmentTree((Map<?, ?>) content.get("payload"));
    }

    private static void validateCommitmentTree(Map<?, ?> payload) {
        Deque<CommitmentFrame> pending = new ArrayDeque<>();
        payload.values().forEach(value -> pending.push(new CommitmentFrame(value, 0)));
        while (!pending.isEmpty()) {
            CommitmentFrame frame = pending.pop();
            Object value = frame.value();
            if (value instanceof String commitment) {
                if (!commitment.matches("[0-9a-f]{64}")) {
                    throw new IllegalArgumentException("Payload leaves must be lowercase SHA-256 hashes");
                }
            } else if (value instanceof Map<?, ?> object) {
                if (frame.depth() >= CanonicalJson.MAX_NESTING_DEPTH) {
                    throw new IllegalArgumentException("Payload nesting depth exceeds the limit");
                }
                for (Map.Entry<?, ?> entry : object.entrySet()) {
                    if (!(entry.getKey() instanceof String)) {
                        throw new IllegalArgumentException("Payload object keys must be strings");
                    }
                    pending.push(new CommitmentFrame(entry.getValue(), frame.depth() + 1));
                }
            } else if (value instanceof List<?> array) {
                if (frame.depth() >= CanonicalJson.MAX_NESTING_DEPTH) {
                    throw new IllegalArgumentException("Payload nesting depth exceeds the limit");
                }
                array.forEach(child -> pending.push(new CommitmentFrame(child, frame.depth() + 1)));
            } else {
                throw new IllegalArgumentException("Payload leaves must be commitment strings");
            }
        }
    }

    private static boolean isSafePositiveInteger(Number number) {
        if (number instanceof Byte || number instanceof Short
                || number instanceof Integer || number instanceof Long) {
            long value = number.longValue();
            return value > 0 && value <= MAX_SAFE_INTEGER.longValue();
        }
        if (number instanceof BigInteger value) {
            return value.signum() > 0 && value.compareTo(MAX_SAFE_INTEGER) <= 0;
        }
        return false;
    }

    private static byte[] decodeHash(String hash) {
        if (hash == null || !hash.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Hash must be lowercase 64-character hexadecimal");
        }
        return HexFormat.of().parseHex(hash);
    }

    private static String hashDomain(String domain, byte[]... values) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
        digest.update(utf8(domain));
        digest.update((byte) 0);
        for (byte[] value : values) {
            digest.update(value);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static byte[] utf8(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Text value is required");
        }
        return CanonicalJson.encodeText(value);
    }

    private record CommitmentFrame(Object value, int depth) {
    }
}
