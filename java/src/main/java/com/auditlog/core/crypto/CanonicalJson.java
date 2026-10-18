package com.auditlog.core.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;

public final class CanonicalJson {

    public static final int MAX_INPUT_BYTES = 256 * 1024;
    public static final int MAX_NESTING_DEPTH = 10;
    /** Upper bound for documents that wrap events, such as export bundles. */
    public static final int MAX_DOCUMENT_DEPTH = 32;
    private static final BigInteger MAX_SAFE_INTEGER = BigInteger.valueOf(9_007_199_254_740_991L);

    private static final JsonFactory JSON_FACTORY = JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(MAX_NESTING_DEPTH)
                    .maxStringLength(MAX_INPUT_BYTES)
                    .maxNumberLength(100)
                    .build())
            .build();
    private static final ObjectMapper MAPPER = new ObjectMapper(JSON_FACTORY)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private CanonicalJson() {
    }

    public static JsonNode parse(byte[] json) {
        return parse(json, MAX_NESTING_DEPTH);
    }

    public static JsonNode parse(byte[] json, int maxDepth) {
        if (maxDepth < 1 || maxDepth > MAX_NESTING_DEPTH + 2) {
            throw new IllegalArgumentException("JSON nesting depth limit is outside supported bounds");
        }
        return parse(json, maxDepth, MAX_INPUT_BYTES);
    }

    /** Parses with caller-chosen limits, for documents (such as export bundles) larger than events. */
    public static JsonNode parse(byte[] json, int maxDepth, int maxBytes) {
        if (json == null || json.length > maxBytes) {
            throw new IllegalArgumentException("JSON input is missing or exceeds the byte limit");
        }
        if (maxDepth < 1 || maxDepth > MAX_DOCUMENT_DEPTH || maxBytes < 1) {
            throw new IllegalArgumentException("JSON nesting depth limit is outside supported bounds");
        }
        String text = decodeUtf8(json);
        checkDepth(text, maxDepth);
        JsonFactory factory = maxDepth == MAX_NESTING_DEPTH
                ? JSON_FACTORY
                : JsonFactory.builder()
                        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                        .streamReadConstraints(StreamReadConstraints.builder()
                                .maxNestingDepth(maxDepth)
                                .maxStringLength(MAX_INPUT_BYTES)
                                .maxNumberLength(100)
                                .build())
                        .build();
        try (JsonParser parser = factory.createParser(text)) {
            while (parser.nextToken() != null) {
                JsonToken token = parser.currentToken();
                if (token == JsonToken.VALUE_NUMBER_INT) {
                    BigInteger integer = new BigInteger(parser.getText());
                    if (integer.abs().compareTo(MAX_SAFE_INTEGER) > 0) {
                        throw new IllegalArgumentException("JSON integer token exceeds the safe range");
                    }
                } else if (token == JsonToken.VALUE_NUMBER_FLOAT) {
                    double number = Double.parseDouble(parser.getText());
                    if (!Double.isFinite(number)) {
                        throw new IllegalArgumentException("JSON number must be finite");
                    }
                }
            }
            JsonNode root;
            try (JsonParser treeParser = factory.createParser(text)) {
                root = MAPPER.readTree(treeParser);
            }
            if (root == null) {
                throw new IllegalArgumentException("JSON input must contain one value");
            }
            validateTree(root, maxDepth);
            return root;
        } catch (IOException | NumberFormatException exception) {
            throw new IllegalArgumentException("Invalid JSON input", exception);
        }
    }

    public static byte[] canonicalize(byte[] json) {
        return canonicalize(json, MAX_NESTING_DEPTH);
    }

    public static byte[] canonicalize(byte[] json, int maxDepth) {
        if (maxDepth < 1 || maxDepth > MAX_NESTING_DEPTH + 2) {
            throw new IllegalArgumentException("JSON nesting depth limit is outside supported bounds");
        }
        return canonicalize(json, maxDepth, MAX_INPUT_BYTES);
    }

    public static byte[] canonicalize(byte[] json, int maxDepth, int maxBytes) {
        parse(json, maxDepth, maxBytes);
        try {
            byte[] wrapped = new JsonCanonicalizer("[" + decodeUtf8(json) + "]").getEncodedUTF8();
            byte[] canonical = new byte[wrapped.length - 2];
            System.arraycopy(wrapped, 1, canonical, 0, canonical.length);
            return canonical;
        } catch (IOException exception) {
            throw new IllegalArgumentException("Unable to canonicalize JSON", exception);
        }
    }

    public static byte[] canonicalize(String json) {
        if (json == null) {
            throw new IllegalArgumentException("JSON input is required");
        }
        return canonicalize(encodeText(json));
    }

    public static byte[] canonicalize(Object value) {
        return canonicalize(value, MAX_NESTING_DEPTH);
    }

    public static byte[] canonicalize(Object value, int maxDepth) {
        if (maxDepth < 1 || maxDepth > MAX_NESTING_DEPTH + 2) {
            throw new IllegalArgumentException("JSON nesting depth limit is outside supported bounds");
        }
        return canonicalize(value, maxDepth, MAX_INPUT_BYTES);
    }

    public static byte[] canonicalize(Object value, int maxDepth, int maxBytes) {
        if (maxDepth < 1 || maxDepth > MAX_DOCUMENT_DEPTH || maxBytes < 1) {
            throw new IllegalArgumentException("JSON nesting depth limit is outside supported bounds");
        }
        validateValue(value, maxDepth);
        try {
            return canonicalize(MAPPER.writeValueAsBytes(value), maxDepth, maxBytes);
        } catch (IOException exception) {
            throw new IllegalArgumentException("Value is not JSON serializable", exception);
        }
    }

    private static String decodeUtf8(byte[] json) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(json))
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("JSON input must be valid UTF-8", exception);
        }
    }

    static byte[] encodeText(String value) {
        validateString(value);
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(java.nio.CharBuffer.wrap(value));
            byte[] bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            return bytes;
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("Text must contain valid Unicode", exception);
        }
    }

    private static void checkDepth(String text, int maxDepth) {
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (character == '\\') {
                    escaped = true;
                } else if (character == '"') {
                    inString = false;
                }
            } else if (character == '"') {
                inString = true;
            } else if (character == '{' || character == '[') {
                depth++;
                if (depth > maxDepth) {
                    throw new IllegalArgumentException("JSON nesting depth exceeds the limit");
                }
            } else if (character == '}' || character == ']') {
                depth--;
            }
        }
    }

    private static void validateTree(JsonNode root, int maxDepth) {
        Deque<TreeFrame> pending = new ArrayDeque<>();
        pending.push(new TreeFrame(root, 0));
        while (!pending.isEmpty()) {
            TreeFrame frame = pending.pop();
            JsonNode node = frame.node();
            if (node.isTextual()) {
                validateString(node.textValue());
            } else if (node.isObject()) {
                if (frame.depth() >= maxDepth) {
                    throw new IllegalArgumentException("JSON nesting depth exceeds the limit");
                }
                node.properties().forEach(entry -> {
                    validateString(entry.getKey());
                    pending.push(new TreeFrame(entry.getValue(), frame.depth() + 1));
                });
            } else if (node.isArray()) {
                if (frame.depth() >= maxDepth) {
                    throw new IllegalArgumentException("JSON nesting depth exceeds the limit");
                }
                node.elements().forEachRemaining(child ->
                        pending.push(new TreeFrame(child, frame.depth() + 1)));
            } else if (node.isNumber() && node.isFloatingPointNumber()
                    && !Double.isFinite(node.doubleValue())) {
                throw new IllegalArgumentException("JSON number must be finite");
            }
        }
    }

    private static void validateValue(Object root, int maxDepth) {
        Deque<ValueFrame> pending = new ArrayDeque<>();
        IdentityHashMap<Object, Boolean> active = new IdentityHashMap<>();
        pending.push(new ValueFrame(root, 0, false));
        while (!pending.isEmpty()) {
            ValueFrame frame = pending.pop();
            Object value = frame.value();
            if (frame.exiting()) {
                active.remove(value);
            } else if (value instanceof String text) {
                validateString(text);
            } else if (value instanceof Boolean || value == null) {
                continue;
            } else if (value instanceof BigInteger integer) {
                if (integer.abs().compareTo(MAX_SAFE_INTEGER) > 0) {
                    throw new IllegalArgumentException("Integer exceeds the safe range");
                }
            } else if (value instanceof Byte || value instanceof Short
                    || value instanceof Integer || value instanceof Long) {
                BigInteger integer = BigInteger.valueOf(((Number) value).longValue());
                if (integer.abs().compareTo(MAX_SAFE_INTEGER) > 0) {
                    throw new IllegalArgumentException("Integer exceeds the safe range");
                }
            } else if (value instanceof Double number) {
                if (!Double.isFinite(number)) {
                    throw new IllegalArgumentException("JSON number must be finite");
                }
            } else if (value instanceof Float) {
                throw new IllegalArgumentException("Use binary64 Double values for JSON numbers");
            } else if (value instanceof Map<?, ?> object) {
                enterContainer(value, frame.depth(), active, pending, maxDepth);
                for (Map.Entry<?, ?> entry : object.entrySet()) {
                    if (!(entry.getKey() instanceof String key)) {
                        throw new IllegalArgumentException("JSON object keys must be strings");
                    }
                    validateString(key);
                    pending.push(new ValueFrame(entry.getValue(), frame.depth() + 1, false));
                }
            } else if (value instanceof List<?> array) {
                enterContainer(value, frame.depth(), active, pending, maxDepth);
                for (Object element : array) {
                    pending.push(new ValueFrame(element, frame.depth() + 1, false));
                }
            } else {
                throw new IllegalArgumentException("Value is not in the supported JSON data model");
            }
        }
    }

    private static void enterContainer(
            Object value,
            int depth,
            IdentityHashMap<Object, Boolean> active,
            Deque<ValueFrame> pending,
            int maxDepth) {
        if (depth >= maxDepth) {
            throw new IllegalArgumentException("JSON nesting depth exceeds the limit");
        }
        if (active.put(value, Boolean.TRUE) != null) {
            throw new IllegalArgumentException("Cyclic values are not JSON serializable");
        }
        pending.push(new ValueFrame(value, depth, true));
    }

    private static void validateString(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 >= value.length()
                        || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    throw new IllegalArgumentException("JSON strings must contain valid Unicode");
                }
                index++;
            } else if (Character.isLowSurrogate(character)) {
                throw new IllegalArgumentException("JSON strings must contain valid Unicode");
            }
        }
    }

    private record TreeFrame(JsonNode node, int depth) {
    }

    private record ValueFrame(Object value, int depth, boolean exiting) {
    }
}
