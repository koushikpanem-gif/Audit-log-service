package com.auditlog.verifier;

import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.core.crypto.V1Hashes;
import com.fasterxml.jackson.databind.JsonNode;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Offline verifier for audit-export-bundle/v1 documents. It depends only on the core crypto
 * primitives, never on the service, repository or web layers.
 */
public final class BundleVerifier {

    public static final int DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
    public static final int DEFAULT_MAX_RECORDS = 100_000;
    public static final int MAX_VIOLATIONS = 100;

    private static final Set<String> BODY_FIELDS = Set.of(
            "format", "bundleId", "purpose", "ledgerId", "hashAlgorithm", "hashVersion",
            "genesisHash", "signatureAlgorithm", "exportedAt", "exportedBy", "selection",
            "completeness", "recordCount", "recordsDigest", "records", "headCheckpoint",
            "signer", "signature");
    private static final Set<String> RECORD_FIELDS = Set.of(
            "seq", "eventId", "eventType", "actorId", "resourceType", "resourceId",
            "occurredAt", "timestamp", "source", "hashVersion", "payloadCommitments",
            "disclosedLeaves", "contentHash", "prevHash", "chainHash");
    private static final Set<String> CHECKPOINT_FIELDS = Set.of(
            "seq", "chainHash", "createdAt", "keyId", "signature");
    private static final Set<String> PURPOSES = Set.of(
            "EXPORT", "RETENTION_ARCHIVE", "COMPLIANCE_REPORT");
    private static final long MAX_SAFE = 9_007_199_254_740_991L;

    private BundleVerifier() {
    }

    /** Thrown for unreadable or over-limit input, which maps to CLI exit code 2. */
    public static final class InputException extends RuntimeException {
        public InputException(String message, Throwable cause) {
            super(message, cause);
        }

        public InputException(String message) {
            super(message);
        }
    }

    public record Options(
            String pinnedPublicKeyBase64,
            boolean allowSelfAsserted,
            int maxBytes,
            int maxRecords) {

        public static Options pinned(String publicKeyBase64) {
            return new Options(publicKeyBase64, false, DEFAULT_MAX_BYTES, DEFAULT_MAX_RECORDS);
        }

        public static Options selfAsserted() {
            return new Options(null, true, DEFAULT_MAX_BYTES, DEFAULT_MAX_RECORDS);
        }

        public Options withLimits(int bytes, int records) {
            return new Options(pinnedPublicKeyBase64, allowSelfAsserted, bytes, records);
        }
    }

    public record Result(
            boolean verified,
            String trust,
            String keyId,
            String ledgerId,
            String bundleId,
            long recordCount,
            long undisclosedLeafCount,
            long totalViolationCount,
            boolean violationsTruncated,
            List<String> violations,
            List<String> notes) {
    }

    public static Result verify(byte[] input, Options options) {
        if (options == null) {
            throw new InputException("Verifier options are required");
        }
        boolean pinned = options.pinnedPublicKeyBase64() != null;
        if (!pinned && !options.allowSelfAsserted()) {
            throw new InputException(
                    "A pinned public key is required; self-asserted verification must be explicit");
        }
        if (pinned && options.allowSelfAsserted()) {
            throw new InputException("Pinned key and self-asserted mode are mutually exclusive");
        }
        if (options.maxBytes() < 1 || options.maxRecords() < 1) {
            throw new InputException("Verifier limits must be positive");
        }
        byte[] pinnedRaw = null;
        if (pinned) {
            pinnedRaw = decodeRawKey(options.pinnedPublicKeyBase64());
            if (pinnedRaw == null) {
                throw new InputException("Pinned public key must be canonical Base64 of 32 raw bytes");
            }
        }
        if (input == null || input.length == 0 || input.length > options.maxBytes()) {
            throw new InputException("Bundle input is empty or exceeds the byte limit");
        }
        JsonNode root;
        try {
            root = CanonicalJson.parse(input, CanonicalJson.MAX_DOCUMENT_DEPTH, options.maxBytes());
        } catch (IllegalArgumentException exception) {
            throw new InputException("Bundle is not strict, bounded JSON: " + exception.getMessage(), exception);
        }
        if (!root.isObject()) {
            throw new InputException("Bundle must be a JSON object");
        }
        Object parsed = toObject(root);
        return new Run(options, pinnedRaw).run(asMap(parsed));
    }

    private static final class Run {
        private final Options options;
        private final byte[] pinnedRaw;
        private final List<String> violations = new ArrayList<>();
        private final List<String> notes = new ArrayList<>();
        private long total;
        private long undisclosed;

        Run(Options options, byte[] pinnedRaw) {
            this.options = options;
            this.pinnedRaw = pinnedRaw;
        }

        private void fail(String code, String detail) {
            total++;
            if (violations.size() < MAX_VIOLATIONS) {
                violations.add(code + ": " + detail);
            }
        }

        Result run(Map<String, Object> bundle) {
            String trust = pinnedRaw != null ? "PINNED_KEY" : "UNTRUSTED_SELF_ASSERTED_KEY";
            if (pinnedRaw == null) {
                notes.add("Signer key was taken from the bundle itself; the origin is untrusted "
                        + "and only internal consistency was checked");
            }
            notes.add("Missing disclosed leaves are undisclosed or redacted; this bundle does not "
                    + "prove they were authorized");
            notes.add("Filtered selections carry no global inclusion proof; completeness is asserted "
                    + "by the signer");

            String keyId = null;
            String ledgerId = null;
            String bundleId = null;
            long recordCount = 0;
            if (!bundle.keySet().equals(BODY_FIELDS)) {
                fail("SCHEMA_INVALID", "bundle must have exactly the v1 fields");
                return result(trust, keyId, ledgerId, bundleId, recordCount);
            }
            ledgerId = text(bundle.get("ledgerId"));
            bundleId = text(bundle.get("bundleId"));
            expect("format", "audit-export-bundle/v1".equals(bundle.get("format")), "unsupported format");
            expect("hashAlgorithm", "SHA-256".equals(bundle.get("hashAlgorithm")), "unsupported hash algorithm");
            expect("signatureAlgorithm", "Ed25519".equals(bundle.get("signatureAlgorithm")),
                    "unsupported signature algorithm");
            expect("hashVersion", isInt(bundle.get("hashVersion"), 1), "unsupported hash version");
            expect("purpose", bundle.get("purpose") instanceof String p && PURPOSES.contains(p),
                    "unknown purpose");
            expect("bundleId", bundleId != null && !bundleId.isBlank(), "bundleId missing");
            expect("exportedAt", isText(bundle.get("exportedAt")), "exportedAt missing");
            expect("exportedBy", isText(bundle.get("exportedBy")), "exportedBy missing");
            expect("selection", bundle.get("selection") instanceof Map, "selection must be an object");
            expect("completeness", bundle.get("completeness") instanceof Map,
                    "completeness must be an object");

            if (ledgerId == null || ledgerId.isBlank()) {
                fail("SCHEMA_INVALID", "ledgerId missing");
            } else {
                String genesis = V1Hashes.genesisHash(ledgerId);
                if (!genesis.equals(bundle.get("genesisHash"))) {
                    fail("GENESIS_MISMATCH", "genesisHash does not match the ledgerId");
                }
            }

            byte[] signerRaw = null;
            if (bundle.get("signer") instanceof Map<?, ?> signer
                    && signer.keySet().equals(Set.of("keyId", "publicKey"))
                    && signer.get("publicKey") instanceof String publicKey
                    && signer.get("keyId") instanceof String declaredKeyId) {
                signerRaw = decodeRawKey(publicKey);
                keyId = declaredKeyId;
                if (signerRaw == null) {
                    fail("SIGNER_INVALID", "signer.publicKey must be canonical Base64 of 32 bytes");
                } else if (!CheckpointSigner.keyIdFor(signerRaw).equals(declaredKeyId)) {
                    fail("SIGNER_INVALID", "signer.keyId does not match the public key");
                }
            } else {
                fail("SCHEMA_INVALID", "signer must contain exactly keyId and publicKey");
            }

            byte[] verifyKey = signerRaw;
            if (pinnedRaw != null) {
                if (signerRaw == null || !MessageDigest.isEqual(pinnedRaw, signerRaw)) {
                    fail("KEY_NOT_PINNED", "bundle signer key differs from the pinned key");
                }
                verifyKey = pinnedRaw;
            }

            Map<String, Object> body = new LinkedHashMap<>(bundle);
            Object signature = body.remove("signature");
            if (verifyKey == null || !(signature instanceof String signatureText)) {
                fail("SIGNATURE_INVALID", "signature cannot be checked");
            } else {
                try {
                    byte[] canonical = CanonicalJson.canonicalize(
                            body, CanonicalJson.MAX_DOCUMENT_DEPTH, options.maxBytes());
                    if (!CheckpointSigner.verifyRaw(canonical, signatureText, verifyKey)) {
                        fail("SIGNATURE_INVALID", "bundle signature does not verify");
                    }
                } catch (IllegalArgumentException exception) {
                    fail("SIGNATURE_INVALID", "bundle cannot be canonicalized");
                }
            }

            if (!(bundle.get("records") instanceof List<?> records)) {
                fail("SCHEMA_INVALID", "records must be an array");
                return result(trust, keyId, ledgerId, bundleId, recordCount);
            }
            recordCount = records.size();
            if (records.size() > options.maxRecords()) {
                throw new InputException("Bundle exceeds the verifier record limit");
            }
            if (!(bundle.get("recordCount") instanceof Number count)
                    || count.longValue() != records.size() || !isSafe(count)) {
                fail("RECORD_COUNT_MISMATCH", "recordCount does not match the records array");
            }
            try {
                String digest = sha256Hex(CanonicalJson.canonicalize(
                        records, CanonicalJson.MAX_DOCUMENT_DEPTH, options.maxBytes()));
                if (!digest.equals(bundle.get("recordsDigest"))) {
                    fail("RECORDS_DIGEST_MISMATCH", "recordsDigest does not match the records");
                }
            } catch (IllegalArgumentException exception) {
                fail("RECORDS_DIGEST_MISMATCH", "records cannot be canonicalized");
            }

            verifyRecords(records, ledgerId);
            verifyHead(bundle, records, ledgerId, verifyKey, keyId);
            return result(trust, keyId, ledgerId, bundleId, recordCount);
        }

        private void verifyRecords(List<?> records, String ledgerId) {
            long previousSeq = 0;
            String previousChain = null;
            for (Object item : records) {
                if (!(item instanceof Map<?, ?> raw) || !raw.keySet().equals(RECORD_FIELDS)) {
                    fail("MALFORMED_RECORD", "record must have exactly the v1 fields");
                    previousSeq = 0;
                    previousChain = null;
                    continue;
                }
                @SuppressWarnings("unchecked")
                Map<String, Object> record = (Map<String, Object>) raw;
                Object seqValue = record.get("seq");
                if (!(seqValue instanceof Number number) || !isSafe(number) || number.longValue() < 1) {
                    fail("MALFORMED_RECORD", "seq must be a positive safe integer");
                    previousSeq = 0;
                    previousChain = null;
                    continue;
                }
                long seq = number.longValue();
                String label = "seq " + seq;
                if (previousSeq != 0 && seq <= previousSeq) {
                    fail("ORDER_INVALID", label + " is not strictly increasing");
                }
                boolean wellFormed = recordShapeValid(record, label);
                if (wellFormed && ledgerId != null) {
                    verifyHashes(record, label);
                    String prevHash = (String) record.get("prevHash");
                    if (seq == 1 && !prevHash.equals(V1Hashes.genesisHash(ledgerId))) {
                        fail("GENESIS_MISMATCH", label + " prevHash is not the genesis hash");
                    }
                    if (previousChain != null && seq == previousSeq + 1 && !prevHash.equals(previousChain)) {
                        fail("CHAIN_LINK_BROKEN", label + " prevHash does not match the predecessor");
                    }
                    previousChain = (String) record.get("chainHash");
                } else {
                    previousChain = null;
                }
                previousSeq = seq;
            }
        }

        private boolean recordShapeValid(Map<String, Object> record, String label) {
            boolean ok = true;
            for (String field : List.of("eventId", "eventType", "actorId", "resourceType",
                    "resourceId", "timestamp", "source")) {
                if (!isText(record.get(field))) {
                    fail("MALFORMED_RECORD", label + " " + field + " must be a non-empty string");
                    ok = false;
                }
            }
            if (record.get("occurredAt") != null && !isText(record.get("occurredAt"))) {
                fail("MALFORMED_RECORD", label + " occurredAt must be null or a string");
                ok = false;
            }
            if (!isInt(record.get("hashVersion"), 1)) {
                fail("MALFORMED_RECORD", label + " has an unsupported hashVersion");
                ok = false;
            }
            for (String field : List.of("contentHash", "prevHash", "chainHash")) {
                if (!isHash(record.get(field))) {
                    fail("MALFORMED_RECORD", label + " " + field + " must be 64 lowercase hex");
                    ok = false;
                }
            }
            if (!(record.get("payloadCommitments") instanceof Map)) {
                fail("MALFORMED_RECORD", label + " payloadCommitments must be an object");
                ok = false;
            }
            if (!(record.get("disclosedLeaves") instanceof Map)) {
                fail("MALFORMED_RECORD", label + " disclosedLeaves must be an object");
                ok = false;
            }
            return ok;
        }

        @SuppressWarnings("unchecked")
        private void verifyHashes(Map<String, Object> record, String label) {
            Map<String, Object> commitments = (Map<String, Object>) record.get("payloadCommitments");
            Map<String, String> expectedLeaves = new TreeMap<>();
            if (!collectLeaves(commitments, "", expectedLeaves)) {
                fail("MALFORMED_RECORD", label + " payloadCommitments contain a non-commitment scalar");
                return;
            }
            Map<String, Object> disclosed = (Map<String, Object>) record.get("disclosedLeaves");
            for (Map.Entry<String, Object> entry : disclosed.entrySet()) {
                String commitment = expectedLeaves.get(entry.getKey());
                if (commitment == null) {
                    fail("LEAF_POINTER_UNKNOWN", label + " discloses a pointer absent from the commitments");
                    continue;
                }
                if (!(entry.getValue() instanceof Map<?, ?> leaf)
                        || !leaf.keySet().equals(Set.of("salt", "value"))
                        || !(leaf.get("salt") instanceof String saltHex)
                        || !saltHex.matches("[0-9a-f]{64}")
                        || leaf.get("value") instanceof Map || leaf.get("value") instanceof List) {
                    fail("MALFORMED_RECORD", label + " has a malformed disclosed leaf");
                    continue;
                }
                try {
                    String hash = V1Hashes.leafHash(
                            HexFormat.of().parseHex(saltHex), entry.getKey(), leaf.get("value"));
                    if (!hash.equals(commitment)) {
                        fail("LEAF_COMMITMENT_MISMATCH", label + " disclosed leaf does not match its commitment");
                    }
                } catch (IllegalArgumentException exception) {
                    fail("MALFORMED_RECORD", label + " has an unhashable disclosed leaf");
                }
            }
            undisclosed += expectedLeaves.size() - disclosed.keySet().stream()
                    .filter(expectedLeaves::containsKey).count();
            try {
                String contentHash = V1Hashes.contentHash(V1Hashes.contentObject(
                        ((Number) record.get("seq")).longValue(),
                        (String) record.get("eventId"),
                        (String) record.get("eventType"),
                        (String) record.get("actorId"),
                        (String) record.get("resourceType"),
                        (String) record.get("resourceId"),
                        (String) record.get("occurredAt"),
                        (String) record.get("timestamp"),
                        (String) record.get("source"),
                        commitments));
                if (!contentHash.equals(record.get("contentHash"))) {
                    fail("CONTENT_HASH_MISMATCH", label + " contentHash does not match the record fields");
                }
                String chain = V1Hashes.chainHash(
                        (String) record.get("prevHash"), (String) record.get("contentHash"));
                if (!chain.equals(record.get("chainHash"))) {
                    fail("CHAIN_HASH_MISMATCH", label + " chainHash does not match prevHash and contentHash");
                }
            } catch (IllegalArgumentException exception) {
                fail("MALFORMED_RECORD", label + " cannot be hashed");
            }
        }

        private void verifyHead(
                Map<String, Object> bundle, List<?> records, String ledgerId, byte[] verifyKey,
                String signerKeyId) {
            if (!(bundle.get("headCheckpoint") instanceof Map<?, ?> head)
                    || !head.keySet().equals(CHECKPOINT_FIELDS)
                    || !(head.get("seq") instanceof Number headSeqNumber)
                    || !isSafe(headSeqNumber) || headSeqNumber.longValue() < 1
                    || !isHash(head.get("chainHash"))) {
                fail("HEAD_CHECKPOINT_INVALID", "headCheckpoint must have the exact v1 fields");
                return;
            }
            long headSeq = headSeqNumber.longValue();
            if (verifyKey != null && ledgerId != null && signerKeyId != null) {
                Map<String, Object> checkpoint = new LinkedHashMap<>();
                checkpoint.put("type", "audit-checkpoint/v1");
                checkpoint.put("ledgerId", ledgerId);
                checkpoint.put("seq", headSeq);
                checkpoint.put("chainHash", head.get("chainHash"));
                checkpoint.put("createdAt", head.get("createdAt"));
                checkpoint.put("keyId", head.get("keyId"));
                checkpoint.put("signature", head.get("signature"));
                try {
                    if (!signerKeyId.equals(head.get("keyId"))
                            || !CheckpointSigner.verifyCheckpoint(
                                    checkpoint, Base64.getEncoder().encodeToString(verifyKey))) {
                        fail("HEAD_CHECKPOINT_INVALID", "headCheckpoint signature does not verify");
                    }
                } catch (IllegalArgumentException exception) {
                    fail("HEAD_CHECKPOINT_INVALID", "headCheckpoint is malformed");
                }
            }
            for (Object item : records) {
                if (item instanceof Map<?, ?> record && record.get("seq") instanceof Number number
                        && isSafe(number)) {
                    if (number.longValue() > headSeq) {
                        fail("RECORD_AFTER_HEAD", "seq " + number.longValue() + " is newer than the head checkpoint");
                    } else if (number.longValue() == headSeq
                            && !head.get("chainHash").equals(record.get("chainHash"))) {
                        fail("HEAD_MISMATCH", "record at the head seq differs from the head checkpoint");
                    }
                }
            }
        }

        private void expect(String field, boolean condition, String detail) {
            if (!condition) {
                fail("SCHEMA_INVALID", field + ": " + detail);
            }
        }

        private Result result(String trust, String keyId, String ledgerId, String bundleId, long count) {
            return new Result(total == 0, trust, keyId, ledgerId, bundleId, count, undisclosed,
                    total, total > violations.size(), List.copyOf(violations), List.copyOf(notes));
        }
    }

    /** Collects JSON-pointer -> commitment string for every scalar position; false if not 64-hex. */
    private static boolean collectLeaves(Object node, String pointer, Map<String, String> out) {
        if (node instanceof Map<?, ?> object) {
            for (Map.Entry<?, ?> entry : object.entrySet()) {
                String key = ((String) entry.getKey()).replace("~", "~0").replace("/", "~1");
                if (!collectLeaves(entry.getValue(), pointer + "/" + key, out)) {
                    return false;
                }
            }
            return true;
        }
        if (node instanceof List<?> array) {
            for (int index = 0; index < array.size(); index++) {
                if (!collectLeaves(array.get(index), pointer + "/" + index, out)) {
                    return false;
                }
            }
            return true;
        }
        if (isHash(node)) {
            out.put(pointer, (String) node);
            return true;
        }
        return false;
    }

    private static byte[] decodeRawKey(String base64) {
        try {
            byte[] raw = Base64.getDecoder().decode(base64);
            if (raw.length != 32 || !Base64.getEncoder().encodeToString(raw).equals(base64)) {
                return null;
            }
            return raw;
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private static boolean isHash(Object value) {
        return value instanceof String text && text.matches("[0-9a-f]{64}");
    }

    private static boolean isText(Object value) {
        return value instanceof String text && !text.isEmpty();
    }

    private static String text(Object value) {
        return value instanceof String text ? text : null;
    }

    private static boolean isInt(Object value, long expected) {
        return value instanceof Number number && !(number instanceof Double)
                && number.longValue() == expected;
    }

    private static boolean isSafe(Number number) {
        if (number instanceof Double || number instanceof Float) {
            return false;
        }
        return Math.abs(number.longValue()) <= MAX_SAFE;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return (Map<String, Object>) value;
    }

    private static Object toObject(JsonNode node) {
        if (node.isObject()) {
            Map<String, Object> map = new LinkedHashMap<>();
            node.properties().forEach(entry -> map.put(entry.getKey(), toObject(entry.getValue())));
            return map;
        }
        if (node.isArray()) {
            List<Object> list = new ArrayList<>(node.size());
            node.elements().forEachRemaining(child -> list.add(toObject(child)));
            return list;
        }
        if (node.isTextual()) {
            return node.textValue();
        }
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        if (node.isNull()) {
            return null;
        }
        if (node.isIntegralNumber()) {
            return node.bigIntegerValue().longValueExact();
        }
        return node.doubleValue();
    }

    private static String sha256Hex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
