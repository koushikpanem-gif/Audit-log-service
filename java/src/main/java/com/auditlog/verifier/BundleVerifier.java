package com.auditlog.verifier;

import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.core.crypto.V1Hashes;
import com.auditlog.domain.BundleCompleteness;
import com.auditlog.domain.BundleDiagnostic;
import com.auditlog.domain.BundleDiagnosticCode;
import com.auditlog.domain.BundlePurpose;
import com.auditlog.domain.BundleSelection;
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
import java.util.regex.Pattern;

/**
 * Offline verifier for audit-export-bundle/v1 documents. It depends only on core crypto and the
 * domain DTOs, never on Spring, the repository or private keys.
 *
 * <p>A valid result proves internal consistency and (with a pinned key) the signer's identity. It
 * does not prove that the source ledger was intact, that omitted matching records do not exist, or
 * that undisclosed leaves were authorized to be removed.
 */
public final class BundleVerifier {

    public static final int DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
    public static final int DEFAULT_MAX_RECORDS = 100_000;
    public static final int MAX_LEAVES_PER_RECORD = 500;
    public static final int MAX_DIAGNOSTICS = 100;

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
    private static final Pattern HASH = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern KEY_ID = Pattern.compile("[0-9a-f]{16}");
    private static final Pattern SIGNATURE = Pattern.compile("[A-Za-z0-9+/]{86}==");
    private static final long MAX_SAFE = BundleSelection.MAX_SAFE;

    private BundleVerifier() {
    }

    /** Thrown for unusable arguments or unreadable input, which maps to CLI exit code 2. */
    public static final class InputException extends RuntimeException {
        public InputException(String message, Throwable cause) {
            super(message, cause);
        }

        public InputException(String message) {
            super(message);
        }
    }

    public enum Status { VERIFIED, INTEGRITY_VALID_ORIGIN_UNTRUSTED, INVALID }

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

        /** No pinned key and no explicit opt-in: verification must fail with TRUSTED_KEY_REQUIRED. */
        public static Options unconfigured() {
            return new Options(null, false, DEFAULT_MAX_BYTES, DEFAULT_MAX_RECORDS);
        }

        public Options withLimits(int bytes, int records) {
            return new Options(pinnedPublicKeyBase64, allowSelfAsserted, bytes, records);
        }
    }

    public record Result(
            Status status,
            boolean originTrusted,
            String ledgerId,
            String bundleId,
            String keyId,
            long recordCount,
            long undisclosedLeafCount,
            List<BundleDiagnostic> diagnostics,
            long totalDiagnosticCount,
            boolean diagnosticsTruncated,
            List<String> notices) {

        public boolean valid() {
            return status != Status.INVALID;
        }
    }

    public static Result verify(byte[] input, Options options) {
        if (options == null) {
            throw new InputException("Verifier options are required");
        }
        if (options.pinnedPublicKeyBase64() != null && options.allowSelfAsserted()) {
            throw new InputException("Pinned key and self-asserted mode are mutually exclusive");
        }
        if (options.maxBytes() < 1 || options.maxRecords() < 1) {
            throw new InputException("Verifier limits must be positive");
        }
        byte[] pinnedRaw = null;
        if (options.pinnedPublicKeyBase64() != null) {
            pinnedRaw = decodeRawKey(options.pinnedPublicKeyBase64());
            if (pinnedRaw == null) {
                throw new InputException("Pinned public key must be canonical Base64 of 32 raw bytes");
            }
        }
        return new Run(options, pinnedRaw).execute(input);
    }

    private static final class Run {
        private final Options options;
        private final byte[] pinnedRaw;
        private final List<BundleDiagnostic> diagnostics = new ArrayList<>();
        private final List<String> notices = new ArrayList<>();
        private long total;
        private long undisclosed;
        private String ledgerId;
        private String bundleId;
        private String keyId;
        private long recordCount;

        Run(Options options, byte[] pinnedRaw) {
            this.options = options;
            this.pinnedRaw = pinnedRaw;
        }

        private void fail(BundleDiagnosticCode code, Long seq, String pointer, String message) {
            total++;
            if (diagnostics.size() < MAX_DIAGNOSTICS) {
                diagnostics.add(new BundleDiagnostic(code, seq, pointer, message));
            }
        }

        private void schema(String pointer, String message) {
            fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, null, pointer, message);
        }

        Result execute(byte[] input) {
            boolean pinned = pinnedRaw != null;
            notices.add("A valid result does not prove the source ledger was intact at export time, "
                    + "that omitted matching records do not exist, or that undisclosed leaves were "
                    + "authorized to be removed");
            if (!pinned && !options.allowSelfAsserted()) {
                fail(BundleDiagnosticCode.TRUSTED_KEY_REQUIRED, null, null,
                        "A pinned public key obtained out of band is required; self-asserted "
                                + "verification must be requested explicitly");
                return result();
            }
            if (!pinned) {
                notices.add("UNTRUSTED ORIGIN: the signer key was taken from the bundle itself, so only "
                        + "internal consistency was checked and the bundle's origin is NOT established");
            }
            if (input == null || input.length == 0) {
                schema(null, "Bundle input is empty");
                return result();
            }
            if (input.length > options.maxBytes()) {
                fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, null,
                        "Bundle input exceeds the configured byte limit");
                return result();
            }
            Map<String, Object> bundle = parse(input);
            if (bundle == null) {
                return result();
            }
            if (!structure(bundle)) {
                return result();
            }
            checkTrustAndSignature(bundle);
            checkGenesis(bundle);
            List<?> records = (List<?>) bundle.get("records");
            recordCount = records.size();
            BundleSelection selection = BundleSelection.fromMap(asMap(bundle.get("selection")));
            long throughSeq = BundleCompleteness.fromMap(asMap(bundle.get("completeness"))).throughSeq();
            Map<String, Object> head = asMap(bundle.get("headCheckpoint"));
            checkCheckpoint(bundle, head);
            checkCountAndDigest(bundle, records);
            checkHeadAndCompleteness(head, throughSeq);
            checkRecords(records, selection, throughSeq, ((Number) head.get("seq")).longValue(),
                    head.get("chainHash").toString());
            return result();
        }

        private Map<String, Object> parse(byte[] input) {
            JsonNode root;
            try {
                root = CanonicalJson.parse(input, CanonicalJson.MAX_DOCUMENT_DEPTH, options.maxBytes());
            } catch (IllegalArgumentException exception) {
                String detail = String.valueOf(exception.getMessage()) + " "
                        + (exception.getCause() == null ? "" : exception.getCause().getMessage());
                if (detail.toLowerCase(java.util.Locale.ROOT).contains("depth")) {
                    fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, null,
                            "JSON nesting depth exceeds the verifier limit");
                } else {
                    schema(null, "Input is not strict JSON (duplicate keys, unsafe integers, invalid "
                            + "Unicode or malformed syntax)");
                }
                return null;
            }
            if (!root.isObject()) {
                schema(null, "Bundle must be a JSON object");
                return null;
            }
            return asMap(toObject(root));
        }

        /** Validates top-level shape; false means dependent checks must not run. */
        private boolean structure(Map<String, Object> bundle) {
            Object format = bundle.get("format");
            if (format instanceof String text && !text.equals("audit-export-bundle/v1")) {
                fail(BundleDiagnosticCode.UNSUPPORTED_FORMAT, null, "/format",
                        "Unsupported bundle format");
                return false;
            }
            if (!bundle.keySet().equals(BODY_FIELDS)) {
                schema(null, "Bundle must have exactly the v1 fields (" + bundle.size()
                        + " present, " + BODY_FIELDS.size() + " required)");
                return false;
            }
            boolean ok = true;
            if (!"audit-export-bundle/v1".equals(format)) {
                schema("/format", "format must be a string");
                ok = false;
            }
            ledgerId = text(bundle.get("ledgerId"));
            bundleId = text(bundle.get("bundleId"));
            ok &= nonEmpty(bundle, "bundleId");
            ok &= nonEmpty(bundle, "ledgerId");
            ok &= nonEmpty(bundle, "exportedBy");
            ok &= timestamp(bundle, "exportedAt");
            ok &= algorithm(bundle, "hashAlgorithm", "SHA-256");
            ok &= algorithm(bundle, "signatureAlgorithm", "Ed25519");
            Object hashVersion = bundle.get("hashVersion");
            if (!(hashVersion instanceof Long)) {
                schema("/hashVersion", "hashVersion must be an integer");
                ok = false;
            } else if ((Long) hashVersion != 1L) {
                fail(BundleDiagnosticCode.UNSUPPORTED_ALGORITHM, null, "/hashVersion",
                        "Unsupported hash version");
                ok = false;
            }
            ok &= hash(bundle, "genesisHash");
            ok &= hash(bundle, "recordsDigest");
            BundlePurpose purpose = BundlePurpose.parse(bundle.get("purpose"));
            if (purpose == null) {
                schema("/purpose", "purpose is not one of the v1 purposes");
                ok = false;
            }
            BundleSelection selection = null;
            if (bundle.get("selection") instanceof Map<?, ?> selectionMap) {
                try {
                    selection = BundleSelection.fromMap(selectionMap);
                } catch (IllegalArgumentException exception) {
                    schema("/selection", exception.getMessage());
                    ok = false;
                }
            } else {
                schema("/selection", "selection must be an object");
                ok = false;
            }
            if (selection != null && purpose != null) {
                ok &= purposeRules(purpose, selection);
            }
            if (bundle.get("completeness") instanceof Map<?, ?> completeness) {
                try {
                    BundleCompleteness.fromMap(completeness);
                } catch (IllegalArgumentException exception) {
                    schema("/completeness", exception.getMessage());
                    ok = false;
                }
            } else {
                schema("/completeness", "completeness must be an object");
                ok = false;
            }
            Object count = bundle.get("recordCount");
            if (!(count instanceof Long number) || number < 0 || number > MAX_SAFE) {
                schema("/recordCount", "recordCount must be a safe nonnegative integer");
                ok = false;
            }
            if (!(bundle.get("records") instanceof List<?> records)) {
                schema("/records", "records must be an array");
                ok = false;
            } else if (records.size() > options.maxRecords()) {
                fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, "/records",
                        "records exceeds the verifier record limit");
                ok = false;
            }
            ok &= checkpointShape(bundle.get("headCheckpoint"));
            ok &= signerShape(bundle.get("signer"));
            Object signature = bundle.get("signature");
            if (!(signature instanceof String text && SIGNATURE.matcher(text).matches()
                    && base64Length(text) == 64)) {
                schema("/signature", "signature must be canonical Base64 of 64 bytes");
                ok = false;
            }
            return ok;
        }

        private boolean purposeRules(BundlePurpose purpose, BundleSelection selection) {
            boolean ok = true;
            if (purpose == BundlePurpose.EXPORT
                    && (selection.seqFrom() != null || selection.seqTo() != null
                            || (selection.actorId() == null && selection.resourceId() == null))) {
                schema("/selection", "an EXPORT selection needs actorId or resourceId and no sequence bounds");
                ok = false;
            }
            if (purpose == BundlePurpose.RETENTION_ARCHIVE
                    && (selection.hasOrdinaryFilters()
                            || selection.seqFrom() == null || selection.seqTo() == null)) {
                schema("/selection", "a RETENTION_ARCHIVE selection uses sequence bounds and no ordinary filters");
                ok = false;
            }
            return ok;
        }

        private boolean checkpointShape(Object value) {
            if (!(value instanceof Map<?, ?> head) || !head.keySet().equals(CHECKPOINT_FIELDS)) {
                schema("/headCheckpoint", "headCheckpoint must have exactly the v1 fields");
                return false;
            }
            boolean ok = true;
            if (!(head.get("seq") instanceof Long seq) || seq < 1 || seq > MAX_SAFE) {
                schema("/headCheckpoint/seq", "seq must be a safe positive integer");
                ok = false;
            }
            if (!isHash(head.get("chainHash"))) {
                schema("/headCheckpoint/chainHash", "chainHash must be 64 lowercase hex");
                ok = false;
            }
            if (!(head.get("createdAt") instanceof String created)
                    || !BundleSelection.isCanonicalTimestamp(created)) {
                schema("/headCheckpoint/createdAt", "createdAt must be a UTC microsecond timestamp");
                ok = false;
            }
            if (!(head.get("keyId") instanceof String id && KEY_ID.matcher(id).matches())) {
                schema("/headCheckpoint/keyId", "keyId must be 16 lowercase hex");
                ok = false;
            }
            if (!(head.get("signature") instanceof String sig && SIGNATURE.matcher(sig).matches()
                    && base64Length(sig) == 64)) {
                schema("/headCheckpoint/signature", "signature must be canonical Base64 of 64 bytes");
                ok = false;
            }
            return ok;
        }

        private boolean signerShape(Object value) {
            if (!(value instanceof Map<?, ?> signer) || !signer.keySet().equals(Set.of("keyId", "publicKey"))) {
                schema("/signer", "signer must contain exactly keyId and publicKey");
                return false;
            }
            boolean ok = true;
            if (!(signer.get("keyId") instanceof String id && KEY_ID.matcher(id).matches())) {
                schema("/signer/keyId", "keyId must be 16 lowercase hex");
                ok = false;
            } else {
                keyId = id;
            }
            if (!(signer.get("publicKey") instanceof String key) || decodeRawKey(key) == null) {
                schema("/signer/publicKey", "publicKey must be canonical Base64 of 32 raw bytes");
                ok = false;
            }
            return ok;
        }

        private void checkTrustAndSignature(Map<String, Object> bundle) {
            Map<String, Object> signer = asMap(bundle.get("signer"));
            byte[] signerRaw = decodeRawKey((String) signer.get("publicKey"));
            boolean keyUsable = true;
            if (!CheckpointSigner.keyIdFor(signerRaw).equals(signer.get("keyId"))) {
                fail(BundleDiagnosticCode.KEY_ID_MISMATCH, null, "/signer/keyId",
                        "signer.keyId does not match the public key");
                keyUsable = false;
            }
            if (pinnedRaw != null && !MessageDigest.isEqual(pinnedRaw, signerRaw)) {
                fail(BundleDiagnosticCode.SIGNER_KEY_MISMATCH, null, "/signer/publicKey",
                        "The bundle signer key differs from the pinned key");
                keyUsable = false;
            }
            effectiveKey = keyUsable ? signerRaw : null;
            if (effectiveKey == null) {
                return;
            }
            Map<String, Object> body = new LinkedHashMap<>(bundle);
            String signature = (String) body.remove("signature");
            try {
                byte[] canonical = CanonicalJson.canonicalize(
                        body, CanonicalJson.MAX_DOCUMENT_DEPTH, options.maxBytes());
                if (!CheckpointSigner.verifyRaw(canonical, signature, effectiveKey)) {
                    fail(BundleDiagnosticCode.BUNDLE_SIGNATURE_INVALID, null, "/signature",
                            "The bundle signature does not verify");
                }
            } catch (IllegalArgumentException exception) {
                fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, null,
                        "The bundle body cannot be canonicalized within the verifier limits");
            }
        }

        private byte[] effectiveKey;

        private void checkGenesis(Map<String, Object> bundle) {
            if (!V1Hashes.genesisHash(ledgerId).equals(bundle.get("genesisHash"))) {
                fail(BundleDiagnosticCode.GENESIS_MISMATCH, null, "/genesisHash",
                        "genesisHash does not match the ledgerId");
            }
        }

        private void checkCheckpoint(Map<String, Object> bundle, Map<String, Object> head) {
            if (!head.get("keyId").equals(keyId)) {
                fail(BundleDiagnosticCode.KEY_ID_MISMATCH, null, "/headCheckpoint/keyId",
                        "headCheckpoint.keyId differs from signer.keyId");
                return;
            }
            if (effectiveKey == null) {
                return;
            }
            Map<String, Object> message = new LinkedHashMap<>();
            message.put("type", "audit-checkpoint/v1");
            message.put("ledgerId", ledgerId);
            message.put("seq", head.get("seq"));
            message.put("chainHash", head.get("chainHash"));
            message.put("createdAt", head.get("createdAt"));
            message.put("keyId", head.get("keyId"));
            message.put("signature", head.get("signature"));
            try {
                if (!CheckpointSigner.verifyCheckpoint(
                        message, Base64.getEncoder().encodeToString(effectiveKey))) {
                    fail(BundleDiagnosticCode.CHECKPOINT_SIGNATURE_INVALID, null, "/headCheckpoint/signature",
                            "The head checkpoint signature does not verify");
                }
            } catch (IllegalArgumentException exception) {
                fail(BundleDiagnosticCode.CHECKPOINT_SIGNATURE_INVALID, null, "/headCheckpoint",
                        "The head checkpoint cannot be verified");
            }
        }

        private void checkCountAndDigest(Map<String, Object> bundle, List<?> records) {
            if (((Number) bundle.get("recordCount")).longValue() != records.size()) {
                fail(BundleDiagnosticCode.RECORD_COUNT_MISMATCH, null, "/recordCount",
                        "recordCount does not match the number of records");
            }
            try {
                String digest = sha256Hex(CanonicalJson.canonicalize(
                        records, CanonicalJson.MAX_DOCUMENT_DEPTH, options.maxBytes()));
                if (!digest.equals(bundle.get("recordsDigest"))) {
                    fail(BundleDiagnosticCode.RECORDS_DIGEST_MISMATCH, null, "/recordsDigest",
                            "recordsDigest does not match the records");
                }
            } catch (IllegalArgumentException exception) {
                fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, null, "/records",
                        "records cannot be canonicalized within the verifier limits");
            }
        }

        private void checkHeadAndCompleteness(Map<String, Object> head, long throughSeq) {
            if (((Number) head.get("seq")).longValue() < throughSeq) {
                fail(BundleDiagnosticCode.CHECKPOINT_MISMATCH, null, "/headCheckpoint/seq",
                        "headCheckpoint.seq is below completeness.throughSeq");
            }
        }

        private void checkRecords(
                List<?> records, BundleSelection selection, long throughSeq, long headSeq,
                String headHash) {
            long previousSeq = 0;
            String previousChain = null;
            for (int index = 0; index < records.size(); index++) {
                String pointer = "/records/" + index;
                Map<String, Object> record = recordShape(records.get(index), pointer);
                if (record == null) {
                    previousSeq = 0;
                    previousChain = null;
                    continue;
                }
                long seq = (Long) record.get("seq");
                if (previousSeq != 0 && seq <= previousSeq) {
                    fail(BundleDiagnosticCode.RECORD_ORDER_INVALID, seq, pointer,
                            "Record sequence numbers must be strictly increasing");
                }
                if (seq > throughSeq || seq > headSeq) {
                    fail(BundleDiagnosticCode.RECORD_OUT_OF_RANGE, seq, pointer,
                            "Record is newer than completeness.throughSeq or the head checkpoint");
                }
                if (seq == headSeq && !headHash.equals(record.get("chainHash"))) {
                    fail(BundleDiagnosticCode.CHECKPOINT_MISMATCH, seq, pointer,
                            "The record at the head sequence differs from the head checkpoint");
                }
                if (!selection.matches(seq, (String) record.get("actorId"),
                        (String) record.get("resourceType"), (String) record.get("resourceId"),
                        (String) record.get("eventType"), (String) record.get("timestamp"))) {
                    fail(BundleDiagnosticCode.SELECTION_MISMATCH, seq, pointer,
                            "Record does not satisfy the bundle selection");
                }
                boolean hashable = verifyLeavesAndHashes(record, seq, pointer);
                String prevHash = (String) record.get("prevHash");
                if (seq == 1 && !prevHash.equals(V1Hashes.genesisHash(ledgerId))) {
                    fail(BundleDiagnosticCode.GENESIS_MISMATCH, seq, pointer + "/prevHash",
                            "Sequence 1 does not start from the genesis hash");
                }
                if (previousChain != null && seq == previousSeq + 1 && !prevHash.equals(previousChain)) {
                    fail(BundleDiagnosticCode.CHAIN_LINK_BROKEN, seq, pointer + "/prevHash",
                            "prevHash does not match the adjacent predecessor's chainHash");
                }
                previousChain = hashable ? (String) record.get("chainHash") : null;
                previousSeq = seq;
            }
        }

        /** Returns the record when it has the exact v1 shape, otherwise reports and returns null. */
        private Map<String, Object> recordShape(Object item, String pointer) {
            if (!(item instanceof Map<?, ?> raw) || !raw.keySet().equals(RECORD_FIELDS)) {
                schema(pointer, "Record must have exactly the v1 fields");
                return null;
            }
            Map<String, Object> record = asMap(raw);
            Long seq = record.get("seq") instanceof Long value && value >= 1 && value <= MAX_SAFE
                    ? value : null;
            if (seq == null) {
                schema(pointer + "/seq", "seq must be a safe positive integer");
                return null;
            }
            boolean ok = true;
            for (String field : List.of("eventId", "eventType", "actorId", "resourceType",
                    "resourceId", "source")) {
                if (!(record.get(field) instanceof String text) || text.isEmpty()) {
                    fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, pointer + "/" + field,
                            "Field must be a non-empty string");
                    ok = false;
                }
            }
            if (!(record.get("timestamp") instanceof String ts) || !BundleSelection.isCanonicalTimestamp(ts)) {
                fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, pointer + "/timestamp",
                        "timestamp must be a UTC microsecond timestamp");
                ok = false;
            }
            if (record.get("occurredAt") != null && !(record.get("occurredAt") instanceof String occurred
                    && BundleSelection.isCanonicalTimestamp(occurred))) {
                fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, pointer + "/occurredAt",
                        "occurredAt must be null or a UTC microsecond timestamp");
                ok = false;
            }
            if (!(record.get("hashVersion") instanceof Long version)) {
                fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, pointer + "/hashVersion",
                        "hashVersion must be an integer");
                ok = false;
            } else if (version != 1L) {
                fail(BundleDiagnosticCode.UNSUPPORTED_ALGORITHM, seq, pointer + "/hashVersion",
                        "Unsupported record hash version");
                ok = false;
            }
            for (String field : List.of("contentHash", "prevHash", "chainHash")) {
                if (!isHash(record.get(field))) {
                    fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, pointer + "/" + field,
                            "Hash must be 64 lowercase hex");
                    ok = false;
                }
            }
            if (!(record.get("payloadCommitments") instanceof Map)) {
                fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, pointer + "/payloadCommitments",
                        "payloadCommitments must be an object");
                ok = false;
            }
            if (!(record.get("disclosedLeaves") instanceof Map)) {
                fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, pointer + "/disclosedLeaves",
                        "disclosedLeaves must be an object");
                ok = false;
            }
            return ok ? record : null;
        }

        private boolean verifyLeavesAndHashes(Map<String, Object> record, long seq, String pointer) {
            Map<String, Object> commitments = asMap(record.get("payloadCommitments"));
            Map<String, String> expected = new TreeMap<>();
            if (!collectLeaves(commitments, "", expected, MAX_LEAVES_PER_RECORD)) {
                if (expected.size() > MAX_LEAVES_PER_RECORD) {
                    fail(BundleDiagnosticCode.RESOURCE_LIMIT_EXCEEDED, seq, pointer + "/payloadCommitments",
                            "Record exceeds the per-record leaf limit");
                } else {
                    fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, pointer + "/payloadCommitments",
                            "payloadCommitments must contain only 64-hex commitment strings");
                }
                return false;
            }
            Map<String, Object> disclosed = asMap(record.get("disclosedLeaves"));
            boolean wellFormed = true;
            long matched = 0;
            for (Map.Entry<String, Object> entry : disclosed.entrySet()) {
                String commitment = expected.get(entry.getKey());
                if (commitment == null) {
                    fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, entry.getKey(),
                            "A disclosed leaf has no matching commitment position");
                    wellFormed = false;
                    continue;
                }
                matched++;
                if (!(entry.getValue() instanceof Map<?, ?> leaf)
                        || !leaf.keySet().equals(Set.of("salt", "value"))
                        || !(leaf.get("salt") instanceof String saltHex)
                        || !HASH.matcher(saltHex).matches()
                        || leaf.get("value") instanceof Map || leaf.get("value") instanceof List) {
                    fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, entry.getKey(),
                            "A disclosed leaf must be {salt: 64 hex, value: scalar}");
                    wellFormed = false;
                    continue;
                }
                try {
                    String hash = V1Hashes.leafHash(
                            HexFormat.of().parseHex(saltHex), entry.getKey(), leaf.get("value"));
                    if (!hash.equals(commitment)) {
                        fail(BundleDiagnosticCode.LEAF_COMMITMENT_MISMATCH, seq, entry.getKey(),
                                "A disclosed leaf does not match its commitment");
                    }
                } catch (IllegalArgumentException exception) {
                    fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, entry.getKey(),
                            "A disclosed leaf value cannot be hashed");
                    wellFormed = false;
                }
            }
            undisclosed += expected.size() - matched;
            try {
                String contentHash = V1Hashes.contentHash(V1Hashes.contentObject(
                        seq,
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
                    fail(BundleDiagnosticCode.CONTENT_HASH_MISMATCH, seq, pointer + "/contentHash",
                            "contentHash does not match the record fields");
                }
                String chain = V1Hashes.chainHash(
                        (String) record.get("prevHash"), (String) record.get("contentHash"));
                if (!chain.equals(record.get("chainHash"))) {
                    fail(BundleDiagnosticCode.CHAIN_HASH_MISMATCH, seq, pointer + "/chainHash",
                            "chainHash does not match prevHash and contentHash");
                }
            } catch (IllegalArgumentException exception) {
                fail(BundleDiagnosticCode.BUNDLE_SCHEMA_INVALID, seq, pointer,
                        "The record cannot be hashed");
                return false;
            }
            return wellFormed;
        }

        private boolean nonEmpty(Map<String, Object> bundle, String field) {
            if (!(bundle.get(field) instanceof String text) || text.isEmpty()) {
                schema("/" + field, field + " must be a non-empty string");
                return false;
            }
            return true;
        }

        private boolean timestamp(Map<String, Object> bundle, String field) {
            if (!(bundle.get(field) instanceof String text) || !BundleSelection.isCanonicalTimestamp(text)) {
                schema("/" + field, field + " must be a UTC microsecond timestamp");
                return false;
            }
            return true;
        }

        private boolean hash(Map<String, Object> bundle, String field) {
            if (!isHash(bundle.get(field))) {
                schema("/" + field, field + " must be 64 lowercase hex");
                return false;
            }
            return true;
        }

        private boolean algorithm(Map<String, Object> bundle, String field, String expected) {
            Object value = bundle.get(field);
            if (!(value instanceof String text)) {
                schema("/" + field, field + " must be a string");
                return false;
            }
            if (!expected.equals(text)) {
                fail(BundleDiagnosticCode.UNSUPPORTED_ALGORITHM, null, "/" + field,
                        "Unsupported " + field);
                return false;
            }
            return true;
        }

        private Result result() {
            Status status;
            if (total > 0) {
                status = Status.INVALID;
            } else {
                status = pinnedRaw != null ? Status.VERIFIED : Status.INTEGRITY_VALID_ORIGIN_UNTRUSTED;
            }
            return new Result(status, status == Status.VERIFIED, ledgerId, bundleId, keyId,
                    recordCount, undisclosed, List.copyOf(diagnostics), total,
                    total > diagnostics.size(), List.copyOf(notices));
        }
    }

    /** Collects pointer -> commitment for every scalar position; false if malformed or too many. */
    private static boolean collectLeaves(Object node, String pointer, Map<String, String> out, int limit) {
        if (node instanceof Map<?, ?> object) {
            for (Map.Entry<?, ?> entry : object.entrySet()) {
                String key = ((String) entry.getKey()).replace("~", "~0").replace("/", "~1");
                if (!collectLeaves(entry.getValue(), pointer + "/" + key, out, limit)) {
                    return false;
                }
            }
            return true;
        }
        if (node instanceof List<?> array) {
            for (int index = 0; index < array.size(); index++) {
                if (!collectLeaves(array.get(index), pointer + "/" + index, out, limit)) {
                    return false;
                }
            }
            return true;
        }
        if (isHash(node)) {
            out.put(pointer, (String) node);
            if (out.size() > limit) {
                return false;
            }
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

    private static int base64Length(String base64) {
        try {
            byte[] raw = Base64.getDecoder().decode(base64);
            return Base64.getEncoder().encodeToString(raw).equals(base64) ? raw.length : -1;
        } catch (IllegalArgumentException exception) {
            return -1;
        }
    }

    private static boolean isHash(Object value) {
        return value instanceof String text && HASH.matcher(text).matches();
    }

    private static String text(Object value) {
        return value instanceof String text ? text : null;
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
