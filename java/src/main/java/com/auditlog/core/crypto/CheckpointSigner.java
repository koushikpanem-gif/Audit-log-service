package com.auditlog.core.crypto;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public final class CheckpointSigner {

    private static final byte[] X509_ED25519_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final int RAW_PUBLIC_KEY_LENGTH = 32;
    private static final String CHECKPOINT_TYPE = "audit-checkpoint/v1";
    private static final String KEY_ID_PREFIX = "audit-log/key-pair-check/v1";

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final byte[] rawPublicKey;
    private final String keyId;

    private CheckpointSigner(PrivateKey privateKey, PublicKey publicKey, byte[] rawPublicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.rawPublicKey = rawPublicKey.clone();
        this.keyId = sha256Hex(rawPublicKey).substring(0, 16);
    }

    public static CheckpointSigner fromPem(byte[] privatePem, String publicKeyBase64) {
        if (privatePem == null || publicKeyBase64 == null) {
            throw new IllegalArgumentException("Private PEM and public Base64 key are required");
        }
        try {
            String pem = new String(privatePem, StandardCharsets.US_ASCII);
            String trimmedPem = pem.strip();
            if (!trimmedPem.startsWith("-----BEGIN PRIVATE KEY-----")
                    || !trimmedPem.endsWith("-----END PRIVATE KEY-----")
                    || trimmedPem.indexOf("-----BEGIN PRIVATE KEY-----",
                            "-----BEGIN PRIVATE KEY-----".length()) >= 0) {
                throw new IllegalArgumentException("Private key must be unencrypted PKCS#8 PEM");
            }
            String body = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            if (body.isEmpty() || pem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
                throw new IllegalArgumentException("Private key must be unencrypted PKCS#8 PEM");
            }
            byte[] privateDer = Base64.getDecoder().decode(body);
            PrivateKey privateKey = KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new PKCS8EncodedKeySpec(privateDer));
            if (!(privateKey instanceof EdECPrivateKey)) {
                throw new IllegalArgumentException("Private key must use Ed25519");
            }
            byte[] rawPublic = Base64.getDecoder().decode(publicKeyBase64);
            if (!Base64.getEncoder().encodeToString(rawPublic).equals(publicKeyBase64)) {
                throw new IllegalArgumentException("Public key must use canonical standard Base64");
            }
            if (rawPublic.length != RAW_PUBLIC_KEY_LENGTH) {
                throw new IllegalArgumentException("Raw Ed25519 public key must contain exactly 32 bytes");
            }
            byte[] publicDer = ByteBuffer.allocate(X509_ED25519_PREFIX.length + rawPublic.length)
                    .put(X509_ED25519_PREFIX)
                    .put(rawPublic)
                    .array();
            PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(publicDer));
            CheckpointSigner signer = new CheckpointSigner(privateKey, publicKey, rawPublic);
            signer.verifyKeyPair();
            return signer;
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            if (exception instanceof IllegalArgumentException illegalArgumentException) {
                throw illegalArgumentException;
            }
            throw new IllegalArgumentException("Invalid Ed25519 PKCS#8 key material", exception);
        }
    }

    public static CheckpointSigner fromFiles(Path privatePath, Path publicPath, String environment)
            throws IOException {
        if (privatePath == null || publicPath == null) {
            throw new IllegalArgumentException("Signing key paths are required");
        }
        privatePath = privatePath.toAbsolutePath().normalize();
        publicPath = publicPath.toAbsolutePath().normalize();
        if (!"dev".equals(environment) && !"prod".equals(environment)) {
            throw new IllegalArgumentException("Environment must be 'dev' or 'prod'");
        }
        boolean privateExists = Files.exists(privatePath, LinkOption.NOFOLLOW_LINKS);
        boolean publicExists = Files.exists(publicPath, LinkOption.NOFOLLOW_LINKS);
        if (privateExists || publicExists) {
            if (!Files.isRegularFile(privatePath, LinkOption.NOFOLLOW_LINKS)
                    || !Files.isRegularFile(publicPath, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalArgumentException("Both signing key files must be regular files");
            }
            byte[] privatePem = readBounded(privatePath, 16 * 1024);
            byte[] publicKeyBytes = readBounded(publicPath, 128);
            if (privatePem.length > 16 * 1024 || publicKeyBytes.length > 128) {
                throw new IllegalArgumentException("Signing key file exceeds its size limit");
            }
            return fromPem(
                    privatePem,
                    new String(publicKeyBytes, StandardCharsets.US_ASCII).trim());
        }
        if ("prod".equals(environment)) {
            throw new IllegalArgumentException("Production requires existing signing key files");
        }
        if (privatePath.toAbsolutePath().normalize().equals(publicPath.toAbsolutePath().normalize())) {
            throw new IllegalArgumentException("Private and public key files must be different paths");
        }

        KeyPairMaterial material = generateKeyPair();
        Path privateParent = privatePath.toAbsolutePath().getParent();
        Path publicParent = publicPath.toAbsolutePath().getParent();
        if (privateParent == null || publicParent == null) {
            throw new IllegalArgumentException("Signing key paths must have parent directories");
        }
        Files.createDirectories(privateParent);
        Files.createDirectories(publicParent);
        createRestrictedFile(privatePath, material.privatePem());
        try {
            createRestrictedFile(publicPath, (material.publicKeyBase64() + "\n")
                    .getBytes(StandardCharsets.US_ASCII));
        } catch (IOException exception) {
            Files.deleteIfExists(privatePath);
            throw exception;
        }
        return fromPem(material.privatePem(), material.publicKeyBase64());
    }

    public String publicKeyBase64() {
        return Base64.getEncoder().encodeToString(rawPublicKey);
    }

    public String keyId() {
        return keyId;
    }

    public Map<String, Object> signCheckpoint(
            String ledgerId, long seq, String chainHash, String createdAt) {
        if (ledgerId == null || ledgerId.isBlank() || seq <= 0 || seq > 9_007_199_254_740_991L
                || chainHash == null || !chainHash.matches("[0-9a-f]{64}")
                || createdAt == null || createdAt.isBlank()) {
            throw new IllegalArgumentException("Checkpoint message fields are invalid");
        }
        validateLedgerId(ledgerId);
        Map<String, Object> message = checkpointMessage(ledgerId, seq, chainHash, createdAt);
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(CanonicalJson.canonicalize(message));
            Map<String, Object> checkpoint = new LinkedHashMap<>(message);
            checkpoint.put("keyId", keyId);
            checkpoint.put("signature", Base64.getEncoder().encodeToString(signature.sign()));
            return Map.copyOf(checkpoint);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Ed25519 checkpoint signing failed", exception);
        }
    }

    /** Signs JCS(message) and returns the standard Base64 signature. */
    public String signMessage(Map<String, Object> message, int maxBytes) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(CanonicalJson.canonicalize(
                    message, CanonicalJson.MAX_DOCUMENT_DEPTH, maxBytes));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Ed25519 message signing failed", exception);
        }
    }

    /** Verifies an Ed25519 signature over already-canonical bytes with a raw 32-byte public key. */
    public static boolean verifyRaw(byte[] canonicalMessage, String signatureBase64, byte[] rawPublic) {
        if (rawPublic == null || rawPublic.length != RAW_PUBLIC_KEY_LENGTH || signatureBase64 == null) {
            throw new IllegalArgumentException("Raw Ed25519 public key must contain exactly 32 bytes");
        }
        byte[] signatureBytes;
        try {
            signatureBytes = Base64.getDecoder().decode(signatureBase64);
        } catch (IllegalArgumentException exception) {
            return false;
        }
        if (!Base64.getEncoder().encodeToString(signatureBytes).equals(signatureBase64)) {
            return false;
        }
        try {
            byte[] publicDer = ByteBuffer.allocate(X509_ED25519_PREFIX.length + rawPublic.length)
                    .put(X509_ED25519_PREFIX)
                    .put(rawPublic)
                    .array();
            PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(publicDer));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(canonicalMessage);
            return verifier.verify(signatureBytes);
        } catch (SignatureException exception) {
            return false;
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException("Invalid Ed25519 public key", exception);
        }
    }

    public static String keyIdFor(byte[] rawPublic) {
        return sha256Hex(rawPublic).substring(0, 16);
    }

    public static boolean verifyCheckpoint(Map<String, ?> checkpoint, String publicKeyBase64) {
        Set<String> fields = Set.of(
                "type", "ledgerId", "seq", "chainHash", "createdAt", "keyId", "signature");
        if (checkpoint == null || !checkpoint.keySet().equals(fields)) {
            throw new IllegalArgumentException("Checkpoint must have exactly the required fields");
        }
        if (publicKeyBase64 == null) {
            throw new IllegalArgumentException("Raw public key Base64 is required");
        }
        Object keyIdValue = checkpoint.get("keyId");
        Object signatureValue = checkpoint.get("signature");
        Object type = checkpoint.get("type");
        Object ledgerId = checkpoint.get("ledgerId");
        Object seq = checkpoint.get("seq");
        Object chainHash = checkpoint.get("chainHash");
        Object createdAt = checkpoint.get("createdAt");
        if (!(keyIdValue instanceof String expectedKeyId)
                || !(signatureValue instanceof String signatureBase64)
                || !CHECKPOINT_TYPE.equals(type)
                || !(ledgerId instanceof String value && !value.isBlank())
                || !(seq instanceof Byte || seq instanceof Short || seq instanceof Integer || seq instanceof Long)
                || ((Number) seq).longValue() <= 0
                || ((Number) seq).longValue() > 9_007_199_254_740_991L
                || !(chainHash instanceof String hash && hash.matches("[0-9a-f]{64}"))
                || !(createdAt instanceof String created && !created.isBlank())) {
            throw new IllegalArgumentException("Checkpoint message fields have invalid types");
        }
        validateLedgerId((String) ledgerId);
        long sequence = ((Number) seq).longValue();
        byte[] rawPublic;
        byte[] signatureBytes;
        try {
            rawPublic = Base64.getDecoder().decode(publicKeyBase64);
            signatureBytes = Base64.getDecoder().decode(signatureBase64);
            if (!Base64.getEncoder().encodeToString(rawPublic).equals(publicKeyBase64)
                    || !Base64.getEncoder().encodeToString(signatureBytes).equals(signatureBase64)) {
                throw new IllegalArgumentException("Checkpoint key and signature must use canonical Base64");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Checkpoint key and signature must be valid Base64", exception);
        }
        if (rawPublic.length != RAW_PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("Raw Ed25519 public key must contain exactly 32 bytes");
        }
        if (!MessageDigest.isEqual(
                sha256Hex(rawPublic).substring(0, 16).getBytes(StandardCharsets.US_ASCII),
                expectedKeyId.getBytes(StandardCharsets.US_ASCII))) {
            return false;
        }
        try {
            byte[] publicDer = ByteBuffer.allocate(X509_ED25519_PREFIX.length + rawPublic.length)
                    .put(X509_ED25519_PREFIX)
                    .put(rawPublic)
                    .array();
            PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(publicDer));
            Map<String, Object> message = checkpointMessage(
                    (String) ledgerId, sequence, (String) chainHash, (String) createdAt);
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(CanonicalJson.canonicalize(message));
            return verifier.verify(signatureBytes);
        } catch (SignatureException exception) {
            return false;
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException("Invalid Ed25519 checkpoint", exception);
        }
    }

    private void verifyKeyPair() throws GeneralSecurityException {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey);
        signature.update(KEY_ID_PREFIX.getBytes(StandardCharsets.UTF_8));
        byte[] proof = signature.sign();
        signature.initVerify(publicKey);
        signature.update(KEY_ID_PREFIX.getBytes(StandardCharsets.UTF_8));
        if (!signature.verify(proof)) {
            throw new IllegalArgumentException("Private and public Ed25519 keys do not match");
        }
    }

    private static Map<String, Object> checkpointMessage(
            String ledgerId, long seq, String chainHash, String createdAt) {
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("type", CHECKPOINT_TYPE);
        message.put("ledgerId", ledgerId);
        message.put("seq", seq);
        message.put("chainHash", chainHash);
        message.put("createdAt", createdAt);
        return message;
    }

    private static void validateLedgerId(String ledgerId) {
        if (!StandardCharsets.UTF_8.newEncoder().canEncode(ledgerId)) {
            throw new IllegalArgumentException("Checkpoint ledgerId must contain valid Unicode");
        }
        byte[] encoded = ledgerId.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > 256) {
            throw new IllegalArgumentException("Checkpoint ledgerId exceeds 256 UTF-8 bytes");
        }
    }

    private static KeyPairMaterial generateKeyPair() {
        try {
            var generated = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            byte[] publicDer = generated.getPublic().getEncoded();
            if (publicDer.length != X509_ED25519_PREFIX.length + RAW_PUBLIC_KEY_LENGTH
                    || !Arrays.equals(
                            Arrays.copyOf(publicDer, X509_ED25519_PREFIX.length),
                            X509_ED25519_PREFIX)) {
                throw new IllegalStateException("JDK returned unexpected Ed25519 public-key encoding");
            }
            byte[] rawPublic = Arrays.copyOfRange(publicDer, X509_ED25519_PREFIX.length, publicDer.length);
            String pemBody = Base64.getMimeEncoder(64, new byte[] {'\n'})
                    .encodeToString(generated.getPrivate().getEncoded());
            byte[] privatePem = ("-----BEGIN PRIVATE KEY-----\n" + pemBody
                    + "\n-----END PRIVATE KEY-----\n").getBytes(StandardCharsets.US_ASCII);
            return new KeyPairMaterial(privatePem, Base64.getEncoder().encodeToString(rawPublic));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to generate an Ed25519 key pair", exception);
        }
    }

    private static void createRestrictedFile(Path path, byte[] contents) throws IOException {
        try {
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null && Files.getFileAttributeView(parent, PosixFileAttributeView.class) != null) {
                Files.createFile(path, PosixFilePermissions.asFileAttribute(
                        Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
            } else {
                Files.createFile(path);
                restrictWindowsAcl(path);
            }
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(contents);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
        } catch (IOException exception) {
            Files.deleteIfExists(path);
            throw exception;
        }
    }

    private static void restrictWindowsAcl(Path path) throws IOException {
        String username = System.getProperty("user.name");
        String domain = System.getenv("USERDOMAIN");
        if (username == null || username.isBlank()) {
            throw new IOException("Current Windows account is unavailable for key ACL");
        }
        String account = domain == null || domain.isBlank() ? username : domain + "\\" + username;
        Process process = new ProcessBuilder(
                "icacls", path.toString(), "/inheritance:r", "/grant:r", account + ":F")
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .start();
        try {
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new IOException("Timed out restricting Windows signing-key ACL");
            }
            if (process.exitValue() != 0) {
                throw new IOException("Unable to restrict Windows signing-key ACL");
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while restricting Windows signing-key ACL", exception);
        }
    }

    private static byte[] readBounded(Path path, int maximumBytes) throws IOException {
        try (var input = Files.newInputStream(path)) {
            return input.readNBytes(maximumBytes + 1);
        }
    }

    private static String sha256Hex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private record KeyPairMaterial(byte[] privatePem, String publicKeyBase64) {
        private KeyPairMaterial {
            privatePem = privatePem.clone();
        }
    }
}
