package com.auditlog.core.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CheckpointSignerTests {

    @Test
    void signsAndVerifiesSharedTestOnlyFixture() throws Exception {
        JsonNode fixture = CanonicalJson.parse(
                getClass().getResourceAsStream("/test-vectors/ed25519-checkpoint-v1.json").readAllBytes());
        assertTrue(fixture.get("fixtureLabel").asText().contains("TEST ONLY"));
        JsonNode message = fixture.get("message");
        CheckpointSigner signer = CheckpointSigner.fromPem(
                fixture.get("privateKeyPkcs8Pem").asText().getBytes(StandardCharsets.US_ASCII),
                fixture.get("publicKeyBase64").asText());

        Map<String, Object> checkpoint = signer.signCheckpoint(
                message.get("ledgerId").asText(),
                message.get("seq").longValue(),
                message.get("chainHash").asText(),
                message.get("createdAt").asText());
        assertEquals(fixture.get("keyId").asText(), signer.keyId());
        assertEquals(fixture.get("signatureBase64").asText(), checkpoint.get("signature"));
        assertEquals(fixture.get("publicKeyBase64").asText(), signer.publicKeyBase64());
        assertTrue(CheckpointSigner.verifyCheckpoint(checkpoint, signer.publicKeyBase64()));

        Map<String, Object> tampered = new LinkedHashMap<>(checkpoint);
        tampered.put("ledgerId", "tampered");
        assertFalse(CheckpointSigner.verifyCheckpoint(tampered, signer.publicKeyBase64()));
    }

    @Test
    void rejectsInvalidKeyTypesLengthsPairsAndCheckpointShapes() throws Exception {
        String publicKey = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
        String privatePem = "-----BEGIN PRIVATE KEY-----\n"
                + "MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n"
                + "-----END PRIVATE KEY-----\n";
        assertThrows(IllegalArgumentException.class,
                () -> CheckpointSigner.fromPem("bad".getBytes(StandardCharsets.US_ASCII), publicKey));
        assertThrows(IllegalArgumentException.class,
                () -> CheckpointSigner.fromPem(privatePem.getBytes(StandardCharsets.US_ASCII), "%%%"));
        assertThrows(IllegalArgumentException.class,
                () -> CheckpointSigner.fromPem(
                        privatePem.getBytes(StandardCharsets.US_ASCII),
                        "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"));
        assertThrows(IllegalArgumentException.class,
                () -> CheckpointSigner.fromPem(
                        privatePem.getBytes(StandardCharsets.US_ASCII),
                        Base64.getEncoder().encodeToString(new byte[31])));

        var other = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] otherDer = other.getPublic().getEncoded();
        String wrongPublic = Base64.getEncoder().encodeToString(
                java.util.Arrays.copyOfRange(otherDer, otherDer.length - 32, otherDer.length));
        assertThrows(IllegalArgumentException.class,
                () -> CheckpointSigner.fromPem(privatePem.getBytes(StandardCharsets.US_ASCII), wrongPublic));

        var rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        byte[] rsaPem = ("-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(rsa.generateKeyPair()
                        .getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n").getBytes(StandardCharsets.US_ASCII);
        assertThrows(IllegalArgumentException.class,
                () -> CheckpointSigner.fromPem(rsaPem, publicKey));

        CheckpointSigner signer = CheckpointSigner.fromPem(
                privatePem.getBytes(StandardCharsets.US_ASCII), publicKey);
        assertThrows(IllegalArgumentException.class,
                () -> signer.signCheckpoint("ledger", 0, "0".repeat(64), "now"));
        assertThrows(IllegalArgumentException.class,
                () -> CheckpointSigner.verifyCheckpoint(Map.of("unexpected", true), publicKey));
    }

    @Test
    void developmentKeyCreationIsExclusiveReusableAndProductionNeverCreates(@TempDir Path tempDir)
            throws Exception {
        Path privatePath = tempDir.resolve("signing-private.pem");
        Path publicPath = tempDir.resolve("signing-public.b64");
        assertThrows(IllegalArgumentException.class,
                () -> CheckpointSigner.fromFiles(privatePath, publicPath, "prod"));

        CheckpointSigner first = CheckpointSigner.fromFiles(privatePath, publicPath, "dev");
        byte[] originalPrivate = Files.readAllBytes(privatePath);
        CheckpointSigner second = CheckpointSigner.fromFiles(privatePath, publicPath, "dev");
        assertEquals(first.keyId(), second.keyId());
        assertTrue(java.util.Arrays.equals(originalPrivate, Files.readAllBytes(privatePath)));
        assertTrue(Files.isRegularFile(publicPath));
        if (Files.getFileAttributeView(tempDir, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            Set<PosixFilePermission> ownerOnly = Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            assertEquals(ownerOnly, Files.getPosixFilePermissions(privatePath));
            assertEquals(ownerOnly, Files.getPosixFilePermissions(publicPath));
        }

        Files.delete(publicPath);
        assertThrows(IllegalArgumentException.class,
                () -> CheckpointSigner.fromFiles(privatePath, publicPath, "dev"));
    }
}
