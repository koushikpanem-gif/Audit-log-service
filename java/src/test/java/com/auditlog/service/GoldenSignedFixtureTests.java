package com.auditlog.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.verifier.BundleVerifier;
import com.auditlog.verifier.BundleVerifier.Options;
import com.auditlog.verifier.BundleVerifier.Result;
import com.auditlog.verifier.BundleVerifier.Status;
import com.auditlog.verifier.ExportSetVerifier;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Verifies frozen golden evidence under src/test/resources/golden/independent_signed. The files
 * were produced once by a separate implementation and are checked in unchanged, so the expected
 * results do not come from this code base. They are signed with the labelled non-production
 * test key in golden/bundle_vectors and must never be used outside tests.
 */
class GoldenSignedFixtureTests {

    @TempDir
    Path directory;

    private static Path golden() {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (dir != null) {
            Path candidate = dir.resolve("src/test/resources/golden");
            if (Files.isDirectory(candidate)) {
                return candidate;
            }
            candidate = dir.resolve("java/src/test/resources/golden");
            if (Files.isDirectory(candidate)) {
                return candidate;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException("golden fixtures not found");
    }

    private static String testKey() throws IOException {
        return Files.readString(golden().resolve("bundle_vectors/test_key_public.b64")).strip();
    }

    @Test
    void verifiesIndependentlySignedBundle() throws Exception {
        Path bundle = golden().resolve("independent_signed/bundle.json");
        Result result = BundleVerifier.verify(Files.readAllBytes(bundle), Options.pinned(testKey()));
        assertEquals(Status.VERIFIED, result.status(), result.diagnostics().toString());
        assertEquals(3, result.recordCount());
        assertEquals(1, result.undisclosedLeafCount());
    }

    @Test
    void verifiesIndependentlySignedExportSet() throws Exception {
        Path manifest = golden().resolve("independent_signed/export_set/manifest.json");
        Result result = ExportSetVerifier.verify(manifest, Options.pinned(testKey()));
        assertEquals(Status.VERIFIED, result.status(), result.diagnostics().toString());
        assertEquals(3, result.recordCount());
        assertEquals(1, result.undisclosedLeafCount());
    }

    @Test
    void rejectsIndependentlySignedEvidenceUnderWrongOrMissingKey() throws Exception {
        CheckpointSigner other = CheckpointSigner.fromFiles(
                directory.resolve("other/private.pem"), directory.resolve("other/public.b64"), "dev");
        byte[] bytes = Files.readAllBytes(golden().resolve("independent_signed/bundle.json"));
        assertEquals(Status.INVALID,
                BundleVerifier.verify(bytes, Options.pinned(other.publicKeyBase64())).status());
        assertEquals(Status.INVALID, BundleVerifier.verify(bytes, Options.unconfigured()).status());
        assertEquals(Status.INTEGRITY_VALID_ORIGIN_UNTRUSTED,
                BundleVerifier.verify(bytes, Options.selfAsserted()).status());
    }
}
