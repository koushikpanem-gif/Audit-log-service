package com.auditlog.verifier;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Offline CLI. Exit codes: 0 verified, 1 evidence invalid, 2 input or usage error.
 *
 * <pre>
 * BundleVerifierCli --bundle bundle.json (--pinned-key-file key.b64 | --pinned-key BASE64
 *                    | --allow-self-asserted) [--max-bytes N] [--max-records N]
 * </pre>
 */
public final class BundleVerifierCli {

    public static final int EXIT_VERIFIED = 0;
    public static final int EXIT_INVALID = 1;
    public static final int EXIT_USAGE = 2;

    private BundleVerifierCli() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    public static int run(String[] args, PrintStream out, PrintStream err) {
        String bundlePath = null;
        String pinnedKey = null;
        String pinnedKeyFile = null;
        boolean selfAsserted = false;
        int maxBytes = BundleVerifier.DEFAULT_MAX_BYTES;
        int maxRecords = BundleVerifier.DEFAULT_MAX_RECORDS;
        try {
            for (int index = 0; index < args.length; index++) {
                switch (args[index]) {
                    case "--bundle" -> bundlePath = value(args, ++index);
                    case "--pinned-key" -> pinnedKey = value(args, ++index);
                    case "--pinned-key-file" -> pinnedKeyFile = value(args, ++index);
                    case "--allow-self-asserted" -> selfAsserted = true;
                    case "--max-bytes" -> maxBytes = Integer.parseInt(value(args, ++index));
                    case "--max-records" -> maxRecords = Integer.parseInt(value(args, ++index));
                    default -> throw new BundleVerifier.InputException("Unknown argument: " + args[index]);
                }
            }
            if (bundlePath == null) {
                throw new BundleVerifier.InputException("--bundle is required");
            }
            if (pinnedKey != null && pinnedKeyFile != null) {
                throw new BundleVerifier.InputException("Use only one of --pinned-key and --pinned-key-file");
            }
            if (pinnedKeyFile != null) {
                pinnedKey = Files.readString(Path.of(pinnedKeyFile), StandardCharsets.UTF_8).strip();
            }
            BundleVerifier.Options options = new BundleVerifier.Options(
                    pinnedKey, selfAsserted, maxBytes, maxRecords);
            byte[] input = read(Path.of(bundlePath), maxBytes);
            BundleVerifier.Result result = BundleVerifier.verify(input, options);
            print(result, out);
            return result.verified() ? EXIT_VERIFIED : EXIT_INVALID;
        } catch (BundleVerifier.InputException | NumberFormatException | IOException
                | java.nio.file.InvalidPathException exception) {
            err.println("ERROR: " + exception.getMessage());
            return EXIT_USAGE;
        }
    }

    private static String value(String[] args, int index) {
        if (index >= args.length) {
            throw new BundleVerifier.InputException("Missing value for " + args[index - 1]);
        }
        return args[index];
    }

    private static byte[] read(Path path, int maxBytes) throws IOException {
        try (InputStream stream = Files.newInputStream(path)) {
            byte[] data = stream.readNBytes(maxBytes + 1);
            if (data.length > maxBytes) {
                throw new BundleVerifier.InputException("Bundle exceeds the byte limit");
            }
            return data;
        }
    }

    private static void print(BundleVerifier.Result result, PrintStream out) {
        out.println(result.verified() ? "VERIFIED" : "INVALID");
        out.println("trust: " + result.trust());
        out.println("ledgerId: " + result.ledgerId());
        out.println("bundleId: " + result.bundleId());
        out.println("keyId: " + result.keyId());
        out.println("recordCount: " + result.recordCount());
        out.println("undisclosedLeafCount: " + result.undisclosedLeafCount());
        out.println("totalViolationCount: " + result.totalViolationCount());
        result.violations().forEach(violation -> out.println("violation: " + violation));
        if (result.violationsTruncated()) {
            out.println("violationsTruncated: true");
        }
        result.notes().forEach(note -> out.println("note: " + note));
    }
}
