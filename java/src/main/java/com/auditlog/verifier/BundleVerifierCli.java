package com.auditlog.verifier;

import com.auditlog.domain.BundleDiagnostic;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;

/**
 * Offline CLI. Exit codes: 0 trusted-valid or explicitly untrusted-valid evidence, 1 evidence
 * invalid (schema, resource limit, signature, missing trusted key), 2 input or usage error such as
 * an unreadable file or bad arguments.
 *
 * <pre>
 * BundleVerifierCli (--bundle bundle.json | --manifest set-dir/manifest.json)
 *                    (--pinned-key-file key.b64 | --pinned-key BASE64
 *                    | --allow-self-asserted) [--max-bytes N] [--max-records N]
 * </pre>
 * A manifest is verified together with the chunk files in its directory.
 */
public final class BundleVerifierCli {

    public static final int EXIT_VALID = 0;
    public static final int EXIT_INVALID = 1;
    public static final int EXIT_USAGE = 2;

    private BundleVerifierCli() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    public static int run(String[] args, PrintStream out, PrintStream err) {
        String bundlePath = null;
        String manifestPath = null;
        String pinnedKey = null;
        String pinnedKeyFile = null;
        boolean selfAsserted = false;
        int maxBytes = BundleVerifier.DEFAULT_MAX_BYTES;
        Integer maxRecordsOption = null;
        try {
            for (int index = 0; index < args.length; index++) {
                switch (args[index]) {
                    case "--bundle" -> bundlePath = value(args, ++index);
                    case "--manifest" -> manifestPath = value(args, ++index);
                    case "--pinned-key" -> pinnedKey = value(args, ++index);
                    case "--pinned-key-file" -> pinnedKeyFile = value(args, ++index);
                    case "--allow-self-asserted" -> selfAsserted = true;
                    case "--max-bytes" -> maxBytes = Integer.parseInt(value(args, ++index));
                    case "--max-records" -> maxRecordsOption = Integer.parseInt(value(args, ++index));
                    default -> throw new BundleVerifier.InputException("Unknown argument");
                }
            }
            if ((bundlePath == null) == (manifestPath == null)) {
                throw new BundleVerifier.InputException("Exactly one of --bundle and --manifest is required");
            }
            int maxRecords = maxRecordsOption != null ? maxRecordsOption
                    : manifestPath != null ? ExportSetVerifier.DEFAULT_MAX_RECORDS
                    : BundleVerifier.DEFAULT_MAX_RECORDS;
            if (pinnedKey != null && pinnedKeyFile != null) {
                throw new BundleVerifier.InputException("Use only one of --pinned-key and --pinned-key-file");
            }
            if (pinnedKeyFile != null) {
                pinnedKey = Files.readString(Path.of(pinnedKeyFile), StandardCharsets.UTF_8).strip();
            }
            if (pinnedKey != null && selfAsserted) {
                throw new BundleVerifier.InputException(
                        "A pinned key and --allow-self-asserted are mutually exclusive");
            }
            BundleVerifier.Options options = new BundleVerifier.Options(
                    pinnedKey, selfAsserted, maxBytes, maxRecords);
            BundleVerifier.Result result;
            if (manifestPath != null) {
                result = ExportSetVerifier.verify(Path.of(manifestPath), options);
            } else {
                byte[] input = read(Path.of(bundlePath), maxBytes);
                result = BundleVerifier.verify(input, options);
            }
            print(result, out);
            return result.valid() ? EXIT_VALID : EXIT_INVALID;
        } catch (BundleVerifier.InputException | NumberFormatException | IOException
                | InvalidPathException exception) {
            err.println("ERROR: " + safeMessage(exception));
            return EXIT_USAGE;
        }
    }

    private static String safeMessage(Exception exception) {
        if (exception instanceof NumberFormatException) {
            return "Numeric option is not a valid integer";
        }
        if (exception instanceof IOException) {
            return "Input file could not be read";
        }
        if (exception instanceof InvalidPathException) {
            return "Path is not valid";
        }
        return exception.getMessage();
    }

    private static String value(String[] args, int index) {
        if (index >= args.length) {
            throw new BundleVerifier.InputException("Missing value for " + args[index - 1]);
        }
        return args[index];
    }

    /** Reads at most maxBytes+1 so oversized input is detected without loading it. */
    private static byte[] read(Path path, int maxBytes) throws IOException {
        try (InputStream stream = Files.newInputStream(path)) {
            return stream.readNBytes(maxBytes + 1);
        }
    }

    private static void print(BundleVerifier.Result result, PrintStream out) {
        switch (result.status()) {
            case VERIFIED -> out.println("VERIFIED");
            case INTEGRITY_VALID_ORIGIN_UNTRUSTED -> {
                out.println("INTEGRITY_VALID_ORIGIN_UNTRUSTED");
                out.println("*** WARNING: ORIGIN NOT TRUSTED - the signer key came from the bundle itself. "
                        + "This only shows internal consistency, not who produced the bundle. ***");
            }
            case INVALID -> out.println("INVALID");
        }
        out.println("originTrusted: " + result.originTrusted());
        out.println("ledgerId: " + result.ledgerId());
        out.println("bundleId: " + result.bundleId());
        out.println("keyId: " + result.keyId());
        out.println("recordCount: " + result.recordCount());
        out.println("undisclosedLeafCount: " + result.undisclosedLeafCount());
        out.println("totalDiagnosticCount: " + result.totalDiagnosticCount());
        for (BundleDiagnostic diagnostic : result.diagnostics()) {
            out.println("diagnostic: " + diagnostic.code()
                    + " seq=" + diagnostic.seq() + " pointer=" + diagnostic.pointer()
                    + " message=" + diagnostic.message());
        }
        if (result.diagnosticsTruncated()) {
            out.println("diagnosticsTruncated: true");
        }
        result.notices().forEach(notice -> out.println("notice: " + notice));
    }
}
