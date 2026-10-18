package com.auditlog.service;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.store.JdbcAuditRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Clock;

/**
 * Offline archive audit, separate from live chain verification. Exit codes: 0 every archive and the
 * coverage check passed, 1 archive evidence failed (missing, corrupt, substituted, wrong key ...),
 * 2 input or usage error.
 *
 * <pre>
 * ArchiveAuditCli --db ledger.db --ledger-id ID --archive-dir DIR
 *                 (--pinned-key-file key.b64 | --pinned-key BASE64) [--max-bytes N] [--max-records N]
 * </pre>
 * Opening the database uses the normal repository, which checks the ledger binding and schema
 * version and migrates an older schema; point it at a copy if that is not wanted.
 */
public final class ArchiveAuditCli {

    public static final int EXIT_INTACT = 0;
    public static final int EXIT_FAILED = 1;
    public static final int EXIT_USAGE = 2;

    private ArchiveAuditCli() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    public static int run(String[] args, PrintStream out, PrintStream err) {
        String db = null;
        String ledgerId = null;
        String archiveDir = null;
        String pinnedKey = null;
        String pinnedKeyFile = null;
        int maxBytes = AuditConfiguration.DEFAULT_ARCHIVE_MAX_BYTES;
        int maxRecords = AuditConfiguration.DEFAULT_ARCHIVE_MAX_RECORDS;
        try {
            for (int index = 0; index < args.length; index++) {
                switch (args[index]) {
                    case "--db" -> db = value(args, ++index);
                    case "--ledger-id" -> ledgerId = value(args, ++index);
                    case "--archive-dir" -> archiveDir = value(args, ++index);
                    case "--pinned-key" -> pinnedKey = value(args, ++index);
                    case "--pinned-key-file" -> pinnedKeyFile = value(args, ++index);
                    case "--max-bytes" -> maxBytes = Integer.parseInt(value(args, ++index));
                    case "--max-records" -> maxRecords = Integer.parseInt(value(args, ++index));
                    default -> throw new IllegalArgumentException("Unknown argument");
                }
            }
            if (db == null || ledgerId == null || archiveDir == null) {
                throw new IllegalArgumentException("--db, --ledger-id and --archive-dir are required");
            }
            if ((pinnedKey == null) == (pinnedKeyFile == null)) {
                throw new IllegalArgumentException("Exactly one of --pinned-key and --pinned-key-file is required");
            }
            if (maxBytes < 1 || maxRecords < 1) {
                throw new IllegalArgumentException("Limits must be positive");
            }
            Path dbPath = Path.of(db);
            if (!Files.isRegularFile(dbPath)) {
                throw new IllegalArgumentException("Database file does not exist");
            }
            if (pinnedKeyFile != null) {
                pinnedKey = Files.readString(Path.of(pinnedKeyFile), StandardCharsets.UTF_8).strip();
            }
            ArchiveAuditService service = new ArchiveAuditService(
                    new JdbcAuditRepository(dbPath, ledgerId), ledgerId, Path.of(archiveDir),
                    maxBytes, maxRecords, pinnedKey, Clock.systemUTC());
            var report = service.audit();
            out.println(new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(report));
            return Boolean.TRUE.equals(report.get("intact")) ? EXIT_INTACT : EXIT_FAILED;
        } catch (IllegalArgumentException | IOException exception) {
            err.println("ERROR: " + (exception instanceof IllegalArgumentException
                    ? exception.getMessage() : "Input could not be read"));
            return EXIT_USAGE;
        } catch (SQLException exception) {
            err.println("ERROR: Ledger database could not be opened or read");
            return EXIT_USAGE;
        }
    }

    private static String value(String[] args, int index) {
        if (index >= args.length) {
            throw new IllegalArgumentException("Missing value for " + args[index - 1]);
        }
        return args[index];
    }
}
