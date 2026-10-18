package com.auditlog.store;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class JdbcAuditRepository implements AuditRepository {

    public static final int SCHEMA_VERSION = 3;
    private static final String SCHEMA_RESOURCE = "/db/schema-v1.sql";
    private static final int DEFAULT_BUSY_TIMEOUT_MILLIS = 30000;
    private static final String MIGRATION_V1_TO_V2_RESOURCE = "/db/migration-v1-to-v2.sql";
    private static final String MIGRATION_V2_TO_V3_RESOURCE = "/db/migration-v2-to-v3.sql";
    private final Path databasePath;
    private final String ledgerId;
    private final String jdbcUrl;
    private final String schemaSql;
    private final String migrationV2Sql;
    private final String migrationV3Sql;
    private final int busyTimeoutMillis;
    // Test seam: a page cap makes SQLite raise SQLITE_FULL without filling a real disk.
    private volatile long maxPageCount;

    public JdbcAuditRepository(Path databasePath, String ledgerId) throws SQLException {
        this(databasePath, ledgerId, DEFAULT_BUSY_TIMEOUT_MILLIS);
    }

    public JdbcAuditRepository(Path databasePath, String ledgerId, int busyTimeoutMillis) throws SQLException {
        if (busyTimeoutMillis <= 0) {
            throw new IllegalArgumentException("busyTimeoutMillis must be positive");
        }
        this.busyTimeoutMillis = busyTimeoutMillis;
        this.databasePath = Objects.requireNonNull(databasePath, "databasePath")
                .toAbsolutePath()
                .normalize();
        if (ledgerId == null || ledgerId.isBlank()) {
            throw new IllegalArgumentException("ledgerId must be non-empty");
        }
        this.ledgerId = ledgerId;
        this.jdbcUrl = "jdbc:sqlite:" + this.databasePath;
        this.schemaSql = loadResource(SCHEMA_RESOURCE);
        this.migrationV2Sql = loadResource(MIGRATION_V1_TO_V2_RESOURCE);
        this.migrationV3Sql = loadResource(MIGRATION_V2_TO_V3_RESOURCE);
        initialize();
    }

    public Path databasePath() {
        return databasePath;
    }

    /** Caps database pages for connections opened afterwards; zero removes the cap. */
    public void setMaxPageCount(long pages) {
        if (pages < 0) {
            throw new IllegalArgumentException("pages must not be negative");
        }
        this.maxPageCount = pages;
    }

    @Override
    public <T> T writeTransaction(TransactionWork<T> work) throws SQLException {
        return inTransaction(work, true);
    }

    @Override
    public <T> T readSnapshot(TransactionWork<T> work) throws SQLException {
        return inTransaction(work, false);
    }

    private <T> T inTransaction(TransactionWork<T> work, boolean immediate) throws SQLException {
        Objects.requireNonNull(work, "work");
        try (Connection connection = openConnection(false, !immediate);
                Statement transaction = connection.createStatement()) {
            try {
                transaction.execute(immediate ? "BEGIN IMMEDIATE" : "BEGIN");
                T result = work.execute(connection);
                transaction.execute("COMMIT");
                return result;
            } catch (SQLException | RuntimeException | Error failure) {
                rollback(transaction, failure);
                if (failure instanceof SQLException sqlException) {
                    throw translateBusy(sqlException);
                }
                throw failure;
            }
        } catch (SQLException exception) {
            if (exception instanceof StorageBusyException) {
                throw exception;
            }
            throw translateBusy(exception);
        }
    }

    private void initialize() throws SQLException {
        try {
            Path parent = databasePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException exception) {
            throw new SQLException("Unable to create SQLite database directory", exception);
        }

        try (Connection connection = openConnection(true);
                Statement statement = connection.createStatement()) {
            try {
                statement.execute("BEGIN IMMEDIATE");
                int version = readUserVersion(statement);
                if (version == SCHEMA_VERSION) {
                    verifyLedgerBinding(connection, SCHEMA_VERSION);
                    statement.execute("COMMIT");
                    return;
                }
                if (version == 1) {
                    verifyLedgerBinding(connection, 1);
                    migrateToV2(connection, statement);
                    migrateToV3(statement);
                    verifyLedgerBinding(connection, SCHEMA_VERSION);
                    statement.execute("COMMIT");
                    return;
                }
                if (version == 2) {
                    verifyLedgerBinding(connection, 2);
                    migrateToV3(statement);
                    verifyLedgerBinding(connection, SCHEMA_VERSION);
                    statement.execute("COMMIT");
                    return;
                }
                if (version != 0) {
                    throw new SQLException("Unsupported SQLite schema version: " + version);
                }
                if (hasApplicationTables(connection)) {
                    throw new SQLException("Unversioned SQLite schema cannot be migrated safely");
                }
                for (String sql : splitSchemaStatements(schemaSql)) {
                    statement.execute(sql);
                }
                try (var insert = connection.prepareStatement(
                        "INSERT INTO ledger_meta(singleton, ledger_id, schema_version) VALUES (1, ?, 1)")) {
                    insert.setString(1, ledgerId);
                    insert.executeUpdate();
                }
                statement.execute("PRAGMA user_version = 1");
                migrateToV2(connection, statement);
                migrateToV3(statement);
                verifyLedgerBinding(connection, SCHEMA_VERSION);
                statement.execute("COMMIT");
            } catch (SQLException | RuntimeException | Error failure) {
                rollback(statement, failure);
                if (failure instanceof SQLException sqlException) {
                    throw translateBusy(sqlException);
                }
                throw failure;
            }
        }
    }

    private Connection openConnection(boolean initializeWal) throws SQLException {
        return openConnection(initializeWal, false);
    }

    private Connection openConnection(boolean initializeWal, boolean queryOnly) throws SQLException {
        Connection connection = DriverManager.getConnection(jdbcUrl);
        boolean configured = false;
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA busy_timeout = " + busyTimeoutMillis);
            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute("PRAGMA secure_delete = ON");
            statement.execute("PRAGMA synchronous = FULL");
            long pageCap = maxPageCount;
            if (pageCap > 0) {
                statement.execute("PRAGMA max_page_count = " + pageCap);
            }
            if (queryOnly) {
                statement.execute("PRAGMA query_only = ON");
            }
            if (initializeWal) {
                try (ResultSet result = statement.executeQuery("PRAGMA journal_mode = WAL")) {
                    if (!result.next() || !"wal".equalsIgnoreCase(result.getString(1))) {
                        throw new SQLException("SQLite could not enable WAL mode");
                    }
                }
            } else {
                try (ResultSet result = statement.executeQuery("PRAGMA journal_mode")) {
                    if (!result.next() || !"wal".equalsIgnoreCase(result.getString(1))) {
                        throw new SQLException("SQLite database is not in WAL mode");
                    }
                }
            }
            configured = true;
            return connection;
        } finally {
            if (!configured) {
                connection.close();
            }
        }
    }

    /** Result row of {@code PRAGMA wal_checkpoint}: busy flag, WAL frames, checkpointed frames. */
    public record WalCheckpoint(int busy, int logFrames, int checkpointedFrames) {

        /** True only when SQLite reports no blocker and the whole WAL was checkpointed. */
        public boolean complete() {
            return busy == 0 && logFrames >= 0 && logFrames == checkpointedFrames;
        }
    }

    /**
     * Runs {@code PRAGMA wal_checkpoint(TRUNCATE)} on a fresh connection and returns the result
     * tuple. SQLite reports a blocked checkpoint (for example a held reader) as busy=1 in the
     * returned row, not as an exception, so the tuple must be inspected. The busy timeout is
     * deliberately shorter than the normal 30 s so that cleanup retries are finite and bounded.
     */
    public WalCheckpoint checkpointWalTruncate(int busyTimeoutMillis) throws SQLException {
        if (busyTimeoutMillis <= 0) {
            throw new IllegalArgumentException("busyTimeoutMillis must be positive");
        }
        try (Connection connection = openConnection(false);
                Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA busy_timeout = " + busyTimeoutMillis);
            try (ResultSet result = statement.executeQuery("PRAGMA wal_checkpoint(TRUNCATE)")) {
                if (!result.next()) {
                    throw new SQLException("wal_checkpoint returned no result row");
                }
                return new WalCheckpoint(result.getInt(1), result.getInt(2), result.getInt(3));
            }
        } catch (SQLException exception) {
            if (translateBusy(exception) instanceof StorageBusyException) {
                return new WalCheckpoint(1, -1, -1);
            }
            throw exception;
        }
    }

    private void migrateToV2(Connection connection, Statement statement) throws SQLException {
        for (String sql : splitSchemaStatements(migrationV2Sql)) {
            statement.execute(sql);
        }
        statement.execute("PRAGMA user_version = 2");
    }

    private void migrateToV3(Statement statement) throws SQLException {
        for (String sql : splitSchemaStatements(migrationV3Sql)) {
            statement.execute(sql);
        }
        statement.execute("PRAGMA user_version = 3");
    }

    private void verifyLedgerBinding(Connection connection, int expectedVersion) throws SQLException {
        try (Statement versionStatement = connection.createStatement()) {
            if (readUserVersion(versionStatement) != expectedVersion) {
                throw new SQLException("SQLite user_version does not match schema version");
            }
        }
        try (var statement = connection.prepareStatement(
                    "SELECT ledger_id, schema_version FROM ledger_meta WHERE singleton = 1");
                ResultSet result = statement.executeQuery()) {
            if (!result.next()) {
                throw new SQLException("SQLite ledger metadata is missing");
            }
            String storedLedgerId = result.getString("ledger_id");
            int storedSchemaVersion = result.getInt("schema_version");
            if (result.next()) {
                throw new SQLException("SQLite database contains multiple ledger metadata rows");
            }
            if (!ledgerId.equals(storedLedgerId)) {
                throw new SQLException("SQLite database is bound to a different ledger ID");
            }
            if (storedSchemaVersion != expectedVersion) {
                throw new SQLException("SQLite ledger metadata schema version is unsupported");
            }
        }
    }

    private static int readUserVersion(Statement statement) throws SQLException {
        try (ResultSet result = statement.executeQuery("PRAGMA user_version")) {
            if (!result.next()) {
                throw new SQLException("SQLite user_version is unavailable");
            }
            return result.getInt(1);
        }
    }

    private static boolean hasApplicationTables(Connection connection) throws SQLException {
        try (var statement = connection.prepareStatement(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                            + "AND name NOT LIKE 'sqlite_%' LIMIT 1");
                ResultSet result = statement.executeQuery()) {
            return result.next();
        }
    }

    private static String loadResource(String resource) throws SQLException {
        try (InputStream input = JdbcAuditRepository.class.getResourceAsStream(resource)) {
            if (input == null) {
                throw new SQLException("SQLite schema resource is missing: " + resource);
            }
            return new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new SQLException("Unable to read SQLite schema resource", exception);
        }
    }

    static List<String> splitSchemaStatements(String schema) throws SQLException {
        List<String> statements = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inTrigger = false;
        for (String line : schema.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.toUpperCase(java.util.Locale.ROOT).startsWith("CREATE TRIGGER ")) {
                inTrigger = true;
            }
            current.append(line).append('\n');
            if (inTrigger) {
                if (trimmed.equalsIgnoreCase("END;")) {
                    statements.add(current.toString());
                    current.setLength(0);
                    inTrigger = false;
                }
            } else if (trimmed.endsWith(";")) {
                statements.add(current.toString());
                current.setLength(0);
            }
        }
        if (inTrigger || !current.toString().isBlank()) {
            throw new SQLException("SQLite schema resource has an incomplete statement");
        }
        return statements;
    }

    private static void rollback(Statement transaction, Throwable originalFailure) {
        try {
            transaction.execute("ROLLBACK");
        } catch (SQLException rollbackFailure) {
            originalFailure.addSuppressed(rollbackFailure);
        }
    }

    private static SQLException translateBusy(SQLException exception) {
        if (exception instanceof StorageBusyException) {
            return exception;
        }
        SQLException current = exception;
        while (current != null) {
            int primaryCode = current.getErrorCode() & 0xff;
            if (primaryCode == 5 || primaryCode == 6) {
                return new StorageBusyException(exception);
            }
            current = current.getNextException();
        }
        return exception;
    }
}
