package com.auditlog.store;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SchemaMigrationTests {

    @TempDir
    Path directory;

    @Test
    void version1DatabaseMigratesToVersion2PreservingLedgerBindingAndRows() throws Exception {
        Path database = directory.resolve("v1.db");
        String schema = new String(
                getClass().getResourceAsStream("/db/schema-v1.sql").readAllBytes(), StandardCharsets.UTF_8);
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
                Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA journal_mode = WAL");
            for (String sql : JdbcAuditRepository.splitSchemaStatements(schema)) {
                statement.execute(sql);
            }
            statement.execute(
                    "INSERT INTO ledger_meta(singleton, ledger_id, schema_version) VALUES (1, 'legacy', 1)");
            statement.execute("PRAGMA user_version = 1");
        }

        new JdbcAuditRepository(database, "legacy");

        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
                Statement statement = connection.createStatement()) {
            assertEquals(2, single(statement, "PRAGMA user_version"));
            assertEquals(2, single(statement, "SELECT schema_version FROM ledger_meta"));
            assertEquals(1, single(statement,
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = 'redaction_cleanup'"));
        }

        new JdbcAuditRepository(database, "legacy");
    }

    private static long single(Statement statement, String sql) throws Exception {
        try (ResultSet rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getLong(1);
        }
    }
}
