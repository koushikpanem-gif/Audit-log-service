package com.auditlog.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JdbcAuditRepositoryTests {

    @TempDir
    Path tempDirectory;

    @Test
    void initializesVersionedLedgerSchemaAndReopensOnlyForBoundLedger() throws Exception {
        Path database = tempDirectory.resolve("ledger.db");
        JdbcAuditRepository repository = new JdbcAuditRepository(database, "ledger-one");
        JdbcAuditRepository reopened = new JdbcAuditRepository(database, "ledger-one");

        assertEquals(1, pragmaInt(database, "user_version"));
        assertEquals("ledger-one", reopened.readSnapshot(connection -> {
            try (var statement = connection.createStatement();
                    var result = statement.executeQuery(
                            "SELECT ledger_id FROM ledger_meta WHERE singleton = 1")) {
                assertTrue(result.next());
                return result.getString(1);
            }
        }));
        assertEquals(List.of(
                "audit_events",
                "checkpoints",
                "ledger_meta",
                "payload_leaves"), applicationTables(database));
        assertEquals(List.of(
                "idx_audit_events_actor_seq",
                "idx_audit_events_recorded_seq",
                "idx_audit_events_resource_seq",
                "idx_audit_events_type_seq"), eventIndexes(database));
        assertThrows(SQLException.class, () -> new JdbcAuditRepository(database, "ledger-two"));
        assertNotNull(repository);
    }

    @Test
    void refusesUnknownAndUnversionedSchemas() throws Exception {
        Path unknownVersionDb = tempDirectory.resolve("unknown-version.db");
        new JdbcAuditRepository(unknownVersionDb, "ledger");
        execute(unknownVersionDb, "PRAGMA user_version = 2");
        assertThrows(SQLException.class, () -> new JdbcAuditRepository(unknownVersionDb, "ledger"));

        Path unversionedDb = tempDirectory.resolve("unversioned.db");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + unversionedDb);
                Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE existing_table(value TEXT)");
        }
        assertThrows(SQLException.class, () -> new JdbcAuditRepository(unversionedDb, "ledger"));
    }

    @Test
    void configuresEveryConnectionAndRollsBackFailedWrites() throws Exception {
        JdbcAuditRepository repository = repository("rollback.db");
        RuntimeException failure = new IllegalStateException("test rollback");
        assertThrows(IllegalStateException.class, () -> repository.writeTransaction(connection -> {
            assertPragmas(connection, false);
            insertEvent(connection, 1, "event-1");
            throw failure;
        }));

        assertEquals(0, eventCount(repository));
        assertEquals(Integer.valueOf(1), repository.<Integer>readSnapshot(connection -> {
            assertPragmas(connection, true);
            return 1;
        }));
    }

    @Test
    void serializesWritersAndKeepsReadSnapshotStable() throws Exception {
        JdbcAuditRepository repository = repository("transactions.db");
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch firstWriterLocked = new CountDownLatch(1);
        CountDownLatch releaseFirstWriter = new CountDownLatch(1);
        CountDownLatch secondWriterStarted = new CountDownLatch(1);
        try {
            Future<?> first = executor.submit(() -> repository.writeTransaction(connection -> {
                insertEvent(connection, 1, "event-1");
                firstWriterLocked.countDown();
                await(releaseFirstWriter);
                return null;
            }));
            assertTrue(firstWriterLocked.await(5, TimeUnit.SECONDS));

            Future<?> second = executor.submit(() -> {
                secondWriterStarted.countDown();
                return repository.writeTransaction(connection -> {
                    insertEvent(connection, 2, "event-2");
                    return null;
                });
            });
            assertTrue(secondWriterStarted.await(5, TimeUnit.SECONDS));
            Thread.sleep(150);
            assertFalse(second.isDone(), "second BEGIN IMMEDIATE must wait for the first writer");
            releaseFirstWriter.countDown();
            first.get(5, TimeUnit.SECONDS);
            second.get(5, TimeUnit.SECONDS);
            assertEquals(2, eventCount(repository));

            CountDownLatch snapshotStarted = new CountDownLatch(1);
            CountDownLatch continueSnapshot = new CountDownLatch(1);
            Future<Integer> snapshot = executor.submit(() -> repository.readSnapshot(connection -> {
                int initialCount = eventCount(connection);
                snapshotStarted.countDown();
                await(continueSnapshot);
                return initialCount * 10 + eventCount(connection);
            }));
            assertTrue(snapshotStarted.await(5, TimeUnit.SECONDS));
            repository.writeTransaction(connection -> {
                insertEvent(connection, 3, "event-3");
                return null;
            });
            continueSnapshot.countDown();
            assertEquals(22, snapshot.get(5, TimeUnit.SECONDS));
            assertEquals(3, eventCount(repository));
        } finally {
            releaseFirstWriter.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void databaseTriggersProtectActualRowsAndAllowOnlyValidArchiveTransition()
            throws Exception {
        JdbcAuditRepository repository = repository("triggers.db");
        repository.writeTransaction(connection -> {
            insertEvent(connection, 1, "event-1");
            insertEvent(connection, 2, "event-2");
            insertEvent(connection, 3, "event-3");
            insertEvent(connection, 4, "event-4");
            insertLeaf(connection, 1, "/value");
            insertCheckpoint(connection, 1);
            return null;
        });

        assertTriggerRejects(repository, "DELETE FROM audit_events WHERE seq = 1");
        for (String update : List.of(
                "event_id = 'changed-event'",
                "event_type = 'CHANGED'",
                "recorded_at = '2025-02-01T00:00:00.000000Z'",
                "hash_version = 2",
                "content_hash = '" + "3".repeat(64) + "'",
                "prev_hash = '" + "4".repeat(64) + "'",
                "chain_hash = '" + "5".repeat(64) + "'")) {
            assertTriggerRejects(
                    repository, "UPDATE audit_events SET " + update + " WHERE seq = 1");
        }
        assertTriggerRejects(repository,
                "UPDATE audit_events SET archived = 1, archived_at = "
                        + "'2025-01-01T00:00:00.000000Z' WHERE seq = 3");
        assertTriggerRejects(repository, "UPDATE payload_leaves SET value = '2' WHERE seq = 1");
        assertTriggerRejects(repository, "UPDATE checkpoints SET signature = 'changed' WHERE id = 1");
        assertTriggerRejects(repository, "DELETE FROM checkpoints WHERE id = 1");

        repository.writeTransaction(connection -> {
            try (var statement = connection.createStatement()) {
                statement.executeUpdate("""
                        UPDATE audit_events
                        SET event_type = NULL, actor_id = NULL, resource_type = NULL,
                            resource_id = NULL, occurred_at = NULL, source = NULL,
                            payload_commitments = NULL, archived = 1,
                            archived_at = '2025-01-01T00:00:00.000000Z'
                        WHERE seq = 2
                        """);
            }
            return null;
        });
        assertTriggerRejects(repository, "UPDATE audit_events SET recorded_at = 'changed' WHERE seq = 2");
        assertTriggerRejects(repository, "DELETE FROM audit_events WHERE seq = 2");

        assertEquals(4, eventCount(repository));
        assertEquals(Integer.valueOf(1), repository.<Integer>readSnapshot(connection -> {
            try (var statement = connection.createStatement();
                    var result = statement.executeQuery(
                            "SELECT archived FROM audit_events WHERE seq = 2")) {
                assertTrue(result.next());
                return result.getInt(1);
            }
        }));
    }

    @Test
    void checksForeignKeysOnEveryConnection() throws Exception {
        JdbcAuditRepository repository = repository("foreign-keys.db");
        repository.writeTransaction(connection -> {
            insertEvent(connection, 1, "event-1");
            return null;
        });
        assertThrows(SQLException.class, () -> repository.writeTransaction(connection -> {
            insertLeaf(connection, 1, "/object", "{}");
            return null;
        }));
        assertThrows(SQLException.class, () -> repository.writeTransaction(connection -> {
            insertLeaf(connection, 1, "/invalid", "not-json");
            return null;
        }));
        assertThrows(SQLException.class, () -> repository.writeTransaction(connection -> {
            insertLeaf(connection, 99, "/orphan", "1");
            return null;
        }));
        assertEquals(Integer.valueOf(0), repository.<Integer>readSnapshot(connection -> {
            try (var statement = connection.createStatement();
                    var result = statement.executeQuery("SELECT COUNT(*) FROM payload_leaves")) {
                assertTrue(result.next());
                return result.getInt(1);
            }
        }));
    }

    private JdbcAuditRepository repository(String fileName) throws SQLException {
        return new JdbcAuditRepository(tempDirectory.resolve(fileName), "test-ledger");
    }

    private static void assertPragmas(Connection connection, boolean queryOnly) throws SQLException {
        assertEquals("wal", pragmaText(connection, "journal_mode").toLowerCase(java.util.Locale.ROOT));
        assertEquals(2, pragmaInt(connection, "synchronous"));
        assertEquals(1, pragmaInt(connection, "foreign_keys"));
        assertEquals(1, pragmaInt(connection, "secure_delete"));
        assertEquals(30_000, pragmaInt(connection, "busy_timeout"));
        assertEquals(queryOnly ? 1 : 0, pragmaInt(connection, "query_only"));
    }

    private static int pragmaInt(Path database, String name) throws SQLException {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database)) {
            return pragmaInt(connection, name);
        }
    }

    private static int pragmaInt(Connection connection, String name) throws SQLException {
        try (var statement = connection.createStatement();
                var result = statement.executeQuery("PRAGMA " + name)) {
            assertTrue(result.next());
            return result.getInt(1);
        }
    }

    private static String pragmaText(Connection connection, String name) throws SQLException {
        try (var statement = connection.createStatement();
                var result = statement.executeQuery("PRAGMA " + name)) {
            assertTrue(result.next());
            return result.getString(1);
        }
    }

    private static List<String> applicationTables(Path database) throws SQLException {
        List<String> tables = new ArrayList<>();
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
                var statement = connection.createStatement();
                var result = statement.executeQuery(
                        "SELECT name FROM sqlite_master WHERE type='table' "
                                + "AND name NOT LIKE 'sqlite_%' ORDER BY name")) {
            while (result.next()) {
                tables.add(result.getString(1));
            }
        }
        return tables;
    }

    private static List<String> eventIndexes(Path database) throws SQLException {
        List<String> indexes = new ArrayList<>();
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
                var statement = connection.createStatement();
                var result = statement.executeQuery("PRAGMA index_list('audit_events')")) {
            while (result.next()) {
                String name = result.getString("name");
                if (name.startsWith("idx_audit_events_")) {
                    indexes.add(name);
                }
            }
        }
        indexes.sort(String::compareTo);
        return indexes;
    }

    private static void execute(Path database, String sql) throws SQLException {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
                var statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static int eventCount(JdbcAuditRepository repository) throws SQLException {
        return repository.readSnapshot(JdbcAuditRepositoryTests::eventCount);
    }

    private static int eventCount(Connection connection) throws SQLException {
        try (var statement = connection.createStatement();
                var result = statement.executeQuery("SELECT COUNT(*) FROM audit_events")) {
            assertTrue(result.next());
            return result.getInt(1);
        }
    }

    private static void insertEvent(Connection connection, long seq, String eventId)
            throws SQLException {
        try (var statement = connection.prepareStatement("""
                INSERT INTO audit_events(
                    seq, event_id, event_type, actor_id, resource_type, resource_id,
                    occurred_at, recorded_at, source, payload_commitments, hash_version,
                    content_hash, prev_hash, chain_hash
                ) VALUES (?, ?, 'TEST_EVENT', 'actor-1', 'RESOURCE', 'resource-1',
                    NULL, '2025-01-01T00:00:00.000000Z', 'writer', '{}', 1,
                    ?, ?, ?)
                """)) {
            statement.setLong(1, seq);
            statement.setString(2, eventId);
            statement.setString(3, "1".repeat(64));
            statement.setString(4, "0".repeat(64));
            statement.setString(5, "2".repeat(64));
            assertEquals(1, statement.executeUpdate());
        }
    }

    private static void insertLeaf(Connection connection, long seq, String pointer)
            throws SQLException {
        insertLeaf(connection, seq, pointer, "1");
    }

    private static void insertLeaf(Connection connection, long seq, String pointer, String value)
            throws SQLException {
        try (var statement = connection.prepareStatement(
                "INSERT INTO payload_leaves(seq, pointer, salt, value) VALUES (?, ?, ?, ?)")) {
            statement.setLong(1, seq);
            statement.setString(2, pointer);
            statement.setString(3, "a".repeat(64));
            statement.setString(4, value);
            assertEquals(1, statement.executeUpdate());
        }
    }

    private static void insertCheckpoint(Connection connection, long seq) throws SQLException {
        try (var statement = connection.prepareStatement("""
                INSERT INTO checkpoints(seq, chain_hash, created_at, key_id, signature)
                VALUES (?, ?, '2025-01-01T00:00:00.000000Z', ?, 'c2lnbmF0dXJl')
                """)) {
            statement.setLong(1, seq);
            statement.setString(2, "2".repeat(64));
            statement.setString(3, "a".repeat(16));
            assertEquals(1, statement.executeUpdate());
        }
    }

    private static void assertTriggerRejects(JdbcAuditRepository repository, String sql)
            throws SQLException {
        assertThrows(SQLException.class, () -> repository.writeTransaction(connection -> {
            try (var statement = connection.createStatement()) {
                statement.executeUpdate(sql);
            }
            return null;
        }), sql);
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting for transaction test latch");
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted during transaction test", exception);
        }
    }
}
