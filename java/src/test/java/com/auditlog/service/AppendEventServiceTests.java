package com.auditlog.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.AppendEventRequest;
import com.auditlog.store.JdbcAuditRepository;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AppendEventServiceTests {

    private static final String LEDGER_ID = "append-test-ledger";
    private static final Instant START = Instant.parse("2026-01-02T03:04:05.123456Z");

    @TempDir
    Path directory;

    private JdbcAuditRepository repository;
    private MutableClock clock;
    private AtomicInteger ids;
    private AtomicInteger salts;
    private CheckpointSigner signer;

    @BeforeEach
    void setUp() throws Exception {
        repository = new JdbcAuditRepository(directory.resolve("audit.db"), LEDGER_ID);
        clock = new MutableClock(START);
        ids = new AtomicInteger();
        salts = new AtomicInteger();
        signer = CheckpointSigner.fromFiles(
                directory.resolve("keys/private.pem"),
                directory.resolve("keys/public.b64"),
                "dev");
    }

    @Test
    void serializesConcurrentWritersAndKeepsAContiguousChain() throws Exception {
        int writers = 20;
        var executor = Executors.newFixedThreadPool(writers);
        try {
            List<Callable<AppendedEvent>> calls = new ArrayList<>();
            for (int index = 0; index < writers; index++) {
                int writer = index;
                calls.add(() -> service(100).append(
                        request("EVENT", "actor-" + writer, Map.of("number", writer), null),
                        "writer-" + writer));
            }
            var futures = executor.invokeAll(calls);
            List<Long> sequences = new ArrayList<>();
            for (var future : futures) {
                sequences.add(future.get().seq());
            }
            sequences.sort(Long::compareTo);
            assertEquals(java.util.stream.LongStream.rangeClosed(1, writers).boxed().toList(), sequences);

            repository.readSnapshot(connection -> {
                try (var statement = connection.createStatement();
                        var result = statement.executeQuery(
                                "SELECT seq, prev_hash, chain_hash FROM audit_events ORDER BY seq")) {
                    String previous = null;
                    long expectedSeq = 1;
                    while (result.next()) {
                        assertEquals(expectedSeq++, result.getLong("seq"));
                        if (previous != null) {
                            assertEquals(previous, result.getString("prev_hash"));
                        }
                        previous = result.getString("chain_hash");
                    }
                    assertEquals(writers + 1L, expectedSeq);
                }
                return null;
            });
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void recordedTimeNeverMovesBackwardsAndAllowsTies() throws Exception {
        AppendEventService service = service(100);
        AppendedEvent first = service.append(request("EVENT", "actor", Map.of(), null), "writer");
        clock.set(START.minusSeconds(30));
        AppendedEvent rollback = service.append(request("EVENT", "actor", Map.of(), null), "writer");
        AppendedEvent tie = service.append(request("EVENT", "actor", Map.of(), null), "writer");

        assertEquals(first.timestamp(), rollback.timestamp());
        assertEquals(rollback.timestamp(), tie.timestamp());
        assertEquals(START, Instant.parse(tie.timestamp()));
    }

    @Test
    void rejectsOccurredAtBeyondFutureSkewWithoutWriting() throws Exception {
        AppendEventService service = service(100);
        var request = request("EVENT", "actor", Map.of(), "2026-01-02T03:09:06.123456Z");

        assertThrows(IllegalArgumentException.class, () -> service.append(request, "writer"));
        assertEquals(0, count("audit_events"));
    }

    @Test
    void acceptsEmptyPayloadAndPreservesExplicitNullLeaves() throws Exception {
        AppendEventService service = service(100);
        AppendedEvent empty = service.append(request("EMPTY", "actor", Map.of(), null), "writer");
        AppendedEvent withNull = service.append(
                request("NULL", "actor", java.util.Collections.singletonMap("x", null), null),
                "writer");

        assertTrue(empty.payloadCommitments().isEmpty());
        assertEquals(0, commitmentCount(empty.seq()));
        assertEquals(1, leafCount(withNull.seq()));
        assertEquals("null", leafValue(withNull.seq(), "/x"));
        assertEquals(64, leafSalt(withNull.seq(), "/x").length());
    }

    @Test
    void continuesSequenceAndPreviousHashAfterRepositoryRestart() throws Exception {
        AppendedEvent first = service(100).append(request("EVENT", "actor", Map.of("x", 1), null), "writer");
        JdbcAuditRepository reopened = new JdbcAuditRepository(directory.resolve("audit.db"), LEDGER_ID);
        AppendedEvent second = new AppendEventService(
                reopened, configuration(100), signer, clock, this::nextId, this::nextSalt)
                .append(request("EVENT", "actor", Map.of("x", 2), null), "writer");

        assertEquals(2, second.seq());
        assertEquals(first.chainHash(), second.prevHash());
    }

    @Test
    void signsCheckpointAtConfiguredInterval() throws Exception {
        AppendEventService service = service(2);
        service.append(request("EVENT", "actor", Map.of(), null), "writer");
        AppendedEvent second = service.append(request("EVENT", "actor", Map.of(), null), "writer");

        repository.readSnapshot(connection -> {
            try (var statement = connection.createStatement();
                    var result = statement.executeQuery("""
                            SELECT seq, chain_hash, created_at, key_id, signature
                            FROM checkpoints
                            """)) {
                assertTrue(result.next());
                long seq = result.getLong("seq");
                assertEquals(2, seq);
                assertEquals(second.chainHash(), result.getString("chain_hash"));
                assertTrue(CheckpointSigner.verifyCheckpoint(Map.of(
                        "type", "audit-checkpoint/v1",
                        "ledgerId", LEDGER_ID,
                        "seq", seq,
                        "chainHash", result.getString("chain_hash"),
                        "createdAt", result.getString("created_at"),
                        "keyId", result.getString("key_id"),
                        "signature", result.getString("signature")),
                        signer.publicKeyBase64()));
                assertFalse(result.next());
            }
            return null;
        });
    }

    @Test
    void rollsBackEventWhenLeafInsertionFails() throws Exception {
        execute("CREATE TRIGGER fail_leaf BEFORE INSERT ON payload_leaves "
                + "BEGIN SELECT RAISE(ABORT, 'injected leaf failure'); END");

        assertThrows(SQLException.class, () -> service(100).append(
                request("EVENT", "actor", Map.of("secret", "value"), null), "writer"));
        assertEquals(0, count("audit_events"));
        assertEquals(0, count("payload_leaves"));
    }

    @Test
    void rollsBackEventAndLeavesWhenIntervalCheckpointInsertionFails() throws Exception {
        execute("CREATE TRIGGER fail_checkpoint BEFORE INSERT ON checkpoints "
                + "BEGIN SELECT RAISE(ABORT, 'injected checkpoint failure'); END");

        assertThrows(SQLException.class, () -> service(1).append(
                request("EVENT", "actor", Map.of("secret", "value"), null), "writer"));
        assertEquals(0, count("audit_events"));
        assertEquals(0, count("payload_leaves"));
        assertEquals(0, count("checkpoints"));
    }

    @Test
    void rejectsCallerOwnedSourceTimestampAndReservedSystemEvents() throws Exception {
        AppendEventService service = service(100);

        assertThrows(IllegalArgumentException.class, () ->
                service.append(request("RECORD_REDACTED", "actor", Map.of(), null), "writer"));
        assertThrows(IllegalArgumentException.class, () ->
                service.append(request("EVENT", "actor", Map.of(), null), "system"));
        assertEquals(0, count("audit_events"));
    }

    @Test
    void rejectsUnknownJsonFieldsEvenWhenMapperIgnoresUnknownProperties() {
        ObjectMapper mapper = new ObjectMapper()
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        String envelope = """
                {"eventType":"EVENT","actorId":"actor","resourceType":"ACCOUNT",
                 "resourceId":"account-1","payload":{}}
                """;

        assertThrows(JsonMappingException.class, () ->
                mapper.readValue(envelope.replace("\"payload\":{}", "\"payload\":{},\"source\":\"body\""),
                        AppendEventRequest.class));
        assertThrows(JsonMappingException.class, () ->
                mapper.readValue(envelope.replace("\"payload\":{}", "\"payload\":{},\"timestamp\":\"body\""),
                        AppendEventRequest.class));
    }

    @Test
    void appliesConfiguredPayloadLimits() throws Exception {
        AuditConfiguration limited = AuditConfiguration.fromEnvironment(Map.of(
                "AUDIT_LEDGER_ID", LEDGER_ID,
                "AUDIT_PAYLOAD_LIMIT_BYTES", "8",
                "AUDIT_MAX_DEPTH", "1",
                "AUDIT_MAX_LEAVES", "1"));
        AppendEventService service = new AppendEventService(
                repository, limited, signer, clock, this::nextId, this::nextSalt);

        assertThrows(IllegalArgumentException.class, () ->
                service.append(request("EVENT", "actor", Map.of("long", "payload"), null), "writer"));
        assertThrows(IllegalArgumentException.class, () ->
                service.append(request("EVENT", "actor", Map.of("x", Map.of("y", 1)), null), "writer"));
        assertThrows(IllegalArgumentException.class, () ->
                service.append(request("EVENT", "actor", Map.of("x", 1, "y", 2), null), "writer"));
        assertEquals(0, count("audit_events"));
    }

    @Test
    void appliesConfiguredRequestLimit() throws Exception {
        AuditConfiguration limited = AuditConfiguration.fromEnvironment(Map.of(
                "AUDIT_LEDGER_ID", LEDGER_ID,
                "AUDIT_REQUEST_LIMIT_BYTES", "64",
                "AUDIT_PAYLOAD_LIMIT_BYTES", "32"));
        AppendEventService service = new AppendEventService(
                repository, limited, signer, clock, this::nextId, this::nextSalt);

        assertThrows(IllegalArgumentException.class, () ->
                service.append(request("EVENT", "actor", Map.of(), null), "writer"));
        assertEquals(0, count("audit_events"));
    }

    private AppendEventService service(int checkpointInterval) {
        return new AppendEventService(
                repository,
                configuration(checkpointInterval),
                signer,
                clock,
                this::nextId,
                this::nextSalt);
    }

    private AuditConfiguration configuration(int checkpointInterval) {
        return AuditConfiguration.fromEnvironment(Map.of(
                "AUDIT_LEDGER_ID", LEDGER_ID,
                "AUDIT_CHECKPOINT_INTERVAL", Integer.toString(checkpointInterval)));
    }

    private AppendEventRequest request(
            String type, String actor, Map<String, ?> payload, String occurredAt) {
        return new AppendEventRequest(type, actor, "ACCOUNT", "account-1", payload, occurredAt);
    }

    private UUID nextId() {
        return UUID.nameUUIDFromBytes(("event-" + ids.getAndIncrement()).getBytes(
                java.nio.charset.StandardCharsets.UTF_8));
    }

    private byte[] nextSalt() {
        byte[] salt = new byte[32];
        salt[0] = (byte) salts.getAndIncrement();
        return salt;
    }

    private int count(String table) throws SQLException {
        return repository.readSnapshot(connection -> {
            try (var statement = connection.createStatement();
                    var result = statement.executeQuery("SELECT COUNT(*) FROM " + table)) {
                result.next();
                return result.getInt(1);
            }

        });
    }

    private int commitmentCount(long seq) throws SQLException {
        return repository.readSnapshot(connection -> {
            try (var statement = connection.prepareStatement(
                    "SELECT payload_commitments FROM audit_events WHERE seq = ?")) {
                statement.setLong(1, seq);
                try (var result = statement.executeQuery()) {
                    result.next();
                    return CanonicalJson.parse(result.getString(1).getBytes(
                            java.nio.charset.StandardCharsets.UTF_8)).size();
                }
            }
        });
    }

    private int leafCount(long seq) throws SQLException {
        return repository.readSnapshot(connection -> {
            try (var statement = connection.prepareStatement(
                    "SELECT COUNT(*) FROM payload_leaves WHERE seq = ?")) {
                statement.setLong(1, seq);
                try (var result = statement.executeQuery()) {
                    result.next();
                    return result.getInt(1);
                }
            }
        });
    }

    private String leafValue(long seq, String pointer) throws SQLException {
        return leafColumn(seq, pointer, "value");
    }

    private String leafSalt(long seq, String pointer) throws SQLException {
        return leafColumn(seq, pointer, "salt");
    }

    private String leafColumn(long seq, String pointer, String column) throws SQLException {
        return repository.readSnapshot(connection -> {
            try (var statement = connection.prepareStatement(
                    "SELECT " + column + " FROM payload_leaves WHERE seq = ? AND pointer = ?")) {
                statement.setLong(1, seq);
                statement.setString(2, pointer);
                try (var result = statement.executeQuery()) {
                    result.next();
                    return result.getString(1);
                }
            }
        });
    }

    private void execute(String sql) throws SQLException {
        try (Connection connection = DriverManager.getConnection(
                    "jdbc:sqlite:" + directory.resolve("audit.db"));
                var statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static final class MutableClock extends Clock {

        private final AtomicReference<Instant> current;

        private MutableClock(Instant initial) {
            current = new AtomicReference<>(initial);
        }

        private void set(Instant instant) {
            current.set(instant);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return current.get();
        }
    }

}
