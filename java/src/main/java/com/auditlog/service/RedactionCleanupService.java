package com.auditlog.service;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.domain.BundleSelection;
import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.store.JdbcAuditRepository.WalCheckpoint;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Durable cleanup of redacted plaintext. A redaction commits its deletions and a PENDING job in
 * one transaction; this service then drives {@code PRAGMA wal_checkpoint(TRUNCATE)} so that old
 * WAL frames holding the deleted values are discarded. A job is COMPLETE only when SQLite
 * reports busy=0 and a fully checkpointed log. Everything is persisted, so a crash or a held
 * reader leaves the job PENDING and {@link #runPending()} or {@link #recover()} finishes it.
 *
 * <p>This is logical cleanup of the live SQLite files only. Earlier exports, archive files,
 * backups, filesystem snapshots and storage-device remnants are out of scope.
 */
public final class RedactionCleanupService {

    public static final String PENDING = "PENDING";
    public static final String COMPLETE = "COMPLETE";

    private static final int MAX_STATUS_JOBS = 100;
    private static final long BACKOFF_MILLIS = 50;

    private final JdbcAuditRepository repository;
    private final int maxAttempts;
    private final int busyTimeoutMillis;
    private final Clock clock;

    public RedactionCleanupService(
            JdbcAuditRepository repository, AuditConfiguration configuration, Clock clock) {
        this.repository = Objects.requireNonNull(repository, "repository");
        Objects.requireNonNull(configuration, "configuration");
        this.maxAttempts = configuration.cleanupMaxAttempts();
        this.busyTimeoutMillis = configuration.cleanupBusyTimeoutMillis();
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Enqueues a PENDING job inside the redaction's own write transaction. */
    long enqueue(Connection connection, long redactionSeq, long targetSeq, int leafCount)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO redaction_cleanup(redaction_seq, target_seq, leaf_count, status, created_at)
                VALUES (?, ?, ?, 'PENDING', ?)
                """, Statement.RETURN_GENERATED_KEYS)) {
            statement.setLong(1, redactionSeq);
            statement.setLong(2, targetSeq);
            statement.setInt(3, leafCount);
            statement.setString(4, now());
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                if (!keys.next()) {
                    throw new SQLException("Cleanup job id was not generated");
                }
                return keys.getLong(1);
            }
        }
    }

    /** Result of one cleanup run. */
    public record Summary(String status, long pendingJobs, int attempts, String lastOutcome) { }

    /**
     * Makes finite checkpoint attempts for every job that was committed before this call. Never
     * throws for a busy database or a storage error; the jobs simply stay PENDING with the
     * outcome recorded.
     */
    public synchronized Summary runPending() {
        long upTo;
        try {
            upTo = repository.readSnapshot(connection -> maxPendingId(connection));
        } catch (SQLException exception) {
            return new Summary(PENDING, -1, 0, "ERROR");
        }
        if (upTo == 0) {
            return new Summary(COMPLETE, 0, 0, null);
        }

        int attempts = 0;
        String outcome = "ERROR";
        boolean done = false;
        while (attempts < maxAttempts && !done) {
            attempts++;
            try {
                WalCheckpoint checkpoint = repository.checkpointWalTruncate(busyTimeoutMillis);
                if (checkpoint.complete()) {
                    outcome = "OK";
                    done = true;
                } else {
                    outcome = checkpoint.busy() != 0 ? "BUSY" : "INCOMPLETE";
                }
            } catch (SQLException exception) {
                outcome = "ERROR";
            }
            if (!done && attempts < maxAttempts) {
                sleep(BACKOFF_MILLIS * attempts);
            }
        }

        int totalAttempts = attempts;
        String finalOutcome = outcome;
        boolean finished = done;
        try {
            repository.writeTransaction(connection -> {
                record(connection, upTo, totalAttempts, finalOutcome, finished);
                return null;
            });
        } catch (SQLException exception) {
            // The checkpoint result is not lost: an unrecorded success is repeated on the next run.
            return new Summary(PENDING, -1, attempts, outcome);
        }
        long remaining;
        try {
            remaining = repository.readSnapshot(connection -> pendingCount(connection));
        } catch (SQLException exception) {
            remaining = -1;
        }
        return new Summary(remaining == 0 ? COMPLETE : PENDING, remaining, attempts, outcome);
    }

    /** Called at start-up: finishes any cleanup interrupted by a crash or a held reader. */
    public Summary recover() {
        return runPending();
    }

    /** Admin status: counts plus the newest jobs. Contains no payload values. */
    public Map<String, Object> status(int limit) throws SQLException {
        int bounded = Math.max(1, Math.min(limit, MAX_STATUS_JOBS));
        return repository.readSnapshot(connection -> {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("pendingJobs", pendingCount(connection));
            result.put("completeJobs", count(connection, COMPLETE));
            List<Map<String, Object>> jobs = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT id, redaction_seq, target_seq, leaf_count, status, attempts,
                           created_at, last_attempt_at, completed_at, last_outcome
                    FROM redaction_cleanup ORDER BY id DESC LIMIT ?
                    """)) {
                statement.setInt(1, bounded);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        Map<String, Object> job = new LinkedHashMap<>();
                        job.put("id", rows.getLong("id"));
                        job.put("redactionSeq", rows.getLong("redaction_seq"));
                        job.put("targetSeq", rows.getLong("target_seq"));
                        job.put("leafCount", rows.getInt("leaf_count"));
                        job.put("status", rows.getString("status"));
                        job.put("attempts", rows.getInt("attempts"));
                        job.put("createdAt", rows.getString("created_at"));
                        job.put("lastAttemptAt", rows.getString("last_attempt_at"));
                        job.put("completedAt", rows.getString("completed_at"));
                        job.put("lastOutcome", rows.getString("last_outcome"));
                        jobs.add(job);
                    }
                }
            }
            result.put("jobs", jobs);
            result.put("limitations", LIMITATIONS);
            return result;
        });
    }

    public static final String LIMITATIONS =
            "COMPLETE means the live SQLite WAL was checkpointed and truncated after the deletion. "
                    + "It is not a guarantee of physical erasure and does not cover earlier exports, "
                    + "archive files, backups, filesystem snapshots or storage-device remnants.";

    private void record(Connection connection, long upTo, int attempts, String outcome, boolean complete)
            throws SQLException {
        String now = now();
        String sql = complete
                ? """
                UPDATE redaction_cleanup
                SET status = 'COMPLETE', attempts = attempts + ?, last_attempt_at = ?,
                    completed_at = ?, last_outcome = ?
                WHERE status = 'PENDING' AND id <= ?
                """
                : """
                UPDATE redaction_cleanup
                SET attempts = attempts + ?, last_attempt_at = ?, last_outcome = ?
                WHERE status = 'PENDING' AND id <= ?
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            int index = 1;
            statement.setInt(index++, attempts);
            statement.setString(index++, now);
            if (complete) {
                statement.setString(index++, now);
            }
            statement.setString(index++, outcome);
            statement.setLong(index, upTo);
            statement.executeUpdate();
        }
    }

    private static long maxPendingId(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery(
                        "SELECT COALESCE(MAX(id), 0) FROM redaction_cleanup WHERE status = 'PENDING'")) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static long pendingCount(Connection connection) throws SQLException {
        return count(connection, PENDING);
    }

    private static long count(Connection connection, String status) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*) FROM redaction_cleanup WHERE status = ?")) {
            statement.setString(1, status);
            try (ResultSet rows = statement.executeQuery()) {
                rows.next();
                return rows.getLong(1);
            }
        }
    }

    private String now() {
        return BundleSelection.normalizeTimestamp(
                clock.instant().truncatedTo(ChronoUnit.MICROS).toString());
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }
}
