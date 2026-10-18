package com.auditlog.verify;

import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.core.crypto.PayloadCommitments;
import com.auditlog.core.crypto.PayloadCommitments.PayloadLeaf;
import com.auditlog.core.crypto.V1Hashes;
import com.auditlog.store.AuditRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Full-chain verifier. One read snapshot is scanned in ordered batches; memory is bounded by
 * the batch size, at most {@value #MAX_DIAGNOSTICS} retained diagnostics and a private scratch
 * database that indexes validated authorization events.
 *
 * <p>Everything read from storage is treated as untrusted raw data: malformed values produce
 * {@link ViolationType#MALFORMED_RECORD} diagnostics and never an exception.
 */
public final class LedgerVerifier {

    public static final int BATCH_SIZE = 1000;
    public static final int MAX_DIAGNOSTICS = 100;
    public static final String HASH_ALGORITHM = "SHA-256";

    private static final int MAX_LEAVES_PER_RECORD = PayloadCommitments.MAX_SCALAR_LEAVES;
    private static final long MAX_SAFE_INTEGER = 9_007_199_254_740_991L;
    private static final long MAX_RETENTION_DAYS = 500_000L;
    private static final Pattern HASH = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern KEY_ID = Pattern.compile("[0-9a-f]{16}");
    private static final Pattern TIMESTAMP =
            Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{6}Z");
    private static final Pattern POINTER = Pattern.compile("(/([^~/]|~[01])*)*");
    private static final DateTimeFormatter UTC_MICROS =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'").withZone(ZoneOffset.UTC);

    static final String REDACTED_TYPE = "RECORD_REDACTED";
    static final String ARCHIVED_TYPE = "RECORDS_ARCHIVED";
    private static final Set<String> RESERVED_TYPES = Set.of(
            REDACTED_TYPE, ARCHIVED_TYPE, "BUNDLE_EXPORTED", "COMPLIANCE_REPORT_GENERATED");
    private static final String SYSTEM_SOURCE = "system";
    private static final Set<String> REDACTION_KEYS = Set.of(
            "targetSeq", "targetEventId", "paths", "reason", "ticketId", "requestedBy");
    private static final Set<String> ARCHIVE_KEYS = Set.of(
            "archivedThroughSeq", "fromSeq", "toSeq", "count", "cutoff", "retentionDays",
            "lastArchivedChainHash", "archiveFile", "archiveSha256", "archiveBundleId",
            "requestedBy");

    private static final String EVENT_COLUMNS = """
            seq, event_id, event_type, actor_id, resource_type, resource_id, occurred_at,
            recorded_at, source, payload_commitments, hash_version, content_hash, prev_hash,
            chain_hash, archived, archived_at""";

    private final AuditRepository repository;
    private final String ledgerId;
    private final String publicKeyBase64;
    private final Clock clock;
    private final int batchSize;

    public LedgerVerifier(
            AuditRepository repository, String ledgerId, String publicKeyBase64, Clock clock) {
        this(repository, ledgerId, publicKeyBase64, clock, BATCH_SIZE);
    }

    LedgerVerifier(
            AuditRepository repository,
            String ledgerId,
            String publicKeyBase64,
            Clock clock,
            int batchSize) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.ledgerId = Objects.requireNonNull(ledgerId, "ledgerId");
        this.publicKeyBase64 = Objects.requireNonNull(publicKeyBase64, "publicKeyBase64");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (batchSize < 1) {
            throw new IllegalArgumentException("batchSize must be positive");
        }
        this.batchSize = batchSize;
    }

    public VerificationReport verify() throws SQLException {
        long started = System.nanoTime();
        Instant verifiedAt = clock.instant();
        return repository.readSnapshot(connection -> {
            try (Scan scan = new Scan(connection)) {
                return scan.run(started, verifiedAt);
            }
        });
    }

    private record RawEvent(
            long seq,
            Object eventId,
            Object eventType,
            Object actorId,
            Object resourceType,
            Object resourceId,
            Object occurredAt,
            Object recordedAt,
            Object source,
            Object commitments,
            Object hashVersion,
            Object contentHash,
            Object prevHash,
            Object chainHash,
            Object archived,
            Object archivedAt) {
    }

    private record Inspection(boolean archived, Authorization authorization) {
    }

    private sealed interface Authorization permits RedactionGrant, ArchiveGrant {
    }

    private record RedactionGrant(long targetSeq, List<String> paths) implements Authorization {
    }

    private record ArchiveGrant(long throughSeq) implements Authorization {
    }

    private record Skeleton(Object eventId, Object chainHash, Object recordedAt) {
    }

    private record StoredLeaf(String pointer, byte[] salt, Object value, boolean valid) {
    }

    private static final class InvalidAuthorization extends RuntimeException {
        private InvalidAuthorization(String message) {
            super(message);
        }
    }

    private final class Scan implements AutoCloseable {

        private final Connection db;
        private final Connection scratch;
        private final Diagnostics diagnostics = new Diagnostics();
        private final List<AutoCloseable> resources = new ArrayList<>();
        private final PreparedStatement leafQuery;
        private final PreparedStatement skeletonQuery;
        private final PreparedStatement redactionLookup;
        private final PreparedStatement archiveLookup;
        private final PreparedStatement redactionInsert;
        private final PreparedStatement archiveInsert;

        private long checkedRecords;
        private long archivedRecords;
        private long redactedFields;
        private long headSeq;
        private String headHash = V1Hashes.genesisHash(ledgerId);
        private long checkpointsVerified;

        private Scan(Connection db) throws SQLException {
            this.db = db;
            this.scratch = DriverManager.getConnection("jdbc:sqlite:");
            resources.add(scratch);
            scratch.setAutoCommit(false);
            try (Statement statement = scratch.createStatement()) {
                statement.execute("""
                        CREATE TABLE redactions(
                            target_seq INTEGER NOT NULL, pointer TEXT NOT NULL,
                            PRIMARY KEY(target_seq, pointer)) WITHOUT ROWID""");
                statement.execute("""
                        CREATE TABLE archives(
                            event_seq INTEGER PRIMARY KEY, through_seq INTEGER NOT NULL)""");
            }
            leafQuery = prepare(db, "SELECT pointer, salt, value FROM payload_leaves "
                    + "WHERE seq = ? ORDER BY pointer LIMIT " + (MAX_LEAVES_PER_RECORD + 1));
            skeletonQuery = prepare(db,
                    "SELECT event_id, chain_hash, recorded_at FROM audit_events WHERE seq = ?");
            redactionLookup = prepare(scratch,
                    "SELECT 1 FROM redactions WHERE target_seq = ? AND pointer = ?");
            archiveLookup = prepare(scratch,
                    "SELECT 1 FROM archives WHERE event_seq > ? AND through_seq >= ? LIMIT 1");
            redactionInsert = prepare(scratch,
                    "INSERT OR IGNORE INTO redactions(target_seq, pointer) VALUES (?, ?)");
            archiveInsert = prepare(scratch,
                    "INSERT OR REPLACE INTO archives(event_seq, through_seq) VALUES (?, ?)");
        }

        private PreparedStatement prepare(Connection connection, String sql) throws SQLException {
            PreparedStatement statement = connection.prepareStatement(sql);
            resources.add(0, statement);
            return statement;
        }

        @Override
        public void close() throws SQLException {
            SQLException failure = null;
            for (AutoCloseable resource : resources) {
                try {
                    resource.close();
                } catch (Exception exception) {
                    if (failure == null) {
                        failure = new SQLException("Unable to release verification resources", exception);
                    }
                }
            }
            if (failure != null) {
                throw failure;
            }
        }

        private VerificationReport run(long started, Instant verifiedAt) throws SQLException {
            checkLedgerMetadata();
            buildAuthorizationIndex();
            scanEvents();
            verifyCheckpoints();
            detectOrphanLeaves();
            List<Violation> kept = diagnostics.retained();
            return new VerificationReport(
                    diagnostics.total() == 0,
                    ledgerId,
                    HASH_ALGORITHM,
                    checkedRecords,
                    archivedRecords,
                    redactedFields,
                    headSeq,
                    headHash,
                    checkpointsVerified,
                    kept.isEmpty() ? null : kept.get(0),
                    kept,
                    diagnostics.total(),
                    diagnostics.total() > kept.size(),
                    UTC_MICROS.format(verifiedAt.truncatedTo(ChronoUnit.MICROS)),
                    (System.nanoTime() - started) / 1_000_000L);
        }

        private void checkLedgerMetadata() throws SQLException {
            int rows = 0;
            boolean matches = false;
            try (Statement statement = db.createStatement();
                    ResultSet result = statement.executeQuery(
                            "SELECT ledger_id, schema_version FROM ledger_meta")) {
                while (result.next()) {
                    rows++;
                    matches = ledgerId.equals(result.getObject(1))
                            && Long.valueOf(1).equals(asLong(result.getObject(2)));
                }
            }
            if (rows != 1 || !matches) {
                violate(true, ViolationType.MALFORMED_RECORD, null, null,
                        "ledger metadata is missing, duplicated or bound to a different ledger");
            }
        }

        private void buildAuthorizationIndex() throws SQLException {
            for (String type : List.of(REDACTED_TYPE, ARCHIVED_TYPE)) {
                long after = Long.MIN_VALUE;
                while (true) {
                    List<RawEvent> batch = readBatch(
                            "WHERE event_type = ? AND archived = 0 AND seq > ?", type, after);
                    for (RawEvent event : batch) {
                        after = event.seq();
                        Inspection inspection = safeInspect(event, false);
                        grant(event.seq(), inspection.authorization());
                    }
                    if (batch.size() < batchSize) {
                        break;
                    }
                }
            }
            scratch.commit();
        }

        private void grant(long eventSeq, Authorization authorization) throws SQLException {
            if (authorization instanceof RedactionGrant redaction) {
                for (String path : redaction.paths()) {
                    redactionInsert.setLong(1, redaction.targetSeq());
                    redactionInsert.setString(2, path);
                    redactionInsert.executeUpdate();
                }
            } else if (authorization instanceof ArchiveGrant archive) {
                archiveInsert.setLong(1, eventSeq);
                archiveInsert.setLong(2, archive.throughSeq());
                archiveInsert.executeUpdate();
            }
        }

        private void scanEvents() throws SQLException {
            long previousSeq = 0;
            boolean haveRecord = false;
            String previousChain = null;
            Instant previousRecorded = null;
            long after = Long.MIN_VALUE;
            while (true) {
                List<RawEvent> batch = readBatch("WHERE seq > ?", null, after);
                for (RawEvent event : batch) {
                    long seq = event.seq();
                    after = seq;
                    checkedRecords++;
                    Inspection inspection = safeInspect(event, true);
                    if (inspection.archived()) {
                        archivedRecords++;
                        if (!archiveGranted(seq)) {
                            violate(true, ViolationType.UNAUTHORIZED_ARCHIVE, seq, null,
                                    "archived record has no validated archive authorization");
                        }
                    }

                    long expected = previousSeq + 1;
                    if (seq != expected) {
                        violate(true, ViolationType.SEQUENCE_GAP, seq, null,
                                "expected sequence " + expected + " but found " + seq);
                    }
                    String prev = hash(event.prevHash());
                    String chain = hash(event.chainHash());
                    if (prev != null) {
                        if (!haveRecord && seq == 1) {
                            if (!prev.equals(V1Hashes.genesisHash(ledgerId))) {
                                violate(true, ViolationType.GENESIS_MISMATCH, seq, null,
                                        "first record does not link to the ledger genesis hash");
                            }
                        } else if (haveRecord && previousChain != null && !prev.equals(previousChain)) {
                            violate(true, ViolationType.CHAIN_LINK_BROKEN, seq, null,
                                    "previous hash does not match the stored hash of sequence "
                                            + previousSeq);
                        }
                    }
                    Instant recorded = parseTimestamp(event.recordedAt());
                    if (recorded != null && previousRecorded != null && recorded.isBefore(previousRecorded)) {
                        violate(true, ViolationType.MALFORMED_RECORD, seq, null,
                                "recordedAt moves backwards");
                    }
                    if (recorded != null) {
                        previousRecorded = recorded;
                    }
                    previousSeq = seq;
                    previousChain = chain;
                    haveRecord = true;
                    headSeq = seq;
                    headHash = chain;
                }
                if (batch.size() < batchSize) {
                    break;
                }
            }
        }

        private List<RawEvent> readBatch(String where, String type, long after) throws SQLException {
            String sql = "SELECT " + EVENT_COLUMNS + " FROM audit_events " + where
                    + " ORDER BY seq LIMIT ?";
            List<RawEvent> batch = new ArrayList<>(Math.min(batchSize, 1024));
            try (PreparedStatement statement = db.prepareStatement(sql)) {
                int index = 1;
                if (type != null) {
                    statement.setString(index++, type);
                }
                statement.setLong(index++, after);
                statement.setInt(index, batchSize);
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        batch.add(new RawEvent(
                                result.getLong(1), result.getObject(2), result.getObject(3),
                                result.getObject(4), result.getObject(5), result.getObject(6),
                                result.getObject(7), result.getObject(8), result.getObject(9),
                                result.getObject(10), result.getObject(11), result.getObject(12),
                                result.getObject(13), result.getObject(14), result.getObject(15),
                                result.getObject(16)));
                    }
                }
            }
            return batch;
        }

        private Inspection safeInspect(RawEvent event, boolean report) {
            try {
                return inspect(event, report);
            } catch (RuntimeException | SQLException exception) {
                violate(report, ViolationType.MALFORMED_RECORD, event.seq(), null,
                        "record could not be validated");
                return new Inspection(Long.valueOf(1).equals(asLong(event.archived())), null);
            }
        }

        private Inspection inspect(RawEvent e, boolean report) throws SQLException {
            long seq = e.seq();
            boolean sound = true;
            Long archivedFlag = asLong(e.archived());
            boolean archived = Long.valueOf(1).equals(archivedFlag);
            if (archivedFlag == null || (archivedFlag != 0 && archivedFlag != 1)) {
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "archived flag must be 0 or 1");
                sound = false;
            }

            String contentHash = hash(e.contentHash());
            String prevHash = hash(e.prevHash());
            String chainHash = hash(e.chainHash());
            boolean hashesValid = contentHash != null && prevHash != null && chainHash != null;
            if (!hashesValid) {
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "stored hashes must be lowercase 64-character hexadecimal");
                sound = false;
            }
            Long version = asLong(e.hashVersion());
            boolean supportedVersion = Long.valueOf(V1Hashes.HASH_VERSION).equals(version);
            if (!supportedVersion) {
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "unsupported or invalid hash version");
                sound = false;
            }
            if (parseTimestamp(e.recordedAt()) == null) {
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "recordedAt is not a valid UTC microsecond timestamp");
                sound = false;
            }
            if (hashesValid && supportedVersion
                    && !V1Hashes.chainHash(prevHash, contentHash).equals(chainHash)) {
                violate(report, ViolationType.CHAIN_HASH_MISMATCH, seq, null,
                        "stored chain hash does not match its previous and content hashes");
                sound = false;
            }

            if (archived) {
                inspectSkeleton(e, report);
                return new Inspection(true, null);
            }
            if (archivedFlag != null && e.archivedAt() != null) {
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "live record carries an archive timestamp");
                sound = false;
            }

            String eventId = text(e.eventId());
            String eventType = text(e.eventType());
            String actorId = text(e.actorId());
            String resourceType = text(e.resourceType());
            String resourceId = text(e.resourceId());
            String source = text(e.source());
            if (eventId == null || eventType == null || actorId == null || resourceType == null
                    || resourceId == null || source == null || !(e.commitments() instanceof String)) {
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "live record is missing required text fields");
                return new Inspection(false, null);
            }
            boolean systemSource = SYSTEM_SOURCE.equals(source);
            if (systemSource != RESERVED_TYPES.contains(eventType)) {
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "system source and reserved event types must be used together");
                sound = false;
            }
            String occurredAt = null;
            if (e.occurredAt() != null) {
                if (parseTimestamp(e.occurredAt()) == null) {
                    violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                            "occurredAt is not a valid UTC microsecond timestamp");
                    sound = false;
                } else {
                    occurredAt = (String) e.occurredAt();
                }
            }

            Map<String, Object> commitments;
            try {
                JsonNode tree = CanonicalJson.parse(
                        ((String) e.commitments()).getBytes(StandardCharsets.UTF_8));
                if (!tree.isObject()) {
                    throw new IllegalArgumentException("not an object");
                }
                commitments = objectValue(tree);
            } catch (IllegalArgumentException exception) {
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "payload commitment tree is not a valid JSON object");
                return new Inspection(false, null);
            }
            if (!supportedVersion) {
                return new Inspection(false, null);
            }

            Map<String, String> expected;
            try {
                String recordedAt = (String) e.recordedAt();
                String computed = V1Hashes.contentHash(V1Hashes.contentObject(
                        seq, eventId, eventType, actorId, resourceType, resourceId,
                        occurredAt, recordedAt, source, commitments));
                if (contentHash != null && !computed.equals(contentHash)) {
                    violate(report, ViolationType.CONTENT_HASH_MISMATCH, seq, null,
                            "recomputed content hash does not match the stored content hash");
                    sound = false;
                }
                expected = commitmentLeaves(commitments);
            } catch (IllegalArgumentException exception) {
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "record cannot be canonicalized as a hash version 1 record");
                return new Inspection(false, null);
            }

            Map<String, PayloadLeaf> leaves = new LinkedHashMap<>();
            Set<String> storedPointers = new LinkedHashSet<>();
            sound &= loadLeaves(seq, report, leaves, storedPointers);
            List<String> missing = new ArrayList<>();
            for (Map.Entry<String, String> entry : expected.entrySet()) {
                String pointer = entry.getKey();
                PayloadLeaf leaf = leaves.get(pointer);
                if (leaf == null) {
                    if (!storedPointers.contains(pointer)) {
                        missing.add(pointer);
                    }
                } else if (!leafMatches(leaf, pointer, entry.getValue())) {
                    violate(report, ViolationType.PAYLOAD_VALUE_MISMATCH, seq, pointer,
                            "stored leaf does not match its commitment");
                    sound = false;
                }
            }
            for (String pointer : storedPointers) {
                if (!expected.containsKey(pointer)) {
                    violate(report, ViolationType.MALFORMED_RECORD, seq, pointer,
                            "stored leaf is not part of the commitment tree");
                    sound = false;
                }
            }
            for (String pointer : missing) {
                if (!systemSource && redactionGranted(seq, pointer)) {
                    if (report) {
                        redactedFields++;
                    }
                } else {
                    violate(report, ViolationType.UNAUTHORIZED_REDACTION, seq, pointer,
                            "leaf is absent without a validated redaction authorization");
                    sound = false;
                }
            }

            Authorization authorization = null;
            if (sound && systemSource && missing.isEmpty()
                    && (REDACTED_TYPE.equals(eventType) || ARCHIVED_TYPE.equals(eventType))) {
                authorization = parseAuthorization(
                        e, eventType, commitments, leaves, parseTimestamp(e.recordedAt()), report);
            }
            return new Inspection(false, authorization);
        }

        private void inspectSkeleton(RawEvent e, boolean report) throws SQLException {
            long seq = e.seq();
            if (e.eventType() != null || e.actorId() != null || e.resourceType() != null
                    || e.resourceId() != null || e.occurredAt() != null || e.source() != null
                    || e.commitments() != null) {
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "archived record retains business columns");
            }
            if (parseInstant(e.archivedAt()) == null) {
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "archived record has no valid archive timestamp");
            }
            leafQuery.setLong(1, seq);
            try (ResultSet result = leafQuery.executeQuery()) {
                if (result.next()) {
                    violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                            "archived record retains payload leaves");
                }
            }
        }

        private boolean loadLeaves(
                long seq,
                boolean report,
                Map<String, PayloadLeaf> leaves,
                Set<String> storedPointers) throws SQLException {
            boolean sound = true;
            leafQuery.setLong(1, seq);
            try (ResultSet result = leafQuery.executeQuery()) {
                int count = 0;
                while (result.next()) {
                    if (++count > MAX_LEAVES_PER_RECORD) {
                        violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                                "record stores more payload leaves than the protocol allows");
                        return false;
                    }
                    StoredLeaf leaf = readLeaf(result);
                    if (leaf.pointer() == null || !leaf.valid()) {
                        violate(report, ViolationType.MALFORMED_RECORD, seq, leaf.pointer(),
                                "stored payload leaf is malformed");
                        sound = false;
                        if (leaf.pointer() != null) {
                            storedPointers.add(leaf.pointer());
                        }
                        continue;
                    }
                    storedPointers.add(leaf.pointer());
                    leaves.put(leaf.pointer(), new PayloadLeaf(leaf.salt(), leaf.value()));
                }
            }
            return sound;
        }

        private StoredLeaf readLeaf(ResultSet result) throws SQLException {
            Object pointerValue = result.getObject(1);
            Object saltValue = result.getObject(2);
            Object value = result.getObject(3);
            String pointer = pointerValue instanceof String text ? text : null;
            byte[] salt = null;
            if (saltValue instanceof String text && HASH.matcher(text).matches()) {
                salt = HexFormat.of().parseHex(text);
            }
            Object parsedValue = null;
            boolean valid = pointer != null && salt != null && POINTER.matcher(pointer).matches()
                    && value instanceof String;
            if (valid) {
                try {
                    JsonNode node = CanonicalJson.parse(((String) value).getBytes(StandardCharsets.UTF_8));
                    if (node.isContainerNode()) {
                        valid = false;
                    } else {
                        parsedValue = jsonValue(node);
                    }
                } catch (IllegalArgumentException exception) {
                    valid = false;
                }
            }
            return new StoredLeaf(pointer, salt, parsedValue, valid);
        }

        private boolean leafMatches(PayloadLeaf leaf, String pointer, String commitment) {
            try {
                return V1Hashes.leafHash(leaf.salt(), pointer, leaf.value()).equals(commitment);
            } catch (IllegalArgumentException exception) {
                return false;
            }
        }

        private Authorization parseAuthorization(
                RawEvent e,
                String eventType,
                Map<String, Object> commitments,
                Map<String, PayloadLeaf> leaves,
                Instant recordedAt,
                boolean report) throws SQLException {
            long seq = e.seq();
            try {
                Map<String, Object> payload = PayloadCommitments.reveal(commitments, leaves).payload();
                if (REDACTED_TYPE.equals(eventType)) {
                    return parseRedaction(payload, seq);
                }
                return parseArchive(payload, seq, recordedAt, report);
            } catch (InvalidAuthorization | IllegalArgumentException exception) {
                String detail = exception instanceof InvalidAuthorization
                        ? ": " + exception.getMessage() : "";
                violate(report, ViolationType.MALFORMED_RECORD, seq, null,
                        "authorization event payload is invalid" + detail);
                return null;
            }
        }

        private RedactionGrant parseRedaction(Map<String, Object> payload, long seq)
                throws SQLException {
            requireKeys(payload, REDACTION_KEYS);
            long targetSeq = positiveLong(payload.get("targetSeq"), "targetSeq");
            String targetEventId = requireText(payload.get("targetEventId"), "targetEventId");
            requireText(payload.get("reason"), "reason");
            requireText(payload.get("ticketId"), "ticketId");
            requireText(payload.get("requestedBy"), "requestedBy");
            if (targetSeq >= seq) {
                throw new InvalidAuthorization("target must precede the authorization");
            }
            if (!(payload.get("paths") instanceof List<?> paths) || paths.isEmpty()
                    || paths.size() > MAX_LEAVES_PER_RECORD) {
                throw new InvalidAuthorization("paths must be a bounded non-empty array");
            }
            List<String> exact = new ArrayList<>();
            for (Object path : paths) {
                if (!(path instanceof String pointer) || !POINTER.matcher(pointer).matches()) {
                    throw new InvalidAuthorization("paths must be RFC 6901 pointers");
                }
                exact.add(pointer);
            }
            Skeleton target = skeleton(targetSeq);
            if (target == null || !targetEventId.equals(target.eventId())) {
                throw new InvalidAuthorization("target does not match the ledger");
            }
            return new RedactionGrant(targetSeq, exact);
        }

        private ArchiveGrant parseArchive(
                Map<String, Object> payload, long seq, Instant recordedAt, boolean report)
                throws SQLException {
            requireKeys(payload, ARCHIVE_KEYS);
            long through = positiveLong(payload.get("archivedThroughSeq"), "archivedThroughSeq");
            long from = positiveLong(payload.get("fromSeq"), "fromSeq");
            long to = positiveLong(payload.get("toSeq"), "toSeq");
            long count = positiveLong(payload.get("count"), "count");
            long retentionDays = positiveLong(payload.get("retentionDays"), "retentionDays");
            Instant cutoff = parseInstant(payload.get("cutoff"));
            String lastHash = requireText(payload.get("lastArchivedChainHash"), "lastArchivedChainHash");
            String fileDigest = requireText(payload.get("archiveSha256"), "archiveSha256");
            requireText(payload.get("archiveFile"), "archiveFile");
            requireText(payload.get("archiveBundleId"), "archiveBundleId");
            requireText(payload.get("requestedBy"), "requestedBy");
            if (cutoff == null || retentionDays > MAX_RETENTION_DAYS
                    || !HASH.matcher(lastHash).matches() || !HASH.matcher(fileDigest).matches()) {
                throw new InvalidAuthorization("archive metadata has invalid values");
            }
            if (from > to || to >= seq || through != to || count != to - from + 1) {
                throw new InvalidAuthorization("archive range is inconsistent");
            }
            Skeleton last = skeleton(to);
            if (last == null || !lastHash.equals(last.chainHash())) {
                throw new InvalidAuthorization("archive end hash does not match the ledger");
            }
            Instant lastRecorded = parseTimestamp(last.recordedAt());
            boolean violation = recordedAt == null || lastRecorded == null
                    || cutoff.isAfter(recordedAt.minus(retentionDays, ChronoUnit.DAYS))
                    || !lastRecorded.isBefore(cutoff);
            if (violation) {
                violate(report, ViolationType.RETENTION_POLICY_VIOLATION, seq, null,
                        "archive cutoff violates the retention policy declared by the event");
            }
            return new ArchiveGrant(through);
        }

        private Skeleton skeleton(long seq) throws SQLException {
            skeletonQuery.setLong(1, seq);
            try (ResultSet result = skeletonQuery.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                return new Skeleton(result.getObject(1), result.getObject(2), result.getObject(3));
            }
        }

        private boolean redactionGranted(long seq, String pointer) throws SQLException {
            redactionLookup.setLong(1, seq);
            redactionLookup.setString(2, pointer);
            try (ResultSet result = redactionLookup.executeQuery()) {
                return result.next();
            }
        }

        private boolean archiveGranted(long seq) throws SQLException {
            archiveLookup.setLong(1, seq);
            archiveLookup.setLong(2, seq);
            try (ResultSet result = archiveLookup.executeQuery()) {
                return result.next();
            }
        }

        private void verifyCheckpoints() throws SQLException {
            long after = Long.MIN_VALUE;
            String sql = "SELECT id, seq, chain_hash, created_at, key_id, signature "
                    + "FROM checkpoints WHERE id > ? ORDER BY id LIMIT ?";
            while (true) {
                int rows = 0;
                try (PreparedStatement statement = db.prepareStatement(sql)) {
                    statement.setLong(1, after);
                    statement.setInt(2, batchSize);
                    try (ResultSet result = statement.executeQuery()) {
                        while (result.next()) {
                            rows++;
                            after = result.getLong(1);
                            checkCheckpoint(
                                    result.getObject(2), result.getObject(3), result.getObject(4),
                                    result.getObject(5), result.getObject(6));
                        }
                    }
                }
                if (rows < batchSize) {
                    break;
                }
            }
        }

        private void checkCheckpoint(
                Object seqValue, Object chainValue, Object createdValue, Object keyValue,
                Object signatureValue) throws SQLException {
            Long seq = asLong(seqValue);
            String chain = hash(chainValue);
            if (seq == null || seq <= 0 || seq > MAX_SAFE_INTEGER || chain == null
                    || parseTimestamp(createdValue) == null
                    || !(keyValue instanceof String key && KEY_ID.matcher(key).matches())
                    || !(signatureValue instanceof String signature)) {
                violate(true, ViolationType.MALFORMED_RECORD, seq != null && seq > 0 ? seq : null,
                        null, "checkpoint record is malformed");
                return;
            }
            Map<String, Object> message = new LinkedHashMap<>();
            message.put("type", "audit-checkpoint/v1");
            message.put("ledgerId", ledgerId);
            message.put("seq", seq);
            message.put("chainHash", chain);
            message.put("createdAt", createdValue);
            message.put("keyId", key);
            message.put("signature", signature);
            boolean valid;
            try {
                valid = CheckpointSigner.verifyCheckpoint(message, publicKeyBase64);
            } catch (IllegalArgumentException exception) {
                valid = false;
            }
            if (!valid) {
                violate(true, ViolationType.CHECKPOINT_SIGNATURE_INVALID, seq, null,
                        "checkpoint signature is invalid for the pinned key and ledger");
                return;
            }
            if (seq > headSeq) {
                violate(true, ViolationType.TRUNCATION_DETECTED, seq, null,
                        "a signed checkpoint covers sequences beyond the ledger head");
                return;
            }
            Skeleton stored = skeleton(seq);
            if (stored == null) {
                violate(true, ViolationType.CHECKPOINT_MISMATCH, seq, null,
                        "checkpointed sequence is missing from the ledger");
            } else if (!chain.equals(stored.chainHash())) {
                violate(true, ViolationType.CHECKPOINT_MISMATCH, seq, null,
                        "checkpoint chain hash differs from the stored chain hash");
            } else {
                checkpointsVerified++;
            }
        }

        private void detectOrphanLeaves() throws SQLException {
            try (Statement statement = db.createStatement();
                    ResultSet result = statement.executeQuery("""
                            SELECT DISTINCT l.seq FROM payload_leaves l
                            LEFT JOIN audit_events e ON e.seq = l.seq
                            WHERE e.seq IS NULL ORDER BY l.seq""")) {
                while (result.next()) {
                    Long seq = asLong(result.getObject(1));
                    violate(true, ViolationType.MALFORMED_RECORD, seq, null,
                            "payload leaves exist for a missing record");
                }
            }
        }

        private void violate(
                boolean report, ViolationType type, Long seq, String pointer, String message) {
            if (report) {
                diagnostics.add(type, seq, pointer, message);
            }
        }
    }

    private static final class Diagnostics {

        private record Entry(Violation violation, long order) {
        }

        private static final Comparator<Entry> ORDER = Comparator
                .comparing((Entry entry) -> entry.violation().seq() == null
                        ? Long.MAX_VALUE : entry.violation().seq())
                .thenComparing(entry -> entry.violation().type())
                .thenComparing(entry -> entry.violation().pointer() == null
                        ? "" : entry.violation().pointer())
                .thenComparing(entry -> entry.violation().message())
                .thenComparingLong(Entry::order);

        private final TreeSet<Entry> kept = new TreeSet<>(ORDER);
        private long total;
        private long order;

        void add(ViolationType type, Long seq, String pointer, String message) {
            total++;
            kept.add(new Entry(new Violation(type, seq, pointer, message), order++));
            if (kept.size() > MAX_DIAGNOSTICS) {
                kept.pollLast();
            }
        }

        long total() {
            return total;
        }

        List<Violation> retained() {
            return kept.stream().map(Entry::violation).toList();
        }
    }

    private static Map<String, String> commitmentLeaves(Map<String, Object> commitments) {
        Map<String, String> leaves = new LinkedHashMap<>();
        record Frame(Object value, String pointer) {
        }
        Deque<Frame> pending = new ArrayDeque<>();
        commitments.entrySet().forEach(entry ->
                pending.addLast(new Frame(entry.getValue(), "/" + escape(entry.getKey()))));
        while (!pending.isEmpty()) {
            Frame frame = pending.removeFirst();
            if (frame.value() instanceof Map<?, ?> object) {
                object.forEach((key, value) ->
                        pending.addLast(new Frame(value, frame.pointer() + "/" + escape((String) key))));
            } else if (frame.value() instanceof List<?> array) {
                for (int index = 0; index < array.size(); index++) {
                    pending.addLast(new Frame(array.get(index), frame.pointer() + "/" + index));
                }
            } else if (frame.value() instanceof String commitment) {
                leaves.put(frame.pointer(), commitment);
            } else {
                throw new IllegalArgumentException("commitment leaves must be strings");
            }
        }
        return leaves;
    }

    private static String escape(String token) {
        return token.replace("~", "~0").replace("/", "~1");
    }

    private static void requireKeys(Map<String, Object> payload, Set<String> keys) {
        if (!payload.keySet().equals(keys)) {
            throw new InvalidAuthorization("payload fields do not match the schema");
        }
    }

    private static String requireText(Object value, String field) {
        if (!(value instanceof String text) || text.isBlank() || text.length() > 4096) {
            throw new InvalidAuthorization(field + " must be a bounded non-blank string");
        }
        return text;
    }

    private static long positiveLong(Object value, String field) {
        long number;
        if (value instanceof BigInteger integer && integer.bitLength() < 63) {
            number = integer.longValue();
        } else if (value instanceof Long || value instanceof Integer) {
            number = ((Number) value).longValue();
        } else {
            throw new InvalidAuthorization(field + " must be an integer");
        }
        if (number <= 0 || number > MAX_SAFE_INTEGER) {
            throw new InvalidAuthorization(field + " must be a positive safe integer");
        }
        return number;
    }

    private static Long asLong(Object value) {
        return value instanceof Long || value instanceof Integer || value instanceof Short
                ? Long.valueOf(((Number) value).longValue()) : null;
    }

    private static String text(Object value) {
        return value instanceof String text && !text.isBlank() ? text : null;
    }

    private static String hash(Object value) {
        return value instanceof String text && HASH.matcher(text).matches() ? text : null;
    }

    private static Instant parseTimestamp(Object value) {
        if (!(value instanceof String text) || !TIMESTAMP.matcher(text).matches()) {
            return null;
        }
        return parseInstant(text);
    }

    private static Instant parseInstant(Object value) {
        if (!(value instanceof String text)) {
            return null;
        }
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException exception) {
            return null;
        }
    }

    private static Map<String, Object> objectValue(JsonNode node) {
        Map<String, Object> result = new LinkedHashMap<>();
        node.properties().forEach(entry -> result.put(entry.getKey(), jsonValue(entry.getValue())));
        return result;
    }

    private static Object jsonValue(JsonNode node) {
        if (node.isObject()) {
            return objectValue(node);
        }
        if (node.isArray()) {
            List<Object> values = new ArrayList<>();
            node.elements().forEachRemaining(child -> values.add(jsonValue(child)));
            return values;
        }
        if (node.isTextual()) {
            return node.textValue();
        }
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        if (node.isNull()) {
            return null;
        }
        if (node.isIntegralNumber()) {
            return node.bigIntegerValue();
        }
        if (node.isFloatingPointNumber()) {
            return node.doubleValue();
        }
        throw new IllegalArgumentException("unsupported JSON value");
    }
}
