package com.auditlog.service;

import com.auditlog.config.AuditConfiguration;
import com.auditlog.core.crypto.CanonicalJson;
import com.auditlog.core.crypto.CheckpointSigner;
import com.auditlog.domain.AccountAccessContract;
import com.auditlog.domain.BundlePurpose;
import com.auditlog.domain.BundleSelection;
import com.auditlog.store.AuditRepository;
import com.auditlog.verify.LedgerVerifier;
import com.auditlog.verify.VerificationReport;
import com.auditlog.verify.Violation;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * On-demand internal account-access report. In ONE write transaction it verifies the ledger,
 * selects retained-live ACCOUNT_DATA_ACCESS events up to the verified head, builds signed evidence,
 * and only then appends COMPLIANCE_REPORT_GENERATED and a checkpoint. A rejection anywhere rolls the
 * meta-event and checkpoint back. Verification of the whole ledger runs under the write lock, so
 * concurrent writers wait for it (documented trade-off).
 */
public final class AccountAccessReportService {

    public static final int REPORT_RECORD_CAP = 10_000;
    public static final String UNKNOWN_REDACTED = "UNKNOWN_REDACTED";
    public static final String UNKNOWN_INVALID = "UNKNOWN_INVALID";

    /** Test hook points, invoked inside the write transaction. */
    public enum Stage { AFTER_VERIFY, AFTER_SELECT }

    private final AuditRepository repository;
    private final AuditConfiguration configuration;
    private final CheckpointSigner signer;
    private final AppendEventService appendService;
    private final ExportBundleService bundleService;
    private final LedgerVerifier verifier;
    private final int recordCap;
    private final Consumer<Stage> hook;

    public AccountAccessReportService(
            AuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService,
            ExportBundleService bundleService,
            LedgerVerifier verifier) {
        this(repository, configuration, signer, appendService, bundleService, verifier,
                REPORT_RECORD_CAP, stage -> { });
    }

    public AccountAccessReportService(
            AuditRepository repository,
            AuditConfiguration configuration,
            CheckpointSigner signer,
            AppendEventService appendService,
            ExportBundleService bundleService,
            LedgerVerifier verifier,
            int recordCap,
            Consumer<Stage> hook) {
        if (recordCap < 1 || recordCap > REPORT_RECORD_CAP) {
            throw new IllegalArgumentException("Report record cap must be within 1.." + REPORT_RECORD_CAP);
        }
        this.repository = repository;
        this.configuration = configuration;
        this.signer = signer;
        this.appendService = appendService;
        this.bundleService = bundleService;
        this.verifier = verifier;
        this.recordCap = recordCap;
        this.hook = hook;
    }

    public Map<String, Object> generate(
            String accountId, String actorId, String from, String to, String requestedBy)
            throws SQLException {
        boolean hasAccount = accountId != null && !accountId.isBlank();
        boolean hasActor = actorId != null && !actorId.isBlank();
        if (hasAccount == hasActor) {
            throw new IllegalArgumentException("Exactly one of accountId or actorId is required");
        }
        if (from == null || from.isBlank() || to == null || to.isBlank()) {
            throw new IllegalArgumentException("Explicit from and to are required");
        }
        if (requestedBy == null || requestedBy.isBlank()) {
            throw new IllegalArgumentException("requestedBy is required");
        }
        BundleSelection selection = new BundleSelection(
                hasActor ? actorId : null,
                hasAccount ? AccountAccessContract.RESOURCE_TYPE : null,
                hasAccount ? accountId : null,
                AccountAccessContract.EVENT_TYPE,
                BundleSelection.normalizeTimestamp(from),
                BundleSelection.normalizeTimestamp(to),
                null, null);
        return repository.writeTransaction(connection ->
                generateLocked(connection, selection, hasAccount ? "ACCOUNT" : "ACTOR", requestedBy));
    }

    private Map<String, Object> generateLocked(
            Connection connection, BundleSelection selection, String subjectType, String requestedBy)
            throws SQLException {
        VerificationReport verification = verifier.verify(connection);
        long verifiedSeq = verification.headSeq();
        hook.accept(Stage.AFTER_VERIFY);

        List<Map<String, Object>> records = new ArrayList<>();
        try (PreparedStatement statement = ExportBundleService.prepareSelection(
                        connection, selection, verifiedSeq, (long) recordCap + 1);
                ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                if (records.size() >= recordCap) {
                    throw new ReportLimitExceededException(recordCap, "records");
                }
                records.add(ExportBundleService.readRecord(connection, result));
            }
        }
        hook.accept(Stage.AFTER_SELECT);

        byte[] recordsCanonical = CanonicalJson.canonicalize(
                records, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE);
        if (recordsCanonical.length > bundleService.maxBytes()) {
            throw new ReportLimitExceededException(bundleService.maxBytes(), "bytes");
        }
        String recordsDigest = sha256Hex(recordsCanonical);
        String reportId = UUID.randomUUID().toString();

        Map<String, Object> eventPayload = new LinkedHashMap<>();
        eventPayload.put("reportId", reportId);
        eventPayload.put("purpose", BundlePurpose.COMPLIANCE_REPORT.name());
        eventPayload.put("subjectType", subjectType);
        eventPayload.put("selectionDigest", sha256Hex(CanonicalJson.canonicalize(selection.toMap())));
        eventPayload.put("from", selection.from());
        eventPayload.put("to", selection.to());
        eventPayload.put("recordCount", records.size());
        eventPayload.put("recordsDigest", recordsDigest);
        eventPayload.put("verifiedDataHeadSeq", verifiedSeq);
        eventPayload.put("verifiedDataHeadHash", verification.headHash());
        eventPayload.put("integrityIntact", verification.intact());
        eventPayload.put("requestedBy", requestedBy);
        AppendedEvent event = appendService.appendSystemEvent(
                connection, "COMPLIANCE_REPORT_GENERATED", requestedBy, "COMPLIANCE_REPORT", reportId,
                eventPayload);
        Map<String, Object> checkpoint = appendService.storeCheckpoint(
                connection, event.seq(), event.chainHash(), event.timestamp());

        Map<String, Object> bundle = bundleService.signedBundle(
                BundlePurpose.COMPLIANCE_REPORT, reportId, selection, verifiedSeq, records, recordsDigest,
                event, checkpoint, requestedBy);
        int bundleBytes = CanonicalJson.canonicalize(
                bundle, CanonicalJson.MAX_DOCUMENT_DEPTH, Integer.MAX_VALUE).length;
        if (bundleBytes > bundleService.maxBytes()) {
            throw new ReportLimitExceededException(bundleService.maxBytes(), "bytes");
        }

        return buildReport(
                reportId, requestedBy, subjectType, selection, verification, records, event, checkpoint,
                bundle);
    }

    private Map<String, Object> buildReport(
            String reportId,
            String requestedBy,
            String subjectType,
            BundleSelection selection,
            VerificationReport verification,
            List<Map<String, Object>> records,
            AppendedEvent event,
            Map<String, Object> checkpoint,
            Map<String, Object> bundle) {
        Map<String, Map<String, Object>> groups = new TreeMap<>();
        Map<String, Long> byOutcome = new TreeMap<>();
        Map<String, Long> byPurpose = new TreeMap<>();
        Map<String, Long> byCategory = new TreeMap<>();
        Map<String, Long> byType = new TreeMap<>();
        Map<String, Long> byActor = new TreeMap<>();
        List<Map<String, Object>> exceptions = new ArrayList<>();
        long unknownRedacted = 0;

        for (Map<String, Object> record : records) {
            String actor = String.valueOf(record.get("actorId"));
            String category = dimension(record, "dataCategory", AccountAccessContract.DATA_CATEGORIES);
            String purpose = dimension(record, "accessPurpose", AccountAccessContract.ACCESS_PURPOSES);
            String outcome = dimension(record, "outcome", AccountAccessContract.OUTCOMES);
            String type = dimension(record, "accessType", AccountAccessContract.ACCESS_TYPES);

            List<String> reasons = new ArrayList<>();
            if ("DENIED".equals(outcome)) {
                reasons.add("DENIED");
            }
            if ("OTHER".equals(purpose)) {
                reasons.add("PURPOSE_OTHER");
            }
            boolean unknown = false;
            for (String value : List.of(category, purpose, outcome, type)) {
                if (value.startsWith("UNKNOWN_")) {
                    unknown = true;
                }
            }
            if (unknown) {
                reasons.add("UNKNOWN_GROUPING_FIELD");
                unknownRedacted++;
            }

            String key = String.join("|", actor, category, purpose, outcome, type);
            Map<String, Object> group = groups.computeIfAbsent(key, ignored -> {
                Map<String, Object> created = new LinkedHashMap<>();
                created.put("actorId", actor);
                created.put("dataCategory", category);
                created.put("accessPurpose", purpose);
                created.put("outcome", outcome);
                created.put("accessType", type);
                created.put("count", 0L);
                return created;
            });
            group.put("count", (Long) group.get("count") + 1);
            byOutcome.merge(outcome, 1L, Long::sum);
            byPurpose.merge(purpose, 1L, Long::sum);
            byCategory.merge(category, 1L, Long::sum);
            byType.merge(type, 1L, Long::sum);
            byActor.merge(actor, 1L, Long::sum);

            if (!reasons.isEmpty()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("seq", record.get("seq"));
                row.put("eventId", record.get("eventId"));
                row.put("timestamp", record.get("timestamp"));
                row.put("actorId", actor);
                row.put("accountId", record.get("resourceId"));
                row.put("dataCategory", category);
                row.put("accessType", type);
                row.put("accessPurpose", purpose);
                row.put("outcome", outcome);
                row.put("reasons", reasons);
                exceptions.add(row);
            }
        }

        Map<String, Object> scope = new LinkedHashMap<>();
        scope.put("subjectType", subjectType);
        scope.put("accountId", selection.resourceId());
        scope.put("actorId", selection.actorId());
        scope.put("eventType", AccountAccessContract.EVENT_TYPE);
        scope.put("from", selection.from());
        scope.put("to", selection.to());
        scope.put("periodBasis", "recordedAt, inclusive UTC");

        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("matchedEvents", (long) records.size());
        counts.put("unknownRedactedEvents", unknownRedacted);
        counts.put("exceptionRows", (long) exceptions.size());
        counts.put("byOutcome", byOutcome);
        counts.put("byAccessPurpose", byPurpose);
        counts.put("byDataCategory", byCategory);
        counts.put("byAccessType", byType);
        counts.put("byActor", byActor);

        Map<String, Object> verifiedHead = new LinkedHashMap<>();
        verifiedHead.put("seq", verification.headSeq());
        verifiedHead.put("chainHash", verification.headHash());
        verifiedHead.put("verifiedAt", verification.verifiedAt());

        Map<String, Object> postHead = new LinkedHashMap<>();
        postHead.put("seq", event.seq());
        postHead.put("chainHash", event.chainHash());
        postHead.put("createdAt", event.timestamp());
        postHead.put("checkpointKeyId", checkpoint.get("keyId"));
        postHead.put("checkpointSignature", checkpoint.get("signature"));
        postHead.put("reportEventId", event.eventId());

        List<Map<String, Object>> violations = new ArrayList<>();
        for (Violation violation : verification.violations()) {
            violations.add(violationMap(violation));
        }
        Map<String, Object> chain = new LinkedHashMap<>();
        chain.put("intact", verification.intact());
        chain.put("checkedRecords", verification.checkedRecords());
        chain.put("archivedRecords", verification.archivedRecords());
        chain.put("redactedFields", verification.redactedFields());
        chain.put("checkpointsVerified", verification.checkpointsVerified());
        chain.put("totalViolationCount", verification.totalViolationCount());
        chain.put("violationsTruncated", verification.violationsTruncated());
        chain.put("firstViolation",
                verification.firstViolation() == null ? null : violationMap(verification.firstViolation()));
        chain.put("violations", violations);

        List<String> exclusions = List.of(
                "ARCHIVED: events moved to retention archives are excluded; run the archive audit for them",
                "LIVE_ONLY: only retained-live events at or before the verified data head are reported",
                "UPSTREAM: events never received from upstream systems cannot be detected by this ledger",
                "NO_REGULATOR_PORTAL: internal auditor report only; not a legal opinion or regulator filing");

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("reportId", reportId);
        report.put("requestedBy", requestedBy);
        report.put("ledgerId", configuration.ledgerId());
        report.put("scope", scope);
        report.put("verifiedDataHead", verifiedHead);
        report.put("postReportHead", postHead);
        report.put("integrity", chain);
        report.put("trustworthy", verification.intact());
        report.put("trustLabel", verification.intact()
                ? "VERIFIED: ledger integrity checks passed at the verified data head"
                : "NOT TRUSTWORTHY: ledger integrity verification failed; the evidence signature does not "
                        + "repair an invalid ledger");
        report.put("counts", counts);
        report.put("groups", new ArrayList<>(groups.values()));
        report.put("exceptions", exceptions);
        report.put("exclusions", exclusions);
        report.put("recordCap", recordCap);
        report.put("evidence", bundle);
        return report;
    }

    private static Map<String, Object> violationMap(Violation violation) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", violation.type().name());
        map.put("seq", violation.seq());
        map.put("pointer", violation.pointer());
        map.put("message", violation.message());
        return map;
    }

    @SuppressWarnings("unchecked")
    private static String dimension(Map<String, Object> record, String field, java.util.Set<String> allowed) {
        Map<String, Object> leaves = (Map<String, Object>) record.get("disclosedLeaves");
        Object leaf = leaves.get("/" + field);
        if (leaf == null) {
            return UNKNOWN_REDACTED;
        }
        Object value = ((Map<String, Object>) leaf).get("value");
        if (value instanceof String text && allowed.contains(text)) {
            return text;
        }
        return UNKNOWN_INVALID;
    }

    private static String sha256Hex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    /** Synchronous reports are capped; the caller must narrow the period. No partial result exists. */
    public static final class ReportLimitExceededException extends RuntimeException {
        private final int limit;
        private final String unit;

        public ReportLimitExceededException(int limit, String unit) {
            super("The report exceeds the synchronous limit of " + limit + " " + unit
                    + "; narrow the period or subject");
            this.limit = limit;
            this.unit = unit;
        }

        public int limit() {
            return limit;
        }

        public String unit() {
            return unit;
        }
    }
}
