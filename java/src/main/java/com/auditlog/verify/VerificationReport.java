package com.auditlog.verify;

import java.util.List;

public record VerificationReport(
        boolean intact,
        String ledgerId,
        String hashAlgorithm,
        long checkedRecords,
        long archivedRecords,
        long redactedFields,
        long headSeq,
        String headHash,
        long checkpointsVerified,
        Violation firstViolation,
        List<Violation> violations,
        long totalViolationCount,
        boolean violationsTruncated,
        String verifiedAt,
        long durationMs) {

    public VerificationReport {
        violations = List.copyOf(violations);
    }
}
