package com.auditlog.domain;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Signed completeness statement of a v1 bundle. These are assertions by the signer, not proofs of
 * omission-free upstream capture or of global chain membership.
 */
public record BundleCompleteness(long throughSeq) {

    public static final String SCOPE = "MATCHING_RETAINED_LIVE_RECORDS";
    public static final String UPSTREAM_COVERAGE = "NOT_PROVEN";
    public static final String ASSURANCE = "SIGNED_ASSERTION";
    public static final Set<String> KEYS = Set.of(
            "scope", "throughSeq", "archivedRecordsExcluded", "upstreamCoverage", "assurance");

    public BundleCompleteness {
        if (throughSeq < 0 || throughSeq > BundleSelection.MAX_SAFE) {
            throw new IllegalArgumentException("throughSeq must be a safe nonnegative integer");
        }
    }

    /** Parses strictly; any deviation from the fixed v1 values is rejected. */
    public static BundleCompleteness fromMap(Map<?, ?> map) {
        if (!map.keySet().equals(KEYS)
                || !SCOPE.equals(map.get("scope"))
                || !Boolean.TRUE.equals(map.get("archivedRecordsExcluded"))
                || !UPSTREAM_COVERAGE.equals(map.get("upstreamCoverage"))
                || !ASSURANCE.equals(map.get("assurance"))
                || !(map.get("throughSeq") instanceof Long || map.get("throughSeq") instanceof Integer)) {
            throw new IllegalArgumentException("completeness does not match the fixed v1 shape");
        }
        return new BundleCompleteness(((Number) map.get("throughSeq")).longValue());
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("scope", SCOPE);
        map.put("throughSeq", throughSeq);
        map.put("archivedRecordsExcluded", true);
        map.put("upstreamCoverage", UPSTREAM_COVERAGE);
        map.put("assurance", ASSURANCE);
        return map;
    }
}
