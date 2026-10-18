package com.auditlog.domain;

/** Allowed v1 bundle purposes. */
public enum BundlePurpose {
    EXPORT,
    RETENTION_ARCHIVE,
    COMPLIANCE_REPORT;

    public static BundlePurpose parse(Object value) {
        if (value instanceof String text) {
            for (BundlePurpose purpose : values()) {
                if (purpose.name().equals(text)) {
                    return purpose;
                }
            }
        }
        return null;
    }
}
