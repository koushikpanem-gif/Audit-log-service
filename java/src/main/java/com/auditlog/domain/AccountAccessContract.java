package com.auditlog.domain;

import java.util.Map;
import java.util.Set;

/**
 * Contract for ACCOUNT_DATA_ACCESS events: resourceType CLIENT_ACCOUNT and a payload with five
 * enum fields plus conditional text fields. Extra payload fields are allowed. Validation messages
 * name fields only and never echo submitted values.
 */
public final class AccountAccessContract {

    public static final String EVENT_TYPE = "ACCOUNT_DATA_ACCESS";
    public static final String RESOURCE_TYPE = "CLIENT_ACCOUNT";
    public static final int MAX_JUSTIFICATION = 1000;
    public static final int MAX_DENIAL_REASON = 500;
    public static final int MAX_SESSION_ID = 128;
    public static final int MAX_SOURCE_IP = 64;

    public static final Set<String> DATA_CATEGORIES = Set.of(
            "PROFILE", "IDENTIFIERS", "BALANCES", "POSITIONS", "TRANSACTIONS", "STATEMENTS",
            "TAX_DOCUMENTS", "BANKING_DETAILS");
    public static final Set<String> ACCESS_TYPES = Set.of("VIEW", "SEARCH", "EXPORT", "PRINT", "MODIFY");
    public static final Set<String> ACCESS_PURPOSES = Set.of(
            "CLIENT_REQUEST", "TRADE_SUPPORT", "SERVICING", "COMPLIANCE_REVIEW", "FRAUD_INVESTIGATION",
            "LEGAL_HOLD", "OTHER");
    public static final Set<String> CHANNELS = Set.of(
            "INTERNAL_APP", "SUPPORT_TOOL", "CLIENT_PORTAL", "API", "BATCH");
    public static final Set<String> OUTCOMES = Set.of("GRANTED", "DENIED");

    private AccountAccessContract() {
    }

    public static void validate(String eventType, String resourceType, Map<String, ?> payload) {
        if (!EVENT_TYPE.equals(eventType)) {
            return;
        }
        if (!RESOURCE_TYPE.equals(resourceType)) {
            throw new IllegalArgumentException("ACCOUNT_DATA_ACCESS requires resourceType CLIENT_ACCOUNT");
        }
        enumField(payload, "dataCategory", DATA_CATEGORIES);
        enumField(payload, "accessType", ACCESS_TYPES);
        String purpose = enumField(payload, "accessPurpose", ACCESS_PURPOSES);
        enumField(payload, "channel", CHANNELS);
        String outcome = enumField(payload, "outcome", OUTCOMES);

        if ("OTHER".equals(purpose)) {
            requiredText(payload, "justification", MAX_JUSTIFICATION);
        } else {
            optionalText(payload, "justification", MAX_JUSTIFICATION);
        }
        if ("DENIED".equals(outcome)) {
            requiredText(payload, "denialReason", MAX_DENIAL_REASON);
        } else {
            optionalText(payload, "denialReason", MAX_DENIAL_REASON);
        }
        optionalText(payload, "sessionId", MAX_SESSION_ID);
        optionalText(payload, "sourceIp", MAX_SOURCE_IP);
    }

    private static String enumField(Map<String, ?> payload, String name, Set<String> allowed) {
        Object value = payload.get(name);
        if (!(value instanceof String text) || !allowed.contains(text)) {
            throw new IllegalArgumentException("ACCOUNT_DATA_ACCESS payload." + name + " is missing or not allowed");
        }
        return text;
    }

    private static void requiredText(Map<String, ?> payload, String name, int max) {
        Object value = payload.get(name);
        if (!(value instanceof String text) || text.isBlank() || text.codePointCount(0, text.length()) > max) {
            throw new IllegalArgumentException(
                    "ACCOUNT_DATA_ACCESS payload." + name + " must be non-blank text of at most " + max
                            + " characters");
        }
    }

    private static void optionalText(Map<String, ?> payload, String name, int max) {
        if (!payload.containsKey(name)) {
            return;
        }
        Object value = payload.get(name);
        if (!(value instanceof String text) || text.codePointCount(0, text.length()) > max) {
            throw new IllegalArgumentException(
                    "ACCOUNT_DATA_ACCESS payload." + name + " must be text of at most " + max + " characters");
        }
    }
}
