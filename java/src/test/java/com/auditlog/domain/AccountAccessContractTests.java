package com.auditlog.domain;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AccountAccessContractTests {

    private static Map<String, Object> valid() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("dataCategory", "BALANCES");
        payload.put("accessType", "VIEW");
        payload.put("accessPurpose", "SERVICING");
        payload.put("channel", "INTERNAL_APP");
        payload.put("outcome", "GRANTED");
        return payload;
    }

    private static void rejected(Map<String, Object> payload) {
        assertThrows(IllegalArgumentException.class,
                () -> AccountAccessContract.validate("ACCOUNT_DATA_ACCESS", "CLIENT_ACCOUNT", payload));
    }

    @Test
    void acceptsValidPayloadAndExtraFields() {
        Map<String, Object> payload = valid();
        payload.put("sessionId", "s".repeat(128));
        payload.put("sourceIp", "i".repeat(64));
        payload.put("extra", Map.of("anything", 1));
        assertDoesNotThrow(() ->
                AccountAccessContract.validate("ACCOUNT_DATA_ACCESS", "CLIENT_ACCOUNT", payload));
    }

    @Test
    void ignoresOtherEventTypes() {
        assertDoesNotThrow(() -> AccountAccessContract.validate("TRADE", "ACCOUNT", Map.of()));
    }

    @Test
    void requiresClientAccountResourceType() {
        assertThrows(IllegalArgumentException.class,
                () -> AccountAccessContract.validate("ACCOUNT_DATA_ACCESS", "ACCOUNT", valid()));
    }

    @Test
    void rejectsMissingOrUnknownEnumValues() {
        for (String field : new String[] {"dataCategory", "accessType", "accessPurpose", "channel", "outcome"}) {
            Map<String, Object> missing = valid();
            missing.remove(field);
            rejected(missing);
            Map<String, Object> unknown = valid();
            unknown.put(field, "NOPE");
            rejected(unknown);
            Map<String, Object> wrongType = valid();
            wrongType.put(field, 5);
            rejected(wrongType);
        }
    }

    @Test
    void otherPurposeRequiresJustification() {
        Map<String, Object> payload = valid();
        payload.put("accessPurpose", "OTHER");
        rejected(payload);
        payload.put("justification", "   ");
        rejected(payload);
        payload.put("justification", "x".repeat(1001));
        rejected(payload);
        payload.put("justification", "x".repeat(1000));
        assertDoesNotThrow(() ->
                AccountAccessContract.validate("ACCOUNT_DATA_ACCESS", "CLIENT_ACCOUNT", payload));
    }

    @Test
    void deniedOutcomeRequiresDenialReason() {
        Map<String, Object> payload = valid();
        payload.put("outcome", "DENIED");
        rejected(payload);
        payload.put("denialReason", "");
        rejected(payload);
        payload.put("denialReason", "y".repeat(501));
        rejected(payload);
        payload.put("denialReason", "y".repeat(500));
        assertDoesNotThrow(() ->
                AccountAccessContract.validate("ACCOUNT_DATA_ACCESS", "CLIENT_ACCOUNT", payload));
    }

    @Test
    void enforcesOptionalFieldLengths() {
        Map<String, Object> session = valid();
        session.put("sessionId", "s".repeat(129));
        rejected(session);
        Map<String, Object> address = valid();
        address.put("sourceIp", "i".repeat(65));
        rejected(address);
        Map<String, Object> wrongType = valid();
        wrongType.put("sessionId", 12);
        rejected(wrongType);
    }
}
