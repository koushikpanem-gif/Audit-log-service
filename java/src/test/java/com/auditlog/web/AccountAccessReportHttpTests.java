package com.auditlog.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AccountAccessReportHttpTests {

    private static final String WRITER = "dev-writer-only";
    private static final String READER = "dev-reader-only";
    private static final String AUDITOR = "dev-auditor-only";
    private static final String ADMIN = "dev-admin-only";
    private static final String PERIOD = "&from=2020-01-01T00:00:00Z&to=2100-01-01T00:00:00Z";

    @TempDir
    static Path directory;

    @Autowired
    private MockMvc mockMvc;

    @DynamicPropertySource
    static void configureRuntime(DynamicPropertyRegistry registry) {
        registry.add("AUDIT_DB_PATH", () -> directory.resolve("report-http.db").toString());
        registry.add("AUDIT_LEDGER_ID", () -> "report-http-ledger");
        registry.add("AUDIT_ARCHIVE_DIR", () -> directory.resolve("archives").toString());
    }

    private static String event(String resourceType, String outcome, String extra) {
        return "{\"eventType\":\"ACCOUNT_DATA_ACCESS\",\"actorId\":\"user-1\",\"resourceType\":\""
                + resourceType + "\",\"resourceId\":\"acct-http\",\"payload\":{\"dataCategory\":\"BALANCES\","
                + "\"accessType\":\"VIEW\",\"accessPurpose\":\"SERVICING\",\"channel\":\"API\","
                + "\"outcome\":\"" + outcome + "\"" + extra + "}}";
    }

    @Test
    void contractIsEnforcedOnAppend() throws Exception {
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON).content(event("ACCOUNT", "GRANTED", "")))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON).content(event("CLIENT_ACCOUNT", "DENIED", "")))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event("CLIENT_ACCOUNT", "DENIED", ",\"denialReason\":\"synthetic\"")))
                .andExpect(status().isCreated());
    }

    @Test
    void reportRolesAndValidation() throws Exception {
        String path = "/compliance/account-access-report?accountId=acct-http" + PERIOD;
        mockMvc.perform(get(path)).andExpect(status().isUnauthorized());
        for (String key : new String[] {WRITER, READER}) {
            mockMvc.perform(get(path).header("X-API-Key", key)).andExpect(status().isForbidden());
        }
        mockMvc.perform(get("/compliance/account-access-report?from=2020-01-01T00:00:00Z"
                        + "&to=2100-01-01T00:00:00Z").header("X-API-Key", AUDITOR))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(get("/compliance/account-access-report?accountId=a&actorId=b" + PERIOD)
                        .header("X-API-Key", AUDITOR))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(get("/compliance/account-access-report?accountId=a").header("X-API-Key", AUDITOR))
                .andExpect(status().isUnprocessableEntity());
    }

    @Test
    void auditorAndAdminReceiveReportWithSeparateHeads() throws Exception {
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(event("CLIENT_ACCOUNT", "GRANTED", "")))
                .andExpect(status().isCreated());
        String path = "/compliance/account-access-report?accountId=acct-http" + PERIOD;
        mockMvc.perform(get(path).header("X-API-Key", AUDITOR))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trustworthy").value(true))
                .andExpect(jsonPath("$.requestedBy").value("dev-auditor"))
                .andExpect(jsonPath("$.verifiedDataHead.seq").exists())
                .andExpect(jsonPath("$.postReportHead.seq").exists())
                .andExpect(jsonPath("$.evidence.purpose").value("COMPLIANCE_REPORT"));
        mockMvc.perform(get(path).header("X-API-Key", ADMIN)).andExpect(status().isOk());
        mockMvc.perform(get("/openapi.json"))
                .andExpect(jsonPath("$.paths['/compliance/account-access-report']").exists());
    }
}
