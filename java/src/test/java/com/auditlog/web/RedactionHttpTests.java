package com.auditlog.web;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
class RedactionHttpTests {

    private static final String MARKER = "SYNTHETIC-HTTP-MARKER-5d2e";

    @TempDir
    static Path directory;

    @Autowired
    private MockMvc mockMvc;

    @DynamicPropertySource
    static void configureRuntime(DynamicPropertyRegistry registry) {
        registry.add("AUDIT_DB_PATH", () -> directory.resolve("redaction-http.db").toString());
        registry.add("AUDIT_LEDGER_ID", () -> "redaction-http-ledger");
    }

    private String append() throws Exception {
        String body = mockMvc.perform(post("/audit/events").header("X-API-Key", "dev-writer-only")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"T\",\"actorId\":\"a\",\"resourceType\":\"R\","
                                + "\"resourceId\":\"r\",\"payload\":{\"secret\":\"" + MARKER + "\",\"keep\":1}}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return new ObjectMapper().readTree(body).get("eventId").asText();
    }

    private static String request(String eventId, String paths) {
        return "{\"eventId\":\"" + eventId + "\",\"paths\":" + paths
                + ",\"reason\":\"erasure request\",\"ticketId\":\"T-1\"}";
    }

    @Test
    void redactionRolesResponseShapeAndNoPlaintext() throws Exception {
        String eventId = append();
        String body = request(eventId, "[\"/secret\"]");

        mockMvc.perform(post("/audit/admin/redactions").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());
        for (String key : new String[] {"dev-writer-only", "dev-reader-only", "dev-auditor-only"}) {
            mockMvc.perform(post("/audit/admin/redactions").header("X-API-Key", key)
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isForbidden());
            mockMvc.perform(get("/audit/admin/redaction-cleanups").header("X-API-Key", key))
                    .andExpect(status().isForbidden());
            mockMvc.perform(post("/audit/admin/redaction-cleanups/retry").header("X-API-Key", key))
                    .andExpect(status().isForbidden());
        }

        String response = mockMvc.perform(post("/audit/admin/redactions").header("X-API-Key", "dev-admin-only")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.redactedPaths[0]").value("/secret"))
                .andExpect(jsonPath("$.cleanupStatus").value("COMPLETE"))
                .andExpect(jsonPath("$.targetEventId").value(eventId))
                .andReturn().getResponse().getContentAsString();
        assertFalse(response.contains(MARKER));

        String read = mockMvc.perform(get("/audit/events/" + eventId).header("X-API-Key", "dev-reader-only"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload.secret").value("[REDACTED]"))
                .andExpect(jsonPath("$.redactedPaths[0]").value("/secret"))
                .andReturn().getResponse().getContentAsString();
        assertFalse(read.contains(MARKER));

        mockMvc.perform(post("/audit/admin/redactions").header("X-API-Key", "dev-admin-only")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isConflict());
        mockMvc.perform(get("/audit/verify").header("X-API-Key", "dev-auditor-only"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.intact").value(true));

        String status = mockMvc.perform(get("/audit/admin/redaction-cleanups").header("X-API-Key", "dev-admin-only"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pendingJobs").value(0))
                .andReturn().getResponse().getContentAsString();
        JsonNode node = new ObjectMapper().readTree(status);
        assertFalse(node.toString().contains(MARKER));
        mockMvc.perform(post("/audit/admin/redaction-cleanups/retry").header("X-API-Key", "dev-admin-only"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.pendingJobs").value(0));
    }

    @Test
    void invalidRedactionRequestsAreRejectedWithoutLeakingValues() throws Exception {
        String eventId = append();
        String[] bad = {
            request(eventId, "[\"/missing\"]"),
            request(eventId, "[]"),
            request(eventId, "[\"nope\"]"),
            "{\"eventId\":\"" + eventId + "\",\"paths\":[\"/keep\"],\"reason\":\"r\",\"ticketId\":\"T\",\"x\":1}",
            "{\"eventId\":\"" + eventId + "\",\"paths\":[\"/secret\"],\"reason\":\"" + MARKER + "\",\"ticketId\":\"T\"}"
        };
        for (String content : bad) {
            String response = mockMvc.perform(post("/audit/admin/redactions").header("X-API-Key", "dev-admin-only")
                            .contentType(MediaType.APPLICATION_JSON).content(content))
                    .andExpect(status().isUnprocessableEntity())
                    .andReturn().getResponse().getContentAsString();
            assertFalse(response.contains("Exception"));
        }
        mockMvc.perform(post("/audit/admin/redactions").header("X-API-Key", "dev-admin-only")
                        .contentType(MediaType.APPLICATION_JSON).content(request("missing-id", "[\"/keep\"]")))
                .andExpect(status().isNotFound());
    }
}
