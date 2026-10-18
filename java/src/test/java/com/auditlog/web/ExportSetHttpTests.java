package com.auditlog.web;

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
class ExportSetHttpTests {

    @TempDir
    static Path directory;

    @Autowired
    private MockMvc mockMvc;

    @DynamicPropertySource
    static void configureRuntime(DynamicPropertyRegistry registry) {
        registry.add("AUDIT_DB_PATH", () -> directory.resolve("set-test.db").toString());
        registry.add("AUDIT_LEDGER_ID", () -> "set-http-ledger");
        registry.add("AUDIT_EXPORT_MAX_RECORDS", () -> "2");
        registry.add("AUDIT_EXPORT_CHUNK_MAX_RECORDS", () -> "2");
    }

    private void append(int i) throws Exception {
        mockMvc.perform(post("/audit/events").header("X-API-Key", "dev-writer-only")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"T\",\"actorId\":\"a\",\"resourceType\":\"R\","
                                + "\"resourceId\":\"r" + i + "\",\"payload\":{\"k\":" + i + "}}"))
                .andExpect(status().isCreated());
    }

    @Test
    void exportSetLifecycleRolesAndPathSafety() throws Exception {
        for (int i = 0; i < 5; i++) {
            append(i);
        }
        mockMvc.perform(get("/audit/export").param("actorId", "a").header("X-API-Key", "dev-auditor-only"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error.code").value("EXPORT_LIMIT_EXCEEDED"));

        mockMvc.perform(post("/audit/export-sets")).andExpect(status().isUnauthorized());
        for (String key : new String[] {"dev-writer-only", "dev-reader-only"}) {
            mockMvc.perform(post("/audit/export-sets").header("X-API-Key", key))
                    .andExpect(status().isForbidden());
        }

        String body = mockMvc.perform(post("/audit/export-sets").header("X-API-Key", "dev-auditor-only"))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
        JsonNode descriptor = new ObjectMapper().readTree(body);
        String id = descriptor.get("exportSetId").asText();
        for (int attempt = 0; attempt < 200; attempt++) {
            String state = new ObjectMapper().readTree(mockMvc.perform(get("/audit/export-sets/" + id)
                            .header("X-API-Key", "dev-auditor-only")).andReturn().getResponse()
                    .getContentAsString()).get("status").asText();
            if ("READY".equals(state)) {
                break;
            }
            Thread.sleep(50);
        }

        mockMvc.perform(get("/audit/export-sets/" + id).header("X-API-Key", "dev-reader-only"))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/audit/export-sets/" + id).header("X-API-Key", "dev-auditor-only"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("READY"));
        mockMvc.perform(get("/audit/export-sets/" + id + "/manifest").header("X-API-Key", "dev-auditor-only"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.chunkCount").value(3));
        mockMvc.perform(get("/audit/export-sets/" + id + "/chunks/chunk-000000.json")
                        .header("X-API-Key", "dev-auditor-only"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.records.length()").value(2));

        for (String name : new String[] {"chunk-000009.json", "..%2Fmanifest.json", "manifest.json", "chunk-1.json"}) {
            mockMvc.perform(get("/audit/export-sets/" + id + "/chunks/" + name)
                            .header("X-API-Key", "dev-auditor-only"))
                    .andExpect(status().is4xxClientError());
        }
        mockMvc.perform(get("/audit/export-sets/not-an-id").header("X-API-Key", "dev-auditor-only"))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/audit/export-sets/00000000-0000-0000-0000-000000000000/manifest")
                        .header("X-API-Key", "dev-auditor-only"))
                .andExpect(status().isNotFound());
    }
}
