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
class ExportLimitHttpTests {

    @TempDir
    static Path directory;

    @Autowired
    private MockMvc mockMvc;

    @DynamicPropertySource
    static void configureRuntime(DynamicPropertyRegistry registry) {
        registry.add("AUDIT_DB_PATH", () -> directory.resolve("limit-test.db").toString());
        registry.add("AUDIT_LEDGER_ID", () -> "limit-test-ledger");
        registry.add("AUDIT_EXPORT_MAX_RECORDS", () -> "2");
    }

    @Test
    void overLimitSelectionReturns422WithoutDataOrMetaEvent() throws Exception {
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/audit/events").header("X-API-Key", "dev-writer-only")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"eventType\":\"T\",\"actorId\":\"limit-actor\","
                                    + "\"resourceType\":\"R\",\"resourceId\":\"r" + i
                                    + "\",\"payload\":{\"secret\":\"sensitive-value\"}}"))
                    .andExpect(status().isCreated());
        }
        mockMvc.perform(get("/audit/export").param("actorId", "limit-actor")
                        .header("X-API-Key", "dev-auditor-only"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error.code").value("EXPORT_LIMIT_EXCEEDED"))
                .andExpect(jsonPath("$.error.details[0].limit").value("AUDIT_EXPORT_MAX_RECORDS"))
                .andExpect(jsonPath("$.error.details[0].value").value(2))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.content()
                        .string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("sensitive-value"))));
        mockMvc.perform(get("/audit/events").param("eventType", "BUNDLE_EXPORTED")
                        .header("X-API-Key", "dev-reader-only"))
                .andExpect(jsonPath("$.items.length()").value(0));
    }
}
