package com.auditlog.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
class ArchiveHttpTests {

    private static final String WRITER = "dev-writer-only";
    private static final String READER = "dev-reader-only";
    private static final String AUDITOR = "dev-auditor-only";
    private static final String ADMIN = "dev-admin-only";

    @TempDir
    static Path directory;

    @Autowired
    private MockMvc mockMvc;

    @DynamicPropertySource
    static void configureRuntime(DynamicPropertyRegistry registry) {
        registry.add("AUDIT_DB_PATH", () -> directory.resolve("archive-http.db").toString());
        registry.add("AUDIT_LEDGER_ID", () -> "archive-http-ledger");
        registry.add("AUDIT_ARCHIVE_DIR", () -> directory.resolve("archives").toString());
    }

    @Test
    void archiveEndpointsAreAdminOnly() throws Exception {
        for (String path : new String[] {"/audit/admin/archive", "/audit/admin/archive-jobs/reconcile"}) {
            mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content("{\"dryRun\":true}"))
                    .andExpect(status().isUnauthorized());
            for (String key : new String[] {WRITER, READER, AUDITOR}) {
                mockMvc.perform(post(path).header("X-API-Key", key)
                                .contentType(MediaType.APPLICATION_JSON).content("{\"dryRun\":true}"))
                        .andExpect(status().isForbidden());
            }
        }
        mockMvc.perform(get("/audit/admin/archive-jobs").header("X-API-Key", AUDITOR))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/audit/admin/archive-jobs").header("X-API-Key", ADMIN))
                .andExpect(status().isOk());
    }

    @Test
    void dryRunIsRequiredAndNothingIsArchivedWhenNothingExpired() throws Exception {
        mockMvc.perform(post("/audit/admin/archive").header("X-API-Key", ADMIN)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(post("/audit/admin/archive").header("X-API-Key", ADMIN)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"dryRun\":false,\"x\":1}"))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(post("/audit/admin/archive").header("X-API-Key", ADMIN)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"dryRun\":true}"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("NOTHING_TO_ARCHIVE")));
    }

    @Test
    void archiveAuditIsAuditorAccessibleAndOpenApiListsArchivePaths() throws Exception {
        mockMvc.perform(get("/audit/archive-audit").header("X-API-Key", READER))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/audit/archive-audit").header("X-API-Key", AUDITOR))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archiveCount").value(0));
        mockMvc.perform(get("/openapi.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/audit/admin/archive']").exists())
                .andExpect(jsonPath("$.paths['/audit/archive-audit']").exists());
    }
}
