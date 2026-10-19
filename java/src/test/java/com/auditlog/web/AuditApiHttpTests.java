package com.auditlog.web;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.auditlog.store.JdbcAuditRepository;
import com.auditlog.store.StorageBusyException;
import com.fasterxml.jackson.databind.JsonNode;
import com.auditlog.verifier.BundleVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
@Import(AuditApiHttpTests.FixedClockConfiguration.class)
class AuditApiHttpTests {

    private static final String WRITER = "dev-writer-only";
    private static final String READER = "dev-reader-only";
    private static final String AUDITOR = "dev-auditor-only";
    private static final String ADMIN = "dev-admin-only";

    @TempDir
    static Path directory;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JdbcAuditRepository repository;

    @DynamicPropertySource
    static void configureRuntime(DynamicPropertyRegistry registry) {
        registry.add("AUDIT_DB_PATH", () -> directory.resolve("http-test.db").toString());
        registry.add("AUDIT_LEDGER_ID", () -> "http-test-ledger");
        registry.add("AUDIT_CHECKPOINT_INTERVAL", () -> "3");
    }

    @Test
    void exportEndpointIsAuditorOnlyAndProducesOfflineVerifiableBundle() throws Exception {
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson("EXPORT_TEST", "actor-export", "resource-export", "{\"k\":\"v\"}")))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/audit/export").param("actorId", "actor-export"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/audit/export").param("actorId", "actor-export").header("X-API-Key", READER))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/audit/export").param("actorId", "actor-export").header("X-API-Key", WRITER))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/audit/export").header("X-API-Key", AUDITOR))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error.code").value("INVALID_INPUT"));
        mockMvc.perform(get("/audit/export").param("actorId", "a").param("resourceId", "b")
                        .header("X-API-Key", AUDITOR))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.recordCount").value(0));
        mockMvc.perform(get("/audit/export").param("actorId", "a")
                        .param("from", "2030-01-02T00:00:00.000000Z").param("to", "2030-01-01T00:00:00.000000Z")
                        .header("X-API-Key", AUDITOR))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(get("/audit/export").param("actorId", "a").param("from", "yesterday")
                        .header("X-API-Key", AUDITOR))
                .andExpect(status().isUnprocessableEntity());

        String body = mockMvc.perform(get("/audit/export").param("actorId", "actor-export")
                        .header("X-API-Key", AUDITOR))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.format").value("audit-export-bundle/v1"))
                .andExpect(jsonPath("$.exportedBy").value("dev-auditor"))
                .andExpect(jsonPath("$.recordCount").value(1))
                .andReturn().getResponse().getContentAsString();
        String publicKey = objectMapper.readTree(mockMvc.perform(get("/audit/public-key"))
                .andReturn().getResponse().getContentAsString()).get("publicKey").asText();

        BundleVerifier.Result result = BundleVerifier.verify(
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                BundleVerifier.Options.pinned(publicKey));

        org.junit.jupiter.api.Assertions.assertEquals(
                BundleVerifier.Status.VERIFIED, result.status(), result.diagnostics().toString());
        org.junit.jupiter.api.Assertions.assertArrayEquals(
                com.auditlog.core.crypto.CanonicalJson.canonicalize(
                        objectMapper.readValue(body, Object.class), 32, Integer.MAX_VALUE),
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                "HTTP body is the exact canonical signed bytes");
        mockMvc.perform(get("/audit/verify").header("X-API-Key", AUDITOR))
                .andExpect(jsonPath("$.intact").value(true));
    }

    @Test
    void exposesPublicHealthOpenApiAndPublicKey() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
        mockMvc.perform(get("/openapi.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/audit/events']").exists())
                .andExpect(jsonPath("$.components.securitySchemes.apiKeyAuth.name")
                        .value("X-API-Key"));
        mockMvc.perform(get("/docs"))
                .andExpect(status().is3xxRedirection());
        mockMvc.perform(get("/audit/public-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signatureAlgorithm").value("Ed25519"))
                .andExpect(jsonPath("$.publicKey").isNotEmpty());
    }

    @Test
    void enforcesHashedApiKeyRolesAndReturnsConsistentErrors() throws Exception {
        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.error.details").isArray());
        mockMvc.perform(get("/audit/events").header("X-API-Key", "invalid-key"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/audit/events").header("X-API-Key", READER)
                        .contentType(MediaType.APPLICATION_JSON).content(eventJson("EVENT", "actor", "resource", "{}")))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/audit/checkpoints").header("X-API-Key", READER))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/audit/checkpoints").header("X-API-Key", AUDITOR))
                .andExpect(status().isOk());
        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/audit/verify").header("X-API-Key", READER))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/audit/verify").header("X-API-Key", WRITER))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/audit/verify").header("X-API-Key", AUDITOR))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.hashAlgorithm").value("SHA-256"))
                .andExpect(jsonPath("$.violations").isArray())
                .andExpect(jsonPath("$.totalViolationCount").value(0));
        mockMvc.perform(get("/audit/verify").header("X-API-Key", ADMIN))
                .andExpect(status().isOk());
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson("ROLE_TEST", "actor-role", "resource-role", "{}")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.source").value("dev-writer"))
                .andExpect(jsonPath("$.timestamp").value("2026-10-18T14:59:00.000000Z"));
        mockMvc.perform(post("/audit/events").header("X-API-Key", ADMIN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson("ADMIN_TEST", "actor-admin", "resource-admin", "{}")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.source").value("dev-admin"));
    }

    @Test
    void rejectsMalformedOversizedUnknownAndReservedEventRequests() throws Exception {
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"eventType\":"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error.code").value("INVALID_JSON"));
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson("EVENT", "actor", "resource", "{}")
                                .replace("\"payload\":{}", "\"payload\":{},\"source\":\"body\"")))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson("EVENT", "actor", "resource", "{}")
                                .replace("\"payload\":{}", "\"payload\":{},\"timestamp\":\"body\"")))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson("RECORD_REDACTED", "actor", "resource", "{}")))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson("EVENT", "actor", "resource", "{}")
                                .replace("\"payload\":{}", "\"payload\":{},\"occurredAt\":\"2026-10-18T15:04:01Z\"")))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eventType\":\"EVENT\",\"eventType\":\"OTHER\","
                                + "\"actorId\":\"actor\",\"resourceType\":\"R\","
                                + "\"resourceId\":\"r\",\"payload\":{}}"))
                .andExpect(status().isUnprocessableEntity());
        String oversizedPayload = "{\"eventType\":\"EVENT\",\"actorId\":\"actor\","
                + "\"resourceType\":\"RESOURCE\",\"resourceId\":\"r\",\"payload\":{\"x\":\""
                + "x".repeat(65_530) + "\"}}";
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON).content(oversizedPayload))
                .andExpect(status().isUnprocessableEntity());
        String oversized = "{\"eventType\":\"EVENT\",\"actorId\":\"actor\","
                + "\"resourceType\":\"RESOURCE\",\"resourceId\":\"r\",\"payload\":{\"x\":\""
                + "x".repeat(263_000) + "\"}}";
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON).content(oversized))
                .andExpect(status().isPayloadTooLarge())
                .andExpect(jsonPath("$.error.code").value("REQUEST_TOO_LARGE"));
    }

    @Test
    void appendsGetsAndQueriesEventsWithAllFiltersAndInclusiveTimestampRanges() throws Exception {
        String actor = "actor-" + UUID.randomUUID();
        String resourceId = "account-" + UUID.randomUUID();
        MvcResult first = append("ACCOUNT_ACCESS", actor, resourceId, "{\"amount\":\"12.50\"}");
        MvcResult second = append("ACCOUNT_ACCESS", actor, resourceId, "{\"ok\":true}");
        JsonNode firstEvent = objectMapper.readTree(first.getResponse().getContentAsString());
        JsonNode secondEvent = objectMapper.readTree(second.getResponse().getContentAsString());
        String timestamp = firstEvent.path("timestamp").textValue();

        mockMvc.perform(get("/audit/events/{id}", firstEvent.path("eventId").textValue())
                        .header("X-API-Key", READER))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload.amount").value("12.50"))
                .andExpect(jsonPath("$.payloadCommitments.amount").isNotEmpty());
        mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                        .param("actorId", actor)
                        .param("resourceType", "CLIENT_ACCOUNT")
                        .param("resourceId", resourceId)
                        .param("eventType", "ACCOUNT_ACCESS")
                        .param("from", timestamp)
                        .param("to", timestamp)
                        .param("limit", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items", hasSize(2)))
                .andExpect(jsonPath("$.items[0].seq").value(firstEvent.path("seq").asInt()))
                .andExpect(jsonPath("$.items[1].seq").value(secondEvent.path("seq").asInt()));
        mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                        .param("from", "2026-10-18T15:00:00Z")
                        .param("to", "2026-10-18T14:00:00Z"))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                        .param("limit", "not-a-number"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error.code").value("INVALID_INPUT"));
        mockMvc.perform(get("/audit/events/{id}", "missing-" + UUID.randomUUID())
                        .header("X-API-Key", READER))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));
    }

    @Test
    void acceptsConfiguredPayloadDepthWithTheEnvelopeLevelAccountedFor() throws Exception {
        String nested = "1";
        for (int index = 0; index < 9; index++) {
            nested = "{\"x\":" + nested + "}";
        }
        String payload = "{\"nested\":" + nested + "}";
        mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson("DEEP_PAYLOAD", "depth-actor-" + UUID.randomUUID(),
                                "depth-resource", payload)))
                .andExpect(status().isCreated());
    }

    @Test
    void rejectsNonStringEventFieldsWithoutAppendingToTheLedger() throws Exception {
        long headBefore = ledgerHead();
        String[] bodies = {
            "{\"eventType\":5,\"actorId\":\"strict-types\",\"resourceType\":\"doc\","
                    + "\"resourceId\":\"r\",\"payload\":{}}",
            "{\"eventType\":\"T\",\"actorId\":5,\"resourceType\":\"doc\","
                    + "\"resourceId\":\"r\",\"payload\":{}}",
            "{\"eventType\":\"T\",\"actorId\":\"strict-types\",\"resourceType\":5,"
                    + "\"resourceId\":\"r\",\"payload\":{}}",
            "{\"eventType\":\"T\",\"actorId\":\"strict-types\",\"resourceType\":\"doc\","
                    + "\"resourceId\":5,\"payload\":{}}"
        };
        for (String body : bodies) {
            mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isUnprocessableEntity())
                    .andExpect(jsonPath("$.error.code").value("INVALID_INPUT"))
                    .andExpect(jsonPath("$.error.details").isArray());
        }
        org.junit.jupiter.api.Assertions.assertEquals(headBefore, ledgerHead());
    }

    @Test
    void returnsStructuredNotFoundForUnknownRoutes() throws Exception {
        mockMvc.perform(get("/no-such-route").header("X-API-Key", READER))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"))
                .andExpect(jsonPath("$.error.details").isArray());
    }

    @Test
    void paginatesFiveEventsAcrossTwoCursorPagesAndAOneItemLastPage() throws Exception {
        String actor = "cursor-pages-" + UUID.randomUUID();
        List<Long> sequences = new ArrayList<>();
        for (int index = 0; index < 5; index++) {
            MvcResult appended = append(
                    "CURSOR_PAGE_EVENT", actor, "cursor-resource", "{\"n\":" + index + "}");
            sequences.add(objectMapper.readTree(appended.getResponse().getContentAsString())
                    .path("seq").asLong());
        }

        MvcResult firstResult = mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                        .param("actorId", actor).param("limit", "2").param("order", "asc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items", hasSize(2)))
                .andReturn();
        JsonNode firstPage = objectMapper.readTree(firstResult.getResponse().getContentAsString());
        String firstCursor = firstPage.path("nextCursor").textValue();

        MvcResult secondResult = mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                        .param("actorId", actor).param("limit", "2").param("order", "asc")
                        .param("cursor", firstCursor))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items", hasSize(2)))
                .andReturn();
        JsonNode secondPage = objectMapper.readTree(secondResult.getResponse().getContentAsString());
        String secondCursor = secondPage.path("nextCursor").textValue();

        MvcResult lastResult = mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                        .param("actorId", actor).param("limit", "2").param("order", "asc")
                        .param("cursor", secondCursor))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items", hasSize(1)))
                .andExpect(jsonPath("$.nextCursor").doesNotExist())
                .andReturn();

        JsonNode lastPage = objectMapper.readTree(lastResult.getResponse().getContentAsString());
        List<JsonNode> pages = List.of(
                firstPage.path("items").get(0), firstPage.path("items").get(1),
                secondPage.path("items").get(0), secondPage.path("items").get(1),
                lastPage.path("items").get(0));
        for (int index = 0; index < pages.size(); index++) {
            org.junit.jupiter.api.Assertions.assertEquals(
                    sequences.get(index), pages.get(index).path("seq").asLong());
        }
    }

    @Test
    void usesStableKeysetCursorsBoundToFiltersAndOrderAndSupportsDescending() throws Exception {
        String actor = "cursor-" + UUID.randomUUID();
        MvcResult first = append("CURSOR_EVENT", actor, "cursor-resource", "{\"n\":1}");
        MvcResult second = append("CURSOR_EVENT", actor, "cursor-resource", "{\"n\":2}");
        MvcResult third = append("CURSOR_EVENT", actor, "cursor-resource", "{\"n\":3}");
        long firstSeq = objectMapper.readTree(first.getResponse().getContentAsString()).path("seq").asLong();
        long secondSeq = objectMapper.readTree(second.getResponse().getContentAsString()).path("seq").asLong();
        long thirdSeq = objectMapper.readTree(third.getResponse().getContentAsString()).path("seq").asLong();

        MvcResult pageOneResult = mockMvc.perform(get("/audit/events")
                        .header("X-API-Key", READER).param("actorId", actor)
                        .param("limit", "1").param("order", "asc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items", hasSize(1)))
                .andReturn();
        JsonNode pageOne = objectMapper.readTree(pageOneResult.getResponse().getContentAsString());
        String cursor = pageOne.path("nextCursor").textValue();
        append("CURSOR_EVENT", actor, "cursor-resource", "{\"n\":4}");
        mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                        .param("actorId", actor).param("limit", "1")
                        .param("order", "asc").param("cursor", cursor))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[0].seq").value(secondSeq));
        mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                        .param("actorId", actor).param("limit", "1")
                        .param("order", "desc").param("cursor", cursor))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                        .param("actorId", actor + "-different").param("limit", "1")
                        .param("order", "asc").param("cursor", cursor))
                .andExpect(status().isUnprocessableEntity());
        mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                        .param("actorId", actor).param("limit", "1")
                        .param("order", "asc").param("cursor", cursor.substring(0, cursor.length() - 2) + "xx"))
                .andExpect(status().isUnprocessableEntity());

        mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                        .param("actorId", actor).param("order", "desc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[0].seq").value(thirdSeq + 1))
                .andExpect(jsonPath("$.items[1].seq").value(thirdSeq))
                .andExpect(jsonPath("$.items[2].seq").value(secondSeq))
                .andExpect(jsonPath("$.items[3].seq").value(firstSeq));
    }

    @Test
    void mapsUnsupportedMethodsAndDatabaseConflictsWithoutLeakingDetails() throws Exception {
        mockMvc.perform(put("/audit/events/{id}", "event")
                        .header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.error.code").value("METHOD_NOT_ALLOWED"));

        repository.writeTransaction(connection -> {
            try (Statement statement = connection.createStatement()) {
                statement.execute("""
                        CREATE TRIGGER api_conflict
                        BEFORE INSERT ON audit_events
                        BEGIN SELECT RAISE(ABORT, 'private database details'); END
                        """);
            }
            return null;
        });
        try {
            mockMvc.perform(post("/audit/events").header("X-API-Key", WRITER)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(eventJson("CONFLICT_TEST", "actor", "resource", "{}")))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.error.code").value("CONFLICT"))
                    .andExpect(jsonPath("$.error.message").value(
                            "The requested change conflicts with existing audit data"));
        } finally {
            repository.writeTransaction(connection -> {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("DROP TRIGGER api_conflict");
                }
                return null;
            });
        }
    }

    @Test
    void mapsDatabaseBusyToSafeServiceUnavailableEnvelope() {
        ApiErrorResponse response = new ApiExceptionHandler()
                .storageBusy(new StorageBusyException(new java.sql.SQLException("private db detail")))
                .getBody();

        org.junit.jupiter.api.Assertions.assertEquals("STORAGE_BUSY", response.error().code());
        org.junit.jupiter.api.Assertions.assertEquals(
                "Audit storage is temporarily unavailable", response.error().message());
        org.junit.jupiter.api.Assertions.assertTrue(response.error().details().isEmpty());
    }

    @Test
    void serializesConcurrentHttpAppends() throws Exception {
        String actor = "parallel-" + UUID.randomUUID();
        var executor = Executors.newFixedThreadPool(8);
        try {
            List<Callable<Long>> calls = new ArrayList<>();
            for (int index = 0; index < 16; index++) {
                int number = index;
                calls.add(() -> {
                    MvcResult result = append(
                            "PARALLEL_EVENT", actor, "parallel-resource",
                            "{\"index\":" + number + "}");
                    return objectMapper.readTree(result.getResponse().getContentAsString())
                            .path("seq").asLong();
                });
            }
            List<Long> sequences = new ArrayList<>();
            for (var future : executor.invokeAll(calls)) {
                sequences.add(future.get());
            }
            org.junit.jupiter.api.Assertions.assertEquals(16, sequences.stream().distinct().count());
            org.junit.jupiter.api.Assertions.assertEquals(
                    sequences.stream().min(Long::compareTo).orElseThrow() + 15,
                    sequences.stream().max(Long::compareTo).orElseThrow());
            mockMvc.perform(get("/audit/events").header("X-API-Key", READER)
                            .param("actorId", actor).param("limit", "100"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.items", hasSize(16)));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void adminCreatesOnDemandCheckpointAndOtherRolesAreRefused() throws Exception {
        append("CHECKPOINT_TEST", "actor-cp", "resource-cp", "{}");
        mockMvc.perform(post("/audit/admin/checkpoints").header("X-API-Key", AUDITOR))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/audit/admin/checkpoints"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/audit/admin/checkpoints").header("X-API-Key", ADMIN))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.type").value("audit-checkpoint/v1"))
                .andExpect(jsonPath("$.ledgerId").value("http-test-ledger"))
                .andExpect(jsonPath("$.signature").isString());
        mockMvc.perform(get("/audit/verify").header("X-API-Key", AUDITOR))
                .andExpect(jsonPath("$.intact").value(true));
    }

    private MvcResult append(String type, String actor, String resourceId, String payload)
            throws Exception {
        return mockMvc.perform(post("/audit/events")
                        .header("X-API-Key", WRITER)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(eventJson(type, actor, resourceId, payload)))
                .andExpect(status().isCreated())
                .andReturn();
    }

    private long ledgerHead() throws Exception {
        String body = mockMvc.perform(get("/audit/verify").header("X-API-Key", AUDITOR))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return objectMapper.readTree(body).path("headSeq").asLong();
    }

    private static String eventJson(String type, String actor, String resourceId, String payload) {
        return "{\"eventType\":\"" + type
                + "\",\"actorId\":\"" + actor
                + "\",\"resourceType\":\"CLIENT_ACCOUNT"
                + "\",\"resourceId\":\"" + resourceId
                + "\",\"payload\":" + payload + "}";
    }

    @TestConfiguration
    static class FixedClockConfiguration {
        @Bean
        @Primary
        Clock fixedAuditClock() {
            return Clock.fixed(Instant.parse("2026-10-18T14:59:00Z"), ZoneOffset.UTC);
        }
    }
}
