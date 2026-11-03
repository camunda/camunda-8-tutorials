package io.camunda.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.time.OffsetDateTime;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Happy path against a running c8run (with connectors) and a local Ollama that has the model the
 * BPMNs use. No mocks. It asserts reachability only (each stage happened), never LLM text.
 * Run with {@code mvn test -Pe2e}. Skips itself when the cluster, the webhook or Ollama is down.
 */
@Tag("e2e")
class E2eHappyPathTest {

    private static final String REST = System.getProperty("e2e.rest", "http://localhost:8080");
    private static final String OLLAMA = System.getProperty("e2e.ollama", "http://localhost:11434");
    private static final String MODEL = "llama3.1:8b";
    private static final Duration DEADLINE = Duration.ofMinutes(8);

    private static final ObjectMapper JSON = new ObjectMapper();
    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void clientDiscoversServerSendsTaskAndGetsCallback() throws Exception {
        assumeTrue(ok(REST + "/v2/topology"), "Camunda is not reachable at " + REST + " (start c8run)");
        assumeTrue(ollamaHasModel(), "Ollama is not reachable at " + OLLAMA + " or lacks " + MODEL + " (ollama pull " + MODEL + ")");

        final Path dir = Path.of("..").toAbsolutePath().normalize();
        deploy(dir, "server-request-validation.dmn", "03-server-agent.bpmn", "04-a2a-task.bpmn", "02-a2a-server.bpmn", "01-client-agent.bpmn");

        final String started = OffsetDateTime.now().minusSeconds(2).toString();
        final String clientKey = post("/v2/process-instances", Map.of("processDefinitionId", "a2a-client")).path("processInstanceKey").asText();

        await(() -> state(clientKey).matches("COMPLETED|TERMINATED"), "client 01 to finish");
        assertThat(state(clientKey)).as("01 client").isEqualTo("COMPLETED");

        assertThat(completed(clientKey, "FetchAgentCard")).as("Agent Card fetched in 01").isTrue();
        assertThat(completed(clientKey, "A2ATaskResult")).as("callback caught in 01").isTrue();
        assertThat(instances("a2a-rpc", started)).as("02 instances").isGreaterThan(0);
        assertThat(instances("a2a-task", started)).as("04 instances").isGreaterThan(0);
    }

    // Plain HTTP on purpose: Camunda client builders pick up CAMUNDA_*/ZEEBE_* env vars and could hit a SaaS cluster.
    private JsonNode post(String path, Object body) throws Exception {
        final HttpResponse<String> r = http.send(
                HttpRequest.newBuilder(URI.create(REST + path)).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body))).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(r.statusCode()).as(path + " -> " + r.body()).isLessThan(300);
        return JSON.readTree(r.body());
    }

    private void deploy(Path dir, String... files) throws Exception {
        final String boundary = "e2e" + System.nanoTime();
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (final String f : files) {
            out.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"resources\"; filename=\"" + f
                    + "\"\r\nContent-Type: application/octet-stream\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            out.write(Files.readAllBytes(dir.resolve(f)));
            out.write("\r\n".getBytes(StandardCharsets.UTF_8));
        }
        out.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        final HttpResponse<String> r = http.send(
                HttpRequest.newBuilder(URI.create(REST + "/v2/deployments"))
                        .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                        .POST(HttpRequest.BodyPublishers.ofByteArray(out.toByteArray())).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(r.statusCode()).as("deploy -> " + r.body()).isLessThan(300);
    }

    private String state(String key) throws Exception {
        final HttpResponse<String> r = http.send(
                HttpRequest.newBuilder(URI.create(REST + "/v2/process-instances/" + key)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return JSON.readTree(r.body()).path("state").asText();
    }

    private boolean completed(String instanceKey, String elementId) throws Exception {
        return post("/v2/element-instances/search", Map.of("filter",
                Map.of("processInstanceKey", instanceKey, "elementId", elementId, "state", "COMPLETED")))
                .path("items").size() > 0;
    }

    private int instances(String processId, String since) throws Exception {
        return post("/v2/process-instances/search", Map.of("filter",
                Map.of("processDefinitionId", processId, "startDate", Map.of("$gte", since))))
                .path("items").size();
    }

    private void await(Check condition, String what) throws Exception {
        final long end = System.nanoTime() + DEADLINE.toNanos();
        while (System.nanoTime() < end) {
            if (condition.test()) {
                return;
            }
            Thread.sleep(2000);
        }
        throw new AssertionError("Timed out after " + DEADLINE + " waiting for " + what);
    }

    @FunctionalInterface
    private interface Check {
        boolean test() throws Exception;
    }

    private boolean ok(String url) {
        try {
            final HttpResponse<Void> r = http.send(
                    HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.discarding());
            return r.statusCode() < 400;
        } catch (final Exception e) {
            return false;
        }
    }

    private boolean ollamaHasModel() {
        try {
            return http.send(
                            HttpRequest.newBuilder(URI.create(OLLAMA + "/api/tags")).timeout(Duration.ofSeconds(5)).GET().build(),
                            HttpResponse.BodyHandlers.ofString())
                    .body().contains("\"" + MODEL + "\"");
        } catch (final Exception e) {
            return false;
        }
    }
}
