package io.camunda.tests;

import static io.camunda.process.test.api.CamundaAssert.assertThat;
import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.client.CamundaClient;
import io.camunda.client.api.response.ProcessInstanceEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import io.camunda.process.test.api.TestDeployment;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Headless-only coverage of the FEEL logic in 04-a2a-task.bpmn:
 * the outcome mapping on the TaskDone end event and the cancellation script.
 * BPMN element coverage is already reached by the Test Studio scenarios.
 */
@TestDeployment(resources = {"01-client-agent.bpmn", "02-a2a-server.bpmn", "03-server-agent.bpmn", "04-a2a-task.bpmn", "server-request-validation.dmn"})
public class FeelCasesTest extends A2ABlueprintTest {

    private static final String PROCESS_ID = "a2a-task";
    private static final String FAILED_TEXT = "The agent could not complete the request.";
    private static final String UNGROUNDED_TEXT = "The agent did not return the required placeholder tool result.";
    private static final Map<String, Object> EVIDENCE = Map.of("value", "Example input");

    @Autowired private CamundaClient client;

    // ---------- Outcome mapping on the TaskDone end event ----------

    record OutcomeCase(
            String name, Map<String, Object> agent, String state, String text, List<String> newArtifacts) {
        @Override
        public String toString() {
            return name;
        }
    }

    static Stream<OutcomeCase> outcomeCases() {
        return Stream.of(
                new OutcomeCase("agent job failed (no agent result)", null, "TASK_STATE_FAILED", FAILED_TEXT, List.of()),
                new OutcomeCase(
                        "tool result is an object",
                        agent("Done.", toolResults(result("upperCase", EVIDENCE))),
                        "TASK_STATE_COMPLETED",
                        "Placeholder tool completed.",
                        List.of("placeholder")),
                new OutcomeCase(
                        "tool result is wrapped in a typed list",
                        agent(
                                "Done.",
                                toolResults(result("upperCase", List.of(Map.of("type", "object", "content", EVIDENCE))))),
                        "TASK_STATE_COMPLETED",
                        "Placeholder tool completed.",
                        List.of("placeholder")),
                new OutcomeCase(
                        "latest of several tool results wins",
                        agent(
                                "Done.",
                                toolResults(result("upperCase", Map.of("value", "old"))),
                                toolResults(result("upperCase", EVIDENCE))),
                        "TASK_STATE_COMPLETED",
                        "Placeholder tool completed.",
                        List.of("placeholder")),
                new OutcomeCase(
                        "other tools are ignored - responseText is trimmed",
                        agent("  I could not do that.  ", toolResults(result("other_tool", EVIDENCE))),
                        "TASK_STATE_FAILED",
                        "I could not do that.",
                        List.of()),
                new OutcomeCase(
                        "no tool call - responseText is trimmed",
                        agent("  Please share your input.  "),
                        "TASK_STATE_FAILED",
                        "Please share your input.",
                        List.of()),
                new OutcomeCase(
                        "no tool call and no responseText - default text",
                        agent(null),
                        "TASK_STATE_FAILED",
                        UNGROUNDED_TEXT,
                        List.of()),
                new OutcomeCase(
                        "responseText is not a string - default text",
                        agent(42),
                        "TASK_STATE_FAILED",
                        UNGROUNDED_TEXT,
                        List.of()),
                new OutcomeCase(
                        "tool returned null - not grounded",
                        agent("Done.", toolResults(result("upperCase", null))),
                        "TASK_STATE_FAILED",
                        "Done.",
                        List.of()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("outcomeCases")
    @SuppressWarnings("unchecked")
    void taskDoneAppliesOutcomeToTask(final OutcomeCase c) {
        final var keep = Map.<String, Object>of("artifactId", "a-keep", "name", "keep", "parts", List.of());
        final var priorMessage = Map.<String, Object>of("messageId", "m-0", "role", "ROLE_USER", "parts", List.of());
        final var task = Map.<String, Object>of(
                "id", "task-1",
                "contextId", "ctx-1",
                "rev", 4,
                "status", Map.of("state", "TASK_STATE_WORKING"),
                "artifacts", List.of(keep),
                "history", List.of(priorMessage));
        final var variables = new java.util.HashMap<String, Object>();
        variables.put("task", task);
        if (c.agent() != null) {
            variables.put("agent", c.agent());
        }

        final ProcessInstanceEvent instance = startAtTaskDone(variables);

        assertThat(instance).isCompleted();
        assertThat(instance)
                .hasVariableSatisfies(
                        "task",
                        Map.class,
                        t -> {
                            assertThat(t.get("id")).isEqualTo("task-1");
                            assertThat(t.get("contextId")).isEqualTo("ctx-1");
                            assertThat(t.get("rev")).isEqualTo(5);
                            assertThat(t.get("responseMode")).isEqualTo("task");

                            final var status = (Map<String, Object>) t.get("status");
                            assertThat(status.get("state")).isEqualTo(c.state());
                            assertThat((String) status.get("timestamp")).matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z");
                            final var statusMessage = (Map<String, Object>) status.get("message");
                            assertThat(statusMessage.get("role")).isEqualTo("ROLE_AGENT");
                            assertThat(((List<Map<String, Object>>) statusMessage.get("parts")).get(0).get("text"))
                                    .isEqualTo(c.text());

                            // The agent message is appended once; earlier history and artifacts are preserved.
                            final var history = (List<Map<String, Object>>) t.get("history");
                            assertThat(history).hasSize(2);
                            assertThat(history.get(0)).isEqualTo(priorMessage);
                            assertThat(history.get(1).get("taskId")).isEqualTo("task-1");

                            final var artifacts = (List<Map<String, Object>>) t.get("artifacts");
                            final var expected = new ArrayList<String>();
                            expected.add("keep");
                            expected.addAll(c.newArtifacts());
                            assertThat(artifacts.stream().map(a -> (String) a.get("name"))).containsExactlyElementsOf(expected);
                            if (!c.newArtifacts().isEmpty()) {
                                final var parts = (List<Map<String, Object>>) artifacts.get(1).get("parts");
                                assertThat(parts.get(0).get("data")).isEqualTo(EVIDENCE);
                            }
                        });
    }

    // ---------- Cancellation script ----------

    @ParameterizedTest(name = "cancel while {0} -> {1}")
    @MethodSource("cancelCases")
    @SuppressWarnings("unchecked")
    void cancelOnlyChangesTasksThatAreNotFinal(final String fromState, final String toState) {
        final var task = taskIn(fromState, "task-" + fromState);
        final var instance = start(task);

        client.newPublishMessageCommand()
                .messageName("a2a-cancel")
                .correlationKey("task-" + fromState)
                .send()
                .join();

        assertThat(instance).isCompleted();
        assertThat(instance)
                .hasVariableSatisfies(
                        "task",
                        Map.class,
                        t -> {
                            final var status = (Map<String, Object>) t.get("status");
                            assertThat(status.get("state")).isEqualTo(toState);
                            if (fromState.equals(toState)) {
                                assertThat(t).isEqualTo(task);
                            } else {
                                assertThat(t.get("rev")).isEqualTo(3);
                                assertThat((List<?>) t.get("artifacts")).isEmpty();
                                assertThat(status.get("timestamp")).isNotNull();
                            }
                        });
    }

    static Stream<Arguments> cancelCases() {
        return Stream.of(
                Arguments.of("TASK_STATE_SUBMITTED", "TASK_STATE_CANCELED"),
                Arguments.of("TASK_STATE_WORKING", "TASK_STATE_CANCELED"),
                Arguments.of("TASK_STATE_INPUT_REQUIRED", "TASK_STATE_CANCELED"),
                Arguments.of("TASK_STATE_COMPLETED", "TASK_STATE_COMPLETED"),
                Arguments.of("TASK_STATE_FAILED", "TASK_STATE_FAILED"),
                Arguments.of("TASK_STATE_CANCELED", "TASK_STATE_CANCELED"),
                Arguments.of("TASK_STATE_REJECTED", "TASK_STATE_REJECTED"));
    }

    @Test
    void cancelForAnotherTaskIsIgnored() {
        final var instance = start(taskIn("TASK_STATE_WORKING", "task-mine"));

        client.newPublishMessageCommand()
                .messageName("a2a-cancel")
                .correlationKey("task-other")
                .send()
                .join();

        assertThat(instance).hasActiveElements("AgentTools").hasNoActiveElements("A2ASetCanceled");
    }

    // ---------- Authenticated push callback ----------

    @Test
    void pushCarriesBearerCredentialsAndNotificationToken() {
        client.newCreateInstanceCommand()
                .bpmnProcessId(PROCESS_ID)
                .latestVersion()
                .startBeforeElement("PushConfigured")
                .variables(Map.of(
                        "task", Map.of(
                                "id", "task-push",
                                "contextId", "ctx-1",
                                "rev", 2,
                                "status", Map.of("state", "TASK_STATE_COMPLETED"),
                                "artifacts", List.of(),
                                "history", List.of()),
                        "push", Map.of(
                                "url", "https://client.example.invalid/callback",
                                "dialect", "1.0",
                                "token", "notify-token",
                                "authentication", Map.of("scheme", "Bearer", "credentials", "secret-value"))))
                .send()
                .join();

        final var job = client.newActivateJobsCommand()
                .jobType("io.camunda:http-json:1")
                .maxJobsToActivate(1)
                .requestTimeout(java.time.Duration.ofSeconds(5))
                .send()
                .join()
                .getJobs()
                .get(0);

        @SuppressWarnings("unchecked")
        final var headers = (Map<String, Object>) job.getVariablesAsMap().get("headers");
        assertThat(headers.get("Authorization")).isEqualTo("Bearer secret-value");
        assertThat(headers.get("X-A2A-Notification-Token")).isEqualTo("notify-token");
        assertThat(job.getVariablesAsMap().get("url")).isEqualTo("https://client.example.invalid/callback");
    }

    // ---------- Helpers ----------

    private ProcessInstanceEvent start(final Map<String, Object> task) {
        return client.newCreateInstanceCommand()
                .bpmnProcessId(PROCESS_ID)
                .latestVersion()
                .startBeforeElement("AgentTools")
                .variables(Map.of("req", Map.of("message", Map.of("parts", List.of())), "task", task))
                .send()
                .join();
    }

    private ProcessInstanceEvent startAtTaskDone(final Map<String, Object> variables) {
        return client.newCreateInstanceCommand()
                .bpmnProcessId(PROCESS_ID)
                .latestVersion()
                .startBeforeElement("TaskDone")
                .variables(variables)
                .send()
                .join();
    }

    private static Map<String, Object> taskIn(final String state, final String id) {
        return Map.of(
                "id", id,
                "contextId", "ctx-1",
                "rev", 2,
                "status", Map.of("state", state),
                "artifacts", List.of(Map.of("artifactId", "a-1", "name", "answer", "parts", List.of())),
                "history", List.of());
    }

    private static Map<String, Object> agent(final Object responseText, final Map<String, Object>... messages) {
        final var agent = new java.util.HashMap<String, Object>();
        agent.put("responseText", responseText);
        agent.put("context", Map.of("conversation", Map.of("messages", List.of(messages))));
        return agent;
    }

    private static Map<String, Object> toolResults(final Map<String, Object>... results) {
        return Map.of("role", "tool_call_result", "results", List.of(results));
    }

    private static Map<String, Object> result(final String name, final Object content) {
        final var result = new java.util.HashMap<String, Object>();
        result.put("id", "call-" + name);
        result.put("name", name);
        result.put("content", content);
        return result;
    }
}
