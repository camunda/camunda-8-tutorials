package io.camunda.tests;

import static io.camunda.process.test.api.CamundaAssert.assertThatProcessInstance;
import static io.camunda.process.test.api.CamundaAssert.assertThatUserTask;
import static io.camunda.process.test.api.assertions.ElementSelectors.byId;
import static io.camunda.process.test.api.assertions.UserTaskSelectors.byElementId;

import io.camunda.client.CamundaClient;
import io.camunda.client.api.response.ProcessInstanceEvent;
import io.camunda.client.api.search.enums.UserTaskState;
import io.camunda.process.test.api.CamundaAssert;
import io.camunda.process.test.api.CamundaProcessTestContext;
import io.camunda.process.test.api.CamundaSpringProcessTest;
import io.camunda.process.test.api.TestDeployment;
import java.time.Duration;
import java.util.Map;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Integration tests for ai-agent-chat-with-tools using CPT's managed runtime.
 *
 * runtime-mode=managed starts an embedded Zeebe engine + full connector runtime (Docker).
 * This means the agenticai connector and HTTP JSON connector run for real, against real APIs.
 *
 * Two test groups:
 *   1. REST endpoint tests — each test activates one segment of the consolidated test BPMN
 *      using startBeforeElement(). One BPMN, one deployment, one process ID for all tools.
 *   2. Agent tests — verify specific prompts trigger expected tool calls via real Bedrock
 *
 * After each agent test passes, capture the agent output for mock data:
 *   - Check test output for the "CAPTURE FOR MOCK" log line
 *   - Copy the agent JSON to outer-flow.json to create realistic process test mocks
 *
 * Prerequisites:
 *   - Docker running
 *   - AWS_BEDROCK_ACCESS_KEY and AWS_BEDROCK_SECRET_KEY set in environment
 *   - Run: env $(cat ../.env | grep -v '^#' | xargs) mvn clean test -P integration-test
 *
 * Note: Connector runtime startup adds ~30-60s to the first test. @Timeout values account for this.
 * Note: Do NOT use @Nested classes — each nested class gets its own CPT runtime and
 *       does not inherit @TestDeployment from the outer class.
 */
@SpringBootTest(properties = {"camunda.client.worker.defaults.enabled=false"})
@CamundaSpringProcessTest
@TestDeployment(resources = {
    "ai-agent-chat-with-tools.bpmn",
    "ai-agent-chat-initial-request.form",
    "ai-agent-chat-user-feedback.form",
    "ai-agent-chat-human-send-email-request.form",
    "bpmn/test-ai-agent-chat-with-tools.bpmn"
})
public class AgentJavaIT {

    private static final Logger log = LoggerFactory.getLogger(AgentJavaIT.class);
    private static final String PROCESS_ID = "ai-agent-chat-with-tools";

    @Autowired private CamundaClient client;
    @Autowired private CamundaProcessTestContext processTestContext;

    @BeforeAll
    static void configureAssertionTimeout() {
        // CPT default is 10s — too short for agent runs that involve LLM calls + tool calls.
        // Integration tests use real Bedrock and can take 30–120s per agent run.
        CamundaAssert.setAssertionTimeout(Duration.ofMinutes(5));
    }

    // =========================================================================
    // REST endpoint isolation tests
    //
    // Each test activates one segment of the consolidated test BPMN using
    // startBeforeElement(). The real HTTP connector runs against the public API.
    // No mocks. Verifies connector config, FEEL expressions, and API availability.
    //
    // Consolidated test BPMN: bpmn/test-ai-agent-chat-with-tools.bpmn
    // Process ID: test-ai-agent-chat-with-tools
    // Each tool has its own segment: Start_<ToolName> → <ToolName> → End_<ToolName>
    // =========================================================================

    @Test
    @Timeout(120)
    @DisplayName("REST: LoadUserByID — fetches user 1 from jsonplaceholder")
    void loadUserById() {
        var instance = client.newCreateInstanceCommand()
            .bpmnProcessId("test-ai-agent-chat-with-tools")
            .latestVersion()
            .startBeforeElement("Start_LoadUserByID")
            .variables(Map.of("userId", 1))
            .send().join();

        assertThatProcessInstance(instance)
            .hasCompletedElements(byId("End_LoadUserByID"))
            .isCompleted();
    }

    @Test
    @Timeout(120)
    @DisplayName("REST: ListUsers — lists all users from jsonplaceholder")
    void listUsers() {
        var instance = client.newCreateInstanceCommand()
            .bpmnProcessId("test-ai-agent-chat-with-tools")
            .latestVersion()
            .startBeforeElement("Start_ListUsers")
            .send().join();

        assertThatProcessInstance(instance).isCompleted();
    }

    @Test
    @Timeout(120)
    @DisplayName("REST: Search_Recipe — searches 'pizza' on dummyjson")
    void searchRecipe() {
        var instance = client.newCreateInstanceCommand()
            .bpmnProcessId("test-ai-agent-chat-with-tools")
            .latestVersion()
            .startBeforeElement("Start_SearchRecipe")
            .variables(Map.of("searchQuery", "pizza"))
            .send().join();

        assertThatProcessInstance(instance).isCompleted();
    }

    @Test
    @Timeout(120)
    @DisplayName("REST: Jokes_API — fetches a random joke from jokeapi.dev")
    void jokesApi() {
        var instance = client.newCreateInstanceCommand()
            .bpmnProcessId("test-ai-agent-chat-with-tools")
            .latestVersion()
            .startBeforeElement("Start_JokesAPI")
            .send().join();

        assertThatProcessInstance(instance).isCompleted();
    }

    @Test
    @Timeout(120)
    @DisplayName("REST: Fetch_URL — fetches a dynamic URL (jsonplaceholder todo 1)")
    void fetchUrl() {
        var instance = client.newCreateInstanceCommand()
            .bpmnProcessId("test-ai-agent-chat-with-tools")
            .latestVersion()
            .startBeforeElement("Start_FetchURL")
            .variables(Map.of("fetchUrl", "https://jsonplaceholder.typicode.com/todos/1"))
            .send().join();

        assertThatProcessInstance(instance).isCompleted();
    }

    // =========================================================================
    // Agent prompt → tool verification tests
    //
    // Each test uses a prompt crafted to deterministically trigger a specific tool.
    // The agent's system prompt and tool descriptions make these paths predictable.
    // When a test passes, capture the logged agent variable for outer-flow.json mocks.
    // =========================================================================

    @Test
    @Timeout(300)
    @DisplayName("Agent: 'List all users' → agent calls ListUsers tool")
    void shouldCallListUsersTool() {
        var instance = startProcess("List all available users for me. Use only the list users tool.");

        // Assert the ListUsers HTTP connector ran inside the ad-hoc subprocess
        assertThatProcessInstance(instance).hasCompletedElements(byId("ListUsers"));

        // Assert User_Feedback user task is waiting
        assertThatUserTask(byElementId("User_Feedback")).isCreated();

        // Capture agent variable for outer-flow.json mock data
        try {
            var vars = client.newVariableSearchRequest()
                .filter(f -> f.processInstanceKey(instance.getProcessInstanceKey()).name("agent"))
                .send().join();
            vars.items().stream().findFirst().ifPresent(v ->
                log.info("CAPTURE FOR MOCK — agent variable JSON:\n{}", v.getValue()));
        } catch (Exception e) {
            log.warn("Could not query agent variable ({}). Check Operate at http://localhost:8081/operate", e.getMessage());
        }

        processTestContext.completeUserTask(
            byElementId("User_Feedback"), Map.of("userSatisfied", true));

        assertThatProcessInstance(instance).isCompleted();
    }

    @Test
    @Timeout(300)
    @DisplayName("Agent: 'Who is user 1?' → agent calls LoadUserByID tool")
    void shouldCallLoadUserByIdTool() {
        var instance = startProcess("Who is user with ID 1? Use the load user by ID tool to get their details.");

        assertThatProcessInstance(instance).hasCompletedElements(byId("LoadUserByID"));
        assertThatUserTask(byElementId("User_Feedback")).isCreated();

        processTestContext.completeUserTask(
            byElementId("User_Feedback"), Map.of("userSatisfied", true));

        assertThatProcessInstance(instance).isCompleted();
    }

    @Test
    @Timeout(300)
    @DisplayName("Agent: 'Find a pasta recipe' → agent calls Search_Recipe tool")
    void shouldCallSearchRecipeTool() {
        var instance = startProcess("Find me a pasta recipe using the recipe search tool.");

        assertThatProcessInstance(instance).hasCompletedElements(byId("Search_Recipe"));
        assertThatUserTask(byElementId("User_Feedback")).isCreated();

        processTestContext.completeUserTask(
            byElementId("User_Feedback"), Map.of("userSatisfied", true));

        assertThatProcessInstance(instance).isCompleted();
    }

    @Test
    @Timeout(300)
    @DisplayName("Agent: 'Tell me a joke' → agent calls Jokes_API tool")
    void shouldCallJokesApiTool() {
        var instance = startProcess("Tell me a random programming joke using the jokes tool.");

        assertThatProcessInstance(instance).hasCompletedElements(byId("Jokes_API"));
        assertThatUserTask(byElementId("User_Feedback")).isCreated();

        processTestContext.completeUserTask(
            byElementId("User_Feedback"), Map.of("userSatisfied", true));

        assertThatProcessInstance(instance).isCompleted();
    }

    @Test
    @Timeout(300)
    @DisplayName("Agent: 'What time is it?' → agent calls GetDateAndTime tool")
    void shouldCallGetDateAndTimeTool() {
        var instance = startProcess("What is the current date and time? Use the date and time tool.");

        assertThatProcessInstance(instance).hasCompletedElements(byId("GetDateAndTime"));
        assertThatUserTask(byElementId("User_Feedback")).isCreated();

        processTestContext.completeUserTask(
            byElementId("User_Feedback"), Map.of("userSatisfied", true));

        assertThatProcessInstance(instance).isCompleted();
    }

    // =========================================================================
    // E2E tests: full process start → end event
    // These verify outer flow, gateway routing, and process completion
    // =========================================================================

    @Test
    @Timeout(300)
    @DisplayName("E2E: user satisfied on first response → process completes")
    void e2eHappyPath() {
        var instance = startProcess("List all available users.");

        assertThatUserTask(byElementId("User_Feedback")).isCreated();
        processTestContext.completeUserTask(
            byElementId("User_Feedback"), Map.of("userSatisfied", true));

        assertThatProcessInstance(instance)
            .hasCompletedElements(
                byId("StartEvent_1"),
                byId("AI_Agent"),
                byId("User_Feedback"),
                byId("Event_0i39jej"))
            .isCompleted();
    }

    @Test
    @Timeout(600)
    @DisplayName("E2E: user not satisfied → loop → satisfied on second try → process ends")
    void e2eWithLoop() {
        var instance = startProcess("List all available users.");

        // First iteration: user not satisfied, sends follow-up
        assertThatUserTask(byElementId("User_Feedback")).isCreated();
        processTestContext.completeUserTask(
            byElementId("User_Feedback"), Map.of(
                "userSatisfied", false,
                "followUpInput", "Can you also show me the email of each user? Just display them, do not send any emails."
            ));

        // Process loops back — agent runs again with followUpInput.
        // completeAhspUserTasksIfPresent polls until User_Feedback is active,
        // completing any AHSP user tasks (e.g. Human_Send_Email_Request) along the way.
        completeAhspUserTasksIfPresent();

        // Second iteration: User_Feedback is now guaranteed active
        processTestContext.completeUserTask(
            byElementId("User_Feedback"), Map.of("userSatisfied", true));

        assertThatProcessInstance(instance).isCompleted();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * After a User_Feedback completion with userSatisfied=false, the process loops back
     * and the agent runs again inside the AHSP. The AHSP may activate user tasks
     * (e.g. Human_Send_Email_Request) before completing. This helper polls every 2s
     * for up to 5 minutes: completing any AHSP user tasks found, and returning only
     * once User_Feedback is active again (AHSP done). Without this, AHSP hangs waiting
     * for the user task to be completed and the test times out.
     */
    private void completeAhspUserTasksIfPresent() {
        Awaitility.await()
            .atMost(Duration.ofMinutes(5))
            .pollInterval(Duration.ofSeconds(2))
            .until(() -> {
                // Complete any AHSP human-approval tasks that the agent may have activated
                var emailTasks = client.newUserTaskSearchRequest()
                    .filter(f -> f.elementId("Human_Send_Email_Request").state(UserTaskState.CREATED))
                    .send().join();
                emailTasks.items().forEach(task ->
                    processTestContext.completeUserTask(
                        byElementId("Human_Send_Email_Request"),
                        Map.of("sendEmailApproved", false)));

                // Return true once the outer User_Feedback task is active (AHSP completed)
                var feedbackTasks = client.newUserTaskSearchRequest()
                    .filter(f -> f.elementId("User_Feedback").state(UserTaskState.CREATED))
                    .send().join();
                return !feedbackTasks.items().isEmpty();
            });
    }

    private ProcessInstanceEvent startProcess(String inputText) {
        return client.newCreateInstanceCommand()
            .bpmnProcessId(PROCESS_ID)
            .latestVersion()
            .variables(Map.of("inputText", inputText))
            .send()
            .join();
    }
}
