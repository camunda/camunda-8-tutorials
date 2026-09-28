package io.camunda.tests;

import static io.camunda.process.test.api.CamundaAssert.assertThatProcessInstance;
import static io.camunda.process.test.api.CamundaAssert.assertThatUserTask;
import static io.camunda.process.test.api.assertions.ElementSelectors.byId;

import io.camunda.client.CamundaClient;
import io.camunda.client.api.command.CompleteAdHocSubProcessResultStep1;
import io.camunda.client.api.response.ProcessInstanceEvent;
import io.camunda.process.test.api.CamundaProcessTestContext;
import io.camunda.process.test.api.CamundaSpringProcessTest;
import io.camunda.process.test.api.assertions.JobSelectors;
import io.camunda.process.test.api.assertions.UserTaskSelectors;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(
    properties = {
      "camunda.client.worker.defaults.enabled=false",
      "io.camunda.process.test.connectors-enabled=true"
    })
@CamundaSpringProcessTest
class LiveConnectorIntegrationTest {

  private static final String PROCESS_ID = "ai-agent-chat-with-tools";
  private static final String AGENT_ID = "AI_Agent";
  private static final String FEEDBACK_ID = "User_Feedback";
  @Autowired private CamundaClient client;
  @Autowired private CamundaProcessTestContext processTestContext;

  @BeforeEach
  void deployProductionModelWithTestAgentWorker() {
    TestModelDeployment.deploy(client, true);
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - list users")
  void callsListUsersConnector() {
    runSingleToolE2E(
        "List all available users.",
        "ListUsers",
        toolCall("list-users", "ListUsers", Map.of()));
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - search recipe")
  void callsRecipeSearchConnector() {
    runSingleToolE2E(
        "Find a pasta recipe.",
        "Search_Recipe",
        toolCall("search-recipe", "Search_Recipe", Map.of("searchQuery", "pasta")));
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - jokes API")
  void callsJokesConnector() {
    runSingleToolE2E(
        "Tell me a safe joke.",
        "Jokes_API",
        toolCall("jokes-api", "Jokes_API", Map.of()));
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - technology products")
  void callsTechnologyProductsConnector() {
    runSingleToolE2E(
        "Which sample technology products are available?",
        "Activity_0x3prgn",
        toolCall("technology-products", "Activity_0x3prgn", Map.of()));
  }

  @Test
  @Timeout(180)
  @DisplayName("E2E - joke and recipe tools complete in one agent turn")
  void completesMultiToolEndToEndPath() {
    final ProcessInstanceEvent instance =
        startProcess("Tell me a safe joke and find a pasta recipe.");

    completeAgent(
        result ->
            result
                .activateElement("Jokes_API")
                .variables(toolCall("jokes-api", "Jokes_API", Map.of()))
                .activateElement("Search_Recipe")
                .variables(
                    toolCall(
                        "search-recipe",
                        "Search_Recipe",
                        Map.of("searchQuery", "pasta"))));

    assertThatProcessInstance(instance)
        .hasCompletedElements(byId("Jokes_API"), byId("Search_Recipe"));

    completeAgentResponse();
    completeFeedback();

    assertThatProcessInstance(instance).isCompleted();
  }

  private void runSingleToolE2E(
      final String prompt, final String toolId, final Map<String, Object> toolVariables) {
    final ProcessInstanceEvent instance = startProcess(prompt);

    completeAgent(result -> result.activateElement(toolId).variables(toolVariables));

    assertThatProcessInstance(instance).hasCompletedElements(byId(toolId));

    completeAgentResponse();
    completeFeedback();

    assertThatProcessInstance(instance).isCompleted();
  }

  private ProcessInstanceEvent startProcess(final String prompt) {
    return client
        .newCreateInstanceCommand()
        .bpmnProcessId(PROCESS_ID)
        .latestVersion()
        .variables(Map.of("inputText", prompt, "inputDocuments", new Object[0]))
        .send()
        .join();
  }

  private void completeAgent(
      final Consumer<CompleteAdHocSubProcessResultStep1> activation) {
    processTestContext.completeJobOfAdHocSubProcess(
        JobSelectors.byElementId(AGENT_ID),
        result -> {
          activation.accept(result);
          result.completionConditionFulfilled(false).cancelRemainingInstances(false);
        });
  }

  private void completeAgentResponse() {
    processTestContext.completeJobOfAdHocSubProcess(
        JobSelectors.byElementId(AGENT_ID),
        Map.of("agent", Map.of("responseText", "The requested tools completed successfully.")),
        result -> result.completionConditionFulfilled(true).cancelRemainingInstances(false));
  }

  private void completeFeedback() {
    assertThatUserTask(UserTaskSelectors.byElementId(FEEDBACK_ID)).isCreated();
    processTestContext.completeUserTask(
        UserTaskSelectors.byElementId(FEEDBACK_ID), Map.of("userSatisfied", true));
  }

  private static Map<String, Object> toolCall(
      final String id, final String name, final Map<String, Object> arguments) {
    final Map<String, Object> toolCall =
        new java.util.HashMap<>(arguments);
    toolCall.put("_meta", Map.of("id", id, "name", name));
    return Map.of("toolCall", toolCall);
  }
}
