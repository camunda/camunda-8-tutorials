package io.camunda.tests;

import static io.camunda.process.test.api.CamundaAssert.assertThatProcessInstance;
import static io.camunda.process.test.api.assertions.ElementSelectors.byId;

import io.camunda.client.CamundaClient;
import io.camunda.client.api.command.CompleteAdHocSubProcessResultStep1;
import io.camunda.client.api.response.ProcessInstanceEvent;
import io.camunda.process.test.api.CamundaProcessTestContext;
import io.camunda.process.test.api.CamundaSpringProcessTest;
import io.camunda.process.test.api.assertions.ElementSelector;
import io.camunda.process.test.api.assertions.JobSelectors;
import java.util.ArrayList;
import java.util.List;
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
  private static final String LIST_USERS_ID = "ListUsers";
  private static final String RECIPE_ID = "Search_Recipe";
  private static final String JOKES_ID = "Jokes_API";
  private static final String TECHNOLOGY_PRODUCTS_ID = "Activity_0x3prgn";
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
    runSingleToolSegment(
        LIST_USERS_ID, toolCall("list-users", LIST_USERS_ID, Map.of()));
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - search recipe")
  void callsRecipeSearchConnector() {
    runSingleToolSegment(
        RECIPE_ID,
        toolCall("search-recipe", RECIPE_ID, Map.of("searchQuery", "pasta")));
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - jokes API")
  void callsJokesConnector() {
    runSingleToolSegment(
        JOKES_ID, toolCall("jokes-api", JOKES_ID, Map.of()));
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - technology products")
  void callsTechnologyProductsConnector() {
    runSingleToolSegment(
        TECHNOLOGY_PRODUCTS_ID,
        toolCall("technology-products", TECHNOLOGY_PRODUCTS_ID, Map.of()));
  }

  @Test
  @Timeout(180)
  @DisplayName("E2E - joke and recipe tools complete in one agent turn")
  void completesMultiToolEndToEndPath() {
    final ProcessInstanceEvent instance =
        startAgentSegment("Tell me a safe joke and find a pasta recipe.");

    completeAgent(
        result ->
            result
                .activateElement(JOKES_ID)
                .variables(toolCall("jokes-api", JOKES_ID, Map.of()))
                .activateElement(RECIPE_ID)
                .variables(
                    toolCall(
                        "search-recipe",
                        RECIPE_ID,
                        Map.of("searchQuery", "pasta"))));

    assertThatProcessInstance(instance)
        .hasCompletedElements(byId(JOKES_ID), byId(RECIPE_ID));

    completeAgentResponse();

    assertThatProcessInstance(instance)
        .isTerminated()
        .hasNotActivatedElements(byId(FEEDBACK_ID));
  }

  private void runSingleToolSegment(
      final String toolId, final Map<String, Object> toolVariables) {
    final ProcessInstanceEvent instance =
        client
            .newCreateInstanceCommand()
            .bpmnProcessId(PROCESS_ID)
            .latestVersion()
            .startBeforeElement(toolId)
            .terminateAfterElement(toolId)
            .variables(toolVariables)
            .send()
            .join();

    assertThatProcessInstance(instance)
        .hasCompletedElements(byId(toolId))
        .hasNotActivatedElements(forbiddenElements(toolId))
        .isTerminated();
  }

  private ProcessInstanceEvent startAgentSegment(final String prompt) {
    return client
        .newCreateInstanceCommand()
        .bpmnProcessId(PROCESS_ID)
        .latestVersion()
        .startBeforeElement(AGENT_ID)
        .terminateAfterElement(AGENT_ID)
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

  private static Map<String, Object> toolCall(
      final String id, final String name, final Map<String, Object> arguments) {
    final Map<String, Object> toolCall =
        new java.util.HashMap<>(arguments);
    toolCall.put("_meta", Map.of("id", id, "name", name));
    return Map.of("toolCall", toolCall);
  }

  private static ElementSelector[] forbiddenElements(final String activeToolId) {
    final List<ElementSelector> selectors = new ArrayList<>();
    selectors.add(byId(FEEDBACK_ID));
    for (String toolId :
        List.of(LIST_USERS_ID, RECIPE_ID, JOKES_ID, TECHNOLOGY_PRODUCTS_ID)) {
      if (!toolId.equals(activeToolId)) {
        selectors.add(byId(toolId));
      }
    }
    return selectors.toArray(ElementSelector[]::new);
  }
}
