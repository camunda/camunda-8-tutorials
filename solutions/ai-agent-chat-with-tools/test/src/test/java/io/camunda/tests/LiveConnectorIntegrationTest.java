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
  private static final String USER_FIXTURE =
      "toolCallResult != null and count(toolCallResult) > 0"
          + " and (some user in toolCallResult satisfies"
          + " user.id = 1"
          + " and user.name = \"Leanne Graham\""
          + " and user.username = \"Bret\")";
  private static final String RECIPE_FIXTURE =
      "toolCallResult != null and count(toolCallResult) > 0"
          + " and (some recipe in toolCallResult satisfies"
          + " recipe.id = 4"
          + " and recipe.name = \"Chicken Alfredo Pasta\")";
  private static final String NON_EMPTY_TEXT =
      "toolCallResult instance of string and string length(toolCallResult) > 0";
  private static final String TECHNOLOGY_FIXTURE =
      "toolCallResult != null and toolCallResult.status = 200"
          + " and count(toolCallResult.body) > 0"
          + " and (some product in toolCallResult.body satisfies"
          + " product.id = \"1\""
          + " and product.name = \"Google Pixel 6 Pro\")";
  private static final String USER_AND_TECHNOLOGY_PAYLOADS =
      "count(toolCallResults) >= 2"
          + " and (every result in toolCallResults satisfies"
          + " result.name in [\"ListUsers\", \"Activity_0x3prgn\"])"
          + " and (some result in toolCallResults satisfies"
          + " result.name = \"ListUsers\""
          + " and result.content != null"
          + " and (some user in result.content satisfies"
          + " user.id = 1"
          + " and user.name = \"Leanne Graham\""
          + " and user.username = \"Bret\"))"
          + " and (some result in toolCallResults satisfies"
          + " result.name = \"Activity_0x3prgn\""
          + " and result.content != null"
          + " and result.content.status = 200"
          + " and (some product in result.content.body satisfies"
          + " product.id = \"1\""
          + " and product.name = \"Google Pixel 6 Pro\"))";
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
        LIST_USERS_ID,
        toolCall("list-users", LIST_USERS_ID, Map.of()),
        USER_FIXTURE);
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - search recipe")
  void callsRecipeSearchConnector() {
    runSingleToolSegment(
        RECIPE_ID,
        toolCall("search-recipe", RECIPE_ID, Map.of("searchQuery", "pasta")),
        RECIPE_FIXTURE);
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - jokes API")
  void callsJokesConnector() {
    runSingleToolSegment(
        JOKES_ID,
        toolCall("jokes-api", JOKES_ID, Map.of()),
        NON_EMPTY_TEXT);
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - technology products")
  void callsTechnologyProductsConnector() {
    runSingleToolSegment(
        TECHNOLOGY_PRODUCTS_ID,
        toolCall("technology-products", TECHNOLOGY_PRODUCTS_ID, Map.of()),
        TECHNOLOGY_FIXTURE);
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - user and technology payloads in one agent segment")
  void completesMultiToolConnectorPath() {
    final ProcessInstanceEvent instance =
        startAgentSegment(
            "List the available users and tell me which sample technology products are available.");

    completeAgent(
        result ->
            result
                .activateElement(LIST_USERS_ID)
                .variables(toolCall("list-users", LIST_USERS_ID, Map.of()))
                .activateElement(TECHNOLOGY_PRODUCTS_ID)
                .variables(
                    toolCall(
                        "technology-products",
                        TECHNOLOGY_PRODUCTS_ID,
                        Map.of())));

    assertThatProcessInstance(instance)
        .hasCompletedElements(byId(LIST_USERS_ID), byId(TECHNOLOGY_PRODUCTS_ID))
        .hasLocalVariableSatisfiesExpression(
            byId(AGENT_ID),
            "toolCallResults",
            USER_AND_TECHNOLOGY_PAYLOADS);

    completeAgentResponse();

    assertThatProcessInstance(instance)
        .isTerminated()
        .hasNotActivatedElements(
            byId(RECIPE_ID), byId(JOKES_ID), byId(FEEDBACK_ID));
  }

  @Test
  @Timeout(180)
  @DisplayName("E2E topology - all four tools across reject and approve")
  void completesFeedbackLoopWithLiveConnectors() {
    final ProcessInstanceEvent instance =
        client
            .newCreateInstanceCommand()
            .bpmnProcessId(PROCESS_ID)
            .latestVersion()
            .variables(
                Map.of(
                    "inputText",
                    "Tell me a safe joke and find a pasta recipe.",
                    "inputDocuments",
                    new Object[0]))
            .send()
            .join();

    completeAgent(
        result ->
            result
                .activateElement(JOKES_ID)
                .variables(toolCall("jokes-feedback", JOKES_ID, Map.of()))
                .activateElement(RECIPE_ID)
                .variables(
                    toolCall(
                        "recipe-feedback",
                        RECIPE_ID,
                        Map.of("searchQuery", "pasta"))));

    assertThatProcessInstance(instance)
        .hasCompletedElements(byId(JOKES_ID), byId(RECIPE_ID));

    completeAgentResponse();
    assertThatProcessInstance(instance).hasActiveElements(byId(FEEDBACK_ID));

    processTestContext.completeUserTask(
        FEEDBACK_ID,
        Map.of(
            "userSatisfied",
            false,
            "followUpInput",
            "That is helpful, but please also list the available users and tell me which sample technology products are available.",
            "followUpDocuments",
            new Object[0]));

    completeAgent(
        result ->
            result
                .activateElement(LIST_USERS_ID)
                .variables(toolCall("list-users-feedback", LIST_USERS_ID, Map.of()))
                .activateElement(TECHNOLOGY_PRODUCTS_ID)
                .variables(
                    toolCall(
                        "technology-products-feedback",
                        TECHNOLOGY_PRODUCTS_ID,
                        Map.of())));

    assertThatProcessInstance(instance)
        .hasCompletedElements(byId(LIST_USERS_ID), byId(TECHNOLOGY_PRODUCTS_ID));

    completeAgentResponse();
    assertThatProcessInstance(instance).hasActiveElements(byId(FEEDBACK_ID));

    processTestContext.completeUserTask(
        FEEDBACK_ID, Map.of("userSatisfied", true));

    assertThatProcessInstance(instance)
        .isCompleted()
        .hasCompletedElement(byId(AGENT_ID), 2)
        .hasCompletedElement(byId(FEEDBACK_ID), 2)
        .hasCompletedElements(
            byId(JOKES_ID),
            byId(RECIPE_ID),
            byId(LIST_USERS_ID),
            byId(TECHNOLOGY_PRODUCTS_ID));
  }

  private void runSingleToolSegment(
      final String toolId,
      final Map<String, Object> toolVariables,
      final String payloadExpression) {
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
        .hasVariableSatisfiesExpression("toolCallResult", payloadExpression)
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
