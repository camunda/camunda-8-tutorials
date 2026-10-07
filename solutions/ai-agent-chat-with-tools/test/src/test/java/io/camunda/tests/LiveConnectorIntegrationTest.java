package io.camunda.tests;

import static io.camunda.process.test.api.CamundaAssert.assertThatProcessInstance;
import static io.camunda.process.test.api.assertions.ElementSelectors.byId;

import io.camunda.client.CamundaClient;
import io.camunda.client.api.response.ProcessInstanceEvent;
import io.camunda.process.test.api.CamundaSpringProcessTest;
import io.camunda.process.test.api.assertions.ElementSelector;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
  private static final String LIST_USERS_ID = "LookupSampleUsers";
  private static final String RECIPE_ID = "SearchRecipes";
  private static final String JOKES_ID = "FetchSafeJoke";
  private static final String TECHNOLOGY_PRODUCTS_ID = "ListSampleTechnologyProducts";
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
      "toolCallResult != null and count(toolCallResult) > 0"
          + " and (some product in toolCallResult satisfies"
          + " product.id = \"1\""
          + " and product.name = \"Google Pixel 6 Pro\")";
  @Autowired private CamundaClient client;

  @BeforeEach
  void deployProductionModelWithTestAgentWorker() {
    TestModelDeployment.deploy(client, true);
  }

  @Test
  @Timeout(180)
  @DisplayName("Connector integration - list users")
  void callsLookupSampleUsersConnector() {
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

  private static ElementSelector[] forbiddenElements(final String activeToolId) {
    final List<ElementSelector> selectors = new ArrayList<>();
    selectors.add(byId("UserTask_ReviewAgentResponse"));
    for (String toolId :
        List.of(LIST_USERS_ID, RECIPE_ID, JOKES_ID, TECHNOLOGY_PRODUCTS_ID)) {
      if (!toolId.equals(activeToolId)) {
        selectors.add(byId(toolId));
      }
    }
    return selectors.toArray(ElementSelector[]::new);
  }

  private static Map<String, Object> toolCall(
      final String id, final String name, final Map<String, Object> arguments) {
    final Map<String, Object> toolCall =
        new java.util.HashMap<>(arguments);
    toolCall.put("_meta", Map.of("id", id, "name", name));
    return Map.of("toolCall", toolCall);
  }

}
