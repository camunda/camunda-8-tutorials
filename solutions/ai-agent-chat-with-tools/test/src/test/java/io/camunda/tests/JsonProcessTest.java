package io.camunda.tests;

import io.camunda.client.CamundaClient;
import io.camunda.process.test.api.CamundaSpringProcessTest;
import io.camunda.process.test.api.testCases.TestCase;
import io.camunda.process.test.api.testCases.TestCaseRunner;
import io.camunda.process.test.impl.testCases.TestCasesReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Runs the Maven process scenarios with controlled agent and tool results.
 * No LLM calls or external services are used.
 */
@SpringBootTest(
    properties = {
      "camunda.client.worker.defaults.enabled=false",
      "io.camunda.process.test.connectors-enabled=true"
    })
@CamundaSpringProcessTest
public class JsonProcessTest {

    @Autowired
    private TestCaseRunner testCaseRunner;

    @Autowired
    private CamundaClient client;

    @BeforeEach
    void deployDeterministicTestModel() {
        TestModelDeployment.deploy(client, false);
    }

    @Test
    @DisplayName("Process - direct answer and satisfied user")
    void completesWithoutTools() {
        runScenario("Happy path — user satisfied on first response (no tool calls)");
    }

    @Test
    @DisplayName("Process - feedback loop then satisfied user")
    void completesFeedbackLoop() {
        runScenario("Loop path — user not satisfied, then satisfied on second try");
    }

    @Test
    @DisplayName("Process - deterministic LookupSampleUsers tool path")
    void coversLookupSampleUsersToolPath() {
        runScenario("LookupSampleUsers tool — agent calls LookupSampleUsers then responds");
    }

    @Test
    @DisplayName("Process - deterministic recipe tool path")
    void coversRecipeToolPath() {
        runScenario("SearchRecipes tool — agent searches for a recipe");
    }

    @Test
    @DisplayName("Process - deterministic jokes tool path")
    void coversJokesToolPath() {
        runScenario("FetchSafeJoke tool — agent fetches a random joke");
    }

    @Test
    @DisplayName("Process - deterministic technology products tool path")
    void coversTechnologyProductsToolPath() {
        runScenario("ListSampleTechnologyProducts tool — agent gets list of tech stuff");
    }

    private void runScenario(final String scenarioName) {
        final TestCase testCase = loadScenario(scenarioName);
        testCaseRunner.run(testCase);
    }

    private TestCase loadScenario(final String scenarioName) {
        try (var stream = getClass().getResourceAsStream(
                "/ai-agent-chat-with-tools.test.json")) {
            if (stream == null) {
                throw new IllegalStateException("Missing deterministic test scenarios");
            }
            return new TestCasesReader()
                    .read(stream)
                    .getTestCases()
                    .stream()
                    .filter(testCase -> testCase.getName().equals(scenarioName))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Unknown test scenario: " + scenarioName));
        } catch (IOException error) {
            throw new UncheckedIOException("Failed to read deterministic test scenarios", error);
        }
    }
}
