package io.camunda.tests;

import io.camunda.process.test.api.CamundaSpringProcessTest;
import io.camunda.process.test.api.TestDeployment;
import io.camunda.process.test.api.testCases.TestCase;
import io.camunda.process.test.api.testCases.TestCaseRunner;
import io.camunda.process.test.api.testCases.TestCaseSource;
import org.junit.jupiter.params.ParameterizedTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Runs JSON process tests from src/test/resources/test-cases/ against an embedded Zeebe engine.
 *
 * The AI agent job (io.camunda.agenticai:aiagent:subprocess:2) is mocked in each test case
 * with controlled output. Tool jobs are controlled in the same way so the
 * complete modeled flow is tested deterministically without credentials or external services.
 *
 * Run with: mvn test   (Docker must be running)
 */
@SpringBootTest(properties = {"camunda.client.worker.defaults.enabled=false"})
@CamundaSpringProcessTest
@TestDeployment(resources = {
    "ai-agent-chat-with-tools.bpmn",
    "ai-agent-chat-initial-request.form",
    "ai-agent-chat-user-feedback.form"
})
public class JsonProcessTest {

    @Autowired
    private TestCaseRunner testCaseRunner;

    @ParameterizedTest
    @TestCaseSource
    void shouldPass(final TestCase testCase, final String filename) {
        testCaseRunner.run(testCase);
    }
}
