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
 * Runs JSON process tests for an agentic process using COMPLETE_JOB_AD_HOC_SUB_PROCESS.
 *
 * Run with: mvn test   (Docker must be running)
 */
@SpringBootTest(properties = {"camunda.client.worker.defaults.enabled=false"})
@CamundaSpringProcessTest
@TestDeployment(resources = {
    "ai-agent-chat-with-mcp.bpmn",
    "ai-agent-chat-initial-request.form",
    "ai-agent-chat-user-feedback.form",
    "mcp-tool-call-confirmation.form"
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
