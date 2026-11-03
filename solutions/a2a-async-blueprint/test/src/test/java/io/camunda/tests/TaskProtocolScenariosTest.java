package io.camunda.tests;

import io.camunda.process.test.api.testCases.TestCase;
import io.camunda.process.test.api.testCases.TestCaseRunner;
import io.camunda.process.test.api.testCases.TestCaseSource;
import io.camunda.process.test.api.TestDeployment;
import org.junit.jupiter.params.ParameterizedTest;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Runs the Test Studio scenarios (04-a2a-task.test.json) against an embedded engine.
 */
@TestDeployment(resources = {"01-client-agent.bpmn", "02-a2a-server.bpmn", "03-server-agent.bpmn", "04-a2a-task.bpmn", "server-request-validation.dmn"})
public class TaskProtocolScenariosTest extends A2ABlueprintTest {

    @Autowired
    private TestCaseRunner testCaseRunner;

    @ParameterizedTest
    @TestCaseSource(directory = "/scenarios/04")
    void shouldPass(final TestCase testCase, final String fileName) {
        testCaseRunner.run(testCase);
    }
}
