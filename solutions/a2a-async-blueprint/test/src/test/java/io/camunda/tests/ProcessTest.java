package io.camunda.tests;

import io.camunda.process.test.api.testCases.TestCase;
import io.camunda.process.test.api.testCases.TestCaseRunner;
import io.camunda.process.test.api.testCases.TestCaseSource;
import io.camunda.process.test.api.TestDeployment;
import org.junit.jupiter.params.ParameterizedTest;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Runs every scenario in {@code src/test/resources/scenarios} (one {@code .test.json} per process,
 * {@code 01} to {@code 04}) against an embedded engine.
 * The FEEL-level cases live in {@link FeelCasesTest}.
 */
@TestDeployment(resources = {"01-client-agent.bpmn", "02-a2a-server.bpmn", "03-server-agent.bpmn", "04-a2a-task.bpmn", "server-request-validation.dmn"})
public class ProcessTest extends A2ABlueprintTest {

    @Autowired
    private TestCaseRunner testCaseRunner;

    @ParameterizedTest
    @TestCaseSource(directory = "/scenarios")
    void shouldPass(final TestCase testCase, final String fileName) {
        testCaseRunner.run(testCase);
    }
}
