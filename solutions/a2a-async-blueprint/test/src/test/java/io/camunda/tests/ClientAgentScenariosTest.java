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
 * Runs the Test Studio scenarios (01-client-agent.test.json) against an embedded engine.
 */
@SpringBootTest
@CamundaSpringProcessTest
@TestDeployment(resources = {"01-client-agent.bpmn"})
public class ClientAgentScenariosTest {

    @Autowired
    private TestCaseRunner testCaseRunner;

    @ParameterizedTest
    @TestCaseSource(directory = "/scenarios/01")
    void shouldPass(final TestCase testCase, final String fileName) {
        testCaseRunner.run(testCase);
    }
}
