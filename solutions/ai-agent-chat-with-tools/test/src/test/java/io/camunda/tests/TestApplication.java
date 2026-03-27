package io.camunda.tests;

import io.camunda.process.test.api.TestDeployment;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Minimal Spring Boot application context for CPT tests.
 *
 * Since this is a standalone test harness (no main Camunda Spring Boot application),
 * @TestDeployment explicitly tells CPT which resources to deploy on test startup.
 * This covers the main process BPMN (from ../) and all wrapper BPMNs for connector tests.
 */
@SpringBootApplication
public class TestApplication {
    // No main method — only used as the Spring Boot bootstrap class for tests.
    // Resources are deployed via @TestDeployment on each test class.
}
