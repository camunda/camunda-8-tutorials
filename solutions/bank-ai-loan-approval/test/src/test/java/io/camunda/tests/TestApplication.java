package io.camunda.tests;

import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Minimal Spring Boot application context for CPT tests.
 * Deployment is handled by @TestDeployment on JsonProcessTest.
 */
@SpringBootApplication
public class TestApplication {
    // No main method — only used as the Spring Boot bootstrap class for tests.
}
