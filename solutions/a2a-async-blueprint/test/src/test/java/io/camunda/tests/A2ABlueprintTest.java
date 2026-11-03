package io.camunda.tests;

import io.camunda.process.test.api.CamundaAssert;
import io.camunda.process.test.api.CamundaSpringProcessTest;
import java.time.Duration;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Shared base: all test classes use the same Spring context, so the embedded engine starts only
 * once. Each subclass declares the same {@code @TestDeployment} resource list. Assertions poll
 * quickly and give up after 10 seconds, so failures surface fast.
 */
@SpringBootTest
@CamundaSpringProcessTest
abstract class A2ABlueprintTest {

    @BeforeAll
    static void fastAssertions() {
        CamundaAssert.setAssertionInterval(Duration.ofMillis(20));
        CamundaAssert.setAssertionTimeout(Duration.ofSeconds(10));
    }
}
