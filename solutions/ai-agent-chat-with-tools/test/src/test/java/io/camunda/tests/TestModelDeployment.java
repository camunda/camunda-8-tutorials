package io.camunda.tests;

import io.camunda.client.CamundaClient;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

final class TestModelDeployment {

  private static final String AGENT_JOB_TYPE = "io.camunda.agenticai:aiagent:subprocess:2";
  private static final String HTTP_JOB_TYPE = "io.camunda:http-json:1";

  private TestModelDeployment() {}

  static void deploy(final CamundaClient client, final boolean useLiveHttpConnectors) {
    final String productionBpmn = readClasspathResource("/ai-agent-chat-with-tools.bpmn");
    String testableBpmn =
        productionBpmn.replace(
            "type=\"" + AGENT_JOB_TYPE + "\"", "type=\"test:ai-agent:subprocess\"");

    if (!useLiveHttpConnectors) {
      testableBpmn =
          testableBpmn.replace(
              "type=\"" + HTTP_JOB_TYPE + "\"", "type=\"test:http-json\"");
    }

    client
        .newDeployResourceCommand()
        .addResourceBytes(
            testableBpmn.getBytes(StandardCharsets.UTF_8), "ai-agent-chat-with-tools.bpmn")
        .addResourceFromClasspath("ai-agent-chat-initial-request.form")
        .addResourceFromClasspath("ai-agent-chat-user-feedback.form")
        .send()
        .join();
  }

  private static String readClasspathResource(final String path) {
    try (var stream = TestModelDeployment.class.getResourceAsStream(path)) {
      if (stream == null) {
        throw new IllegalStateException("Missing classpath resource: " + path);
      }
      return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException error) {
      throw new UncheckedIOException("Failed to read classpath resource: " + path, error);
    }
  }
}
