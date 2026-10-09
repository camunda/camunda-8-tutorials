# AI Agent Chat With Tools Example

Ask the agent a question, let it use tools, then review its answer or send a follow-up request.

This example uses an [AI Agent Sub-process](https://docs.camunda.io/docs/components/connectors/out-of-the-box-connectors/agentic-ai-aiagent-subprocess/) and requires **Camunda 8.10.0+**. The tools need internet access.

## 🚀 Zero-config LLM on Camunda SaaS

The example is set up for the **Camunda-provided LLM**. You do not need your own LLM credentials. Check [access and budget requirements](https://docs.camunda.io/docs/components/agentic-orchestration/camunda-provided-llm/). If it is not available, follow [Use your own LLM provider](#use-your-own-llm-provider).

1. Import the [AI Agent Chat Quick Start from Marketplace](https://marketplace.camunda.com/en-US/apps/587865/ai-agent-chat-quick-start) into Camunda Hub.
2. Open the diagram, then open **Test mode**.
3. Follow the Test mode instructions to deploy and start the process. Enter `Find me a recipe for pasta` in the start form.
4. Open **User Feedback** to read the answer.
5. Approve the answer to end the process, or enter a follow-up request.

You can also try `Tell me a joke`, `Which users are available?`, or `Which iPhones are available?`. The user and product APIs return sample data.

### Run the low-code tests in Hub

The Marketplace import does not include the live test file. Download [`ai-agent-chat-with-tools.integration.test.json`](./ai-agent-chat-with-tools.integration.test.json), then use **Upload files** on the imported project's page to add it to that project. Open the diagram's **Test tab**, run the suite, and view the results in the run history.

These tests call the LLM and public APIs. They exercise direct answers, tool calls, and the feedback path. You need Camunda-provided LLM access, remaining budget, and internet access.

The tests check that expected tools complete and result variables exist, not answer quality or extra tool calls. Review the answers and check the run history for unexpected calls.

Do not import `ai-agent-chat-with-tools.test.json` into Hub. It mocks the agent and connectors and requires Camunda Process Test (CPT) to run.

## Use your own LLM provider

Use this approach on SaaS without Camunda-provided secrets, or on Self-Managed.

1. Open **AI Agent** in the model.
2. Select your provider, backend, and model. Follow the [provider setup guide](https://docs.camunda.io/docs/components/connectors/out-of-the-box-connectors/agentic-ai-aiagent-model-providers/).
3. Add your provider credentials as secrets. On SaaS, use [cluster secrets](https://docs.camunda.io/docs/components/saas/clusters/manage-secrets/). On Self-Managed, [configure a secret store](https://docs.camunda.io/docs/self-managed/components/orchestration-cluster/core-settings/configuration/properties/#secrets) for the Orchestration Cluster.
4. Replace the `CAMUNDA_PROVIDED_LLM_*` references in **AI Agent** with your provider settings and `camunda.secrets.<name>` references.

Then follow the [SaaS run steps](#-zero-config-llm-on-camunda-saas). Without Hub, deploy the BPMN and forms to your cluster and start an instance in Tasklist. Use **User Feedback** to approve the answer or send a follow-up.

The HTTP tools need no credentials.

## Run end to end with c8run

This runs the real agent and tools locally. You need your own LLM provider, its credentials, and internet access.

1. [Install Camunda 8 Run](https://docs.camunda.io/docs/self-managed/quickstart/developer-quickstart/c8run/install-start/) 8.10.0+.
2. Add your provider secrets to the [local secret store](https://docs.camunda.io/docs/self-managed/quickstart/developer-quickstart/c8run/configuration/#manage-local-secrets). For example, from the c8run directory:

   ```bash
   ./c8run secrets set OPENAI_API_KEY
   ```

   Enter the value at the hidden prompt. Do not put credentials in the BPMN.
3. Configure **AI Agent** as described in [Use your own LLM provider](#use-your-own-llm-provider). Reference the local secret with `=camunda.secrets.OPENAI_API_KEY`.
4. Start c8run using the instructions for your operating system.
5. Open the BPMN in Camunda Desktop Modeler and deploy it with both forms to the local cluster.
6. Open Tasklist at `http://localhost:8080/tasklist`. Start an instance and enter a request.
7. Open **User Feedback**, send a follow-up, then approve the answer to complete the process.

Use Operate at `http://localhost:8080/operate` to inspect the process and any incidents.

## Learn the pro-code tests with Java and Maven

[Camunda Process Test (CPT)](https://docs.camunda.io/docs/apis-tools/testing/getting-started/) runs the process in a test environment. You do not need a running c8run instance.

The process tests supply agent and tool results to check approval, follow-up, and tool paths. The Java connector tests call the public APIs and check the returned data. Neither suite calls an LLM.

### Run locally

You need Java 21+, Maven, and Docker. The connector tests also need internet access. From this example's directory:

```bash
cd test
mvn clean test
```

Reports:

- Coverage: `target/coverage-report/report.html`
- Coverage data: `target/coverage-report/report.json`
- Test results: `target/surefire-reports/`

### Explore the tests

Start with the scenarios in [`ai-agent-chat-with-tools.test.json`](./ai-agent-chat-with-tools.test.json) and their [Java runner](./test/src/test/java/io/camunda/tests/JsonProcessTest.java). For live HTTP connector checks, see [`LiveConnectorIntegrationTest.java`](./test/src/test/java/io/camunda/tests/LiveConnectorIntegrationTest.java).

## Customize the example

The agent can find users, search recipes, fetch a joke, and list technology products.

To add a tool, create an activity inside **AI Agent**. Its documentation should explain what it does, when to use it, when not to use it, its inputs, and its results. See [tool definitions](https://docs.camunda.io/docs/components/connectors/out-of-the-box-connectors/agentic-ai-aiagent-tool-definitions/).

The feedback form labels the response as AI-generated. Keep this disclosure visible on each response, including follow-ups, when you change the forms.

Source and support: [camunda/camunda-8-tutorials](https://github.com/camunda/camunda-8-tutorials/tree/main/solutions/ai-agent-chat-with-tools).

_Made with ❤️ by Camunda_
