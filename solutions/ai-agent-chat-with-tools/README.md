# AI Agent Chat With Tools Example

This example demonstrates an AI Agent Sub-process that can answer questions, use external tools, and collect human feedback. The BPMN targets Camunda 8.10+ and uses template ID `io.camunda.connectors.agenticai.ai-agent-subprocess.v2` (template version `1`, job type `io.camunda.agenticai:aiagent:subprocess:2`). The published template is in the [Camunda Connectors 8.10.0 release](https://github.com/camunda/connectors/blob/8.10.0/connectors/agentic-ai/connector-agentic-ai/element-templates/agenticai-ai-agent-subprocess.v2.json).

---

## 🚀 Zero-config LLM on Camunda SaaS

**Running on Camunda SaaS?** This blueprint is pre-configured to use the **Camunda-provided LLM**. When the feature is available and enabled, SaaS-managed secrets supply its endpoint, API key, and default model; no customer LLM credentials are needed.

👉 [Learn about the Camunda-provided LLM](https://docs.camunda.io/docs/8.10/components/agentic-orchestration/camunda-provided-llm/)

SaaS trial organizations have AI features enabled by default. For enterprise organizations, an organization admin must enable AI-powered features in Camunda Hub. The LLM budget is shared across the organization and intended for evaluation; when it is exhausted, further model calls are blocked and a process may fail with an incident such as `COST_LIMIT_EXCEEDED`. Monitor usage in Hub. See the [Camunda-provided LLM documentation](https://docs.camunda.io/docs/8.10/components/agentic-orchestration/camunda-provided-llm/) for availability and budget details.

---

## Prerequisites

- **Camunda 8.10.0+** (SaaS or Self-Managed)
- Access to Camunda Connectors (Agentic AI, HTTP, etc.)
- Outbound internet access for connectors (to reach APIs)

---

## Secrets & Configuration

The default AI Agent mapping uses the Camunda 8.10 secret references `=camunda.secrets.CAMUNDA_PROVIDED_LLM_API_ENDPOINT`, `=camunda.secrets.CAMUNDA_PROVIDED_LLM_API_KEY`, and `=camunda.secrets.CAMUNDA_PROVIDED_LLM_DEFAULT_MODEL`. These SaaS-managed secrets are available only when Camunda-provided LLM is enabled.

The agent uses the OpenAI **Responses API** with a custom backend. The endpoint secret must contain the base URL, without `/responses`; the connector appends that path. Your gateway must support Responses. OpenRouter requires stateless requests, with conversation history retained by the agent's in-process memory. A live local run verified tool calling and feedback continuity on Camunda 8.10.2 with `https://eu.openrouter.ai/api/v1` and `anthropic/claude-sonnet-4.6`. This does not verify every SaaS-managed gateway; for a backend that supports only Chat Completions, select that API in the agent configuration before deploying.

Camunda-provided LLM is not available in Self-Managed environments. Configure the AI Agent template for a supported customer-managed provider instead, such as Amazon Bedrock, Ollama, or another OpenAI-compatible endpoint, and provide its credentials to the Connectors runtime. The process uses three retries for the agent job; persistent provider, configuration, or budget failures can create an incident that must be inspected and resolved.

---

## How to Deploy & Run

1. **Import the BPMN Model**
	- Open Camunda Web Modeler.
	- Import `ai-agent-chat-with-tools.bpmn`, both form files, `ai-agent-chat-with-tools.test.json`, and `ai-agent-chat-with-tools.integration.test.json` into the same project.

2. **Configure Connectors**
	- Configure any HTTP connectors or other tools you want the agent to use.
    - Feel free to add your own tools by creating new activities in the `AI Agent` ad-hoc sub-process.

3. **Configure the AI Agent**
    - For SaaS, verify that AI-powered features and Camunda-provided LLM are available for your organization.
    - For Self-Managed, configure a supported provider and its secrets in the Connectors runtime.

4. **Deploy the Process**
	- Deploy the process to your Camunda 8 cluster.

5. **Start a New Instance**
	- Use the Web Modeler to start an instance by filling out the form to start an instance.
	- Use tasklist to fill out the form to start a new instance.

6. **Interact**
	- The agent will respond, possibly using tools.

---

## BPMN Process Overview

The process (`ai-agent-chat-with-tools.bpmn`) works as follows:

1. **Start Event**: User submits an initial chat request via a form.
2. **AI Agent Sub-process (v2)**: The Agentic AI connector receives the request and available tools, then generates a response and may request tool calls.
3. **Tools**: The selected tool activities inside the ad-hoc sub-process execute and return results to the agent. Tools include:
	- Find sample users (HTTP API)
	- Search recipes (HTTP API)
	- Get a safe joke (HTTP API)
	- List sample technology products (HTTP API)
4. **User Feedback**: The user is asked if they are satisfied with the answer.
	- If not, the process loops for follow-up.
	- If yes, the process ends.

**Key Features:**
- Dynamic tool invocation by the agent
- Extensible: add your own tools as new tasks in the sub-process

---

## Example Usage

Example inputs which can be entered in the initial form:

- `Tell me a joke`: the agent uses the safe-joke tool.
- `Find me a recipe for pasta`: the agent searches the sample recipe catalog.
- `Which sample users are available?`: the agent uses the sample-user tool.
- `Which iPhones appear in the sample products?`: the agent searches sample technology products, not live inventory.

---

## Testing with Camunda Process Test (CPT)

Tests live in `test/`. `ai-agent-chat-with-tools.test.json` is the deterministic, Test mode-compatible suite shared with the Maven CPT runner. `ai-agent-chat-with-tools.integration.test.json` contains live Test Studio agent/tool segments and a full feedback-to-approval E2E scenario.

### Prerequisites

- Java 21+
- Docker running (for process tests)

### Maven tests

Run the shared deterministic process tests and four live HTTP connector contract tests (Docker required; the four public APIs must be reachable):

```bash
cd test
mvn clean test
```

The AI Agent job is controlled in the local process tests, so Maven does not make LLM calls. The four Java-only connector tests assert response shapes that the imported Test Studio instruction format cannot express.

### Test Studio

Import both JSON files into Test Studio. The deterministic suite exercises modeled paths; the integration suite uses the Camunda-provided LLM and public HTTP APIs, requiring an eligible SaaS cluster, AI feature access, remaining organization budget, and outbound internet access. See [TESTING.md](./TESTING.md) for scenarios, assertions, and known Test Studio limitations.

---

## EU AI Act Transparency Tagging Guidance (Article 50(2))

Use a clear AI-generated label whenever users see model output.

- The form already demonstrates this in `ai-agent-chat-user-feedback.form`.
- Keep the disclosure close to `responseText` (before or after is fine if it is clearly visible).
- Keep it visible on each response turn, including follow-ups.
- Example text: `AI-generated content: This response was generated by an AI system and may contain mistakes. Please review before relying on it.`

Use the current form implementation as the recommended how-to example.

Source and support: [camunda/camunda-8-tutorials](https://github.com/camunda/camunda-8-tutorials/tree/main/solutions/ai-agent-chat-with-tools).

_Made with ❤️ by Camunda_
