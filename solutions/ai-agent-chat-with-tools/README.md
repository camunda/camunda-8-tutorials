# AI Agent Chat With Tools Example

This example demonstrates an AI Agent Sub-process that can answer questions, use external tools, and collect human feedback. The BPMN uses the v2 AI Agent connector template and targets Camunda 8.10 or later.

---

## 🚀 Zero-config LLM on Camunda SaaS

**Running on Camunda SaaS?** This blueprint is already pre-configured to use the **Camunda-provided LLM** — a fully managed model that works out of the box. The required secrets (`CAMUNDA_PROVIDED_LLM_API_ENDPOINT`, `CAMUNDA_PROVIDED_LLM_API_KEY`, and `CAMUNDA_PROVIDED_LLM_DEFAULT_MODEL`) are automatically available on Camunda SaaS — no AWS account, no external API keys, no extra setup.

👉 [Learn about the Camunda-provided LLM](https://docs.camunda.io/docs/components/agentic-orchestration/camunda-provided-llm/)

Just deploy the process to your SaaS cluster and run — the AI is ready to go.

---

## Prerequisites

- **Camunda 8.10+** (SaaS or Self-Managed)
- Access to Camunda Connectors (Agentic AI, HTTP, etc.)
- Outbound internet access for connectors (to reach APIs)
- (Optional) Credentials for any external APIs/tools you want to use

---

## Secrets & Configuration

This example is pre-configured to use the **Camunda-provided LLM** via the `CAMUNDA_PROVIDED_LLM_API_ENDPOINT`, `CAMUNDA_PROVIDED_LLM_API_KEY`, and `CAMUNDA_PROVIDED_LLM_DEFAULT_MODEL` secrets, which are **automatically available on Camunda SaaS** — no additional secrets needed.

If you want to use a different LLM provider (e.g. AWS Bedrock), update the Agentic AI connector configuration in the process and set up the corresponding credentials:

| Secret Name                  | Purpose                        |
|------------------------------|--------------------------------|
| `AWS_BEDROCK_ACCESS_KEY`     | AWS Bedrock access key         |
| `AWS_BEDROCK_SECRET_KEY`     | AWS Bedrock secret key         |
| ...                          | ...                            |

Configure the connectors in the Web Modeler or via environment variables as needed.

---

## How to Deploy & Run

1. **Import the BPMN Model**
	- Open Camunda Web Modeler.
	- Import `ai-agent-chat-with-tools.bpmn`, both form files, and `ai-agent-chat-with-tools.test.json` into the same project.

2. **Configure Connectors**
	- Configure any HTTP connectors or other tools you want the agent to use.
    - Feel free to add your own tools by creating new activities in the `AI Agent` ad-hoc sub-process.

3. **Set Secrets**
	- In Camunda Console, add any required secrets (see above).
    - If you use c8run, set the secrets as environment variables and restart `c8run`
    - If you use c8run with Docker, add the secrets in the `connector-secrets.txt` file and restart `c8run`

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
	- List users (HTTP API)
	- Search recipe (HTTP API)
	- Jokes API (HTTP API)
	- Get list of Tech Stuff (HTTP API)
4. **User Feedback**: The user is asked if they are satisfied with the answer.
	- If not, the process loops for follow-up.
	- If yes, the process ends.

**Key Features:**
- Dynamic tool invocation by the agent
- Extensible: add your own tools as new tasks in the sub-process

---

## Example Usage

Example inputs which can be entered in the initial form:

- `Tell me a joke`: the agent will use the Jokes API tool to fetch a joke.
- `Find me a recipe for pasta`: the agent will use the Search recipe tool.
- `Which user have the longest name`: the agent will use the List users tool to retrieve user data.
- `Which iPhones are available` will call the tech API for available gadgets and filter for iPhones.

---

## Testing with Camunda Process Test (CPT)

Tests live in `test/`. The process uses the AI Agent Sub-process v2 job type and the Test Studio suite uses the Camunda 8.10 test-case schema.

### Prerequisites

- Java 21+
- Docker running (for process tests)

### Maven tests

Run the deterministic process tests and live HTTP connector integration tests (Docker required):

```bash
cd test
mvn clean test
```

The AI Agent job is controlled in the local tests to avoid paid LLM calls; the four HTTP integration tests call their public APIs. The suite covers all reachable process elements and sequence flows.

### Test Studio

Import `ai-agent-chat-with-tools.test.json` into Test Studio for the live agent-selection, connector-isolation, and end-to-end scenarios. Eligible SaaS clusters use the Camunda-provided LLM; the suite calls public HTTP APIs and requires outbound internet access. See [TESTING.md](./TESTING.md) for scenarios, assertions, and known Test Studio limitations.

---

## EU AI Act Transparency Tagging Guidance (Article 50(2))

Use a clear AI-generated label whenever users see model output.

- The form already demonstrates this in `ai-agent-chat-user-feedback.form`.
- Keep the disclosure close to `responseText` (before or after is fine if it is clearly visible).
- Keep it visible on each response turn, including follow-ups.
- Example text: `AI-generated content: This response was generated by an AI system and may contain mistakes. Please review before relying on it.`

Use the current form implementation as the recommended how-to example.

_Made with ❤️ by Camunda_
