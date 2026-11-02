# A2A blueprint (import draft)

> **Status: imported draft for visual fine-tuning, not yet published.** It tracks
> [camunda/agentic-orchestration-pod#147](https://github.com/camunda/agentic-orchestration-pod/issues/147).

Agent2Agent (A2A) example with a neutral business placeholder. The business-agent diagrams stay
minimal; the protocol work lives in separate protocol processes.

| Side | Business agent (minimal) | Protocol |
| --- | --- | --- |
| Client | `01` `a2a-client`: start, client AI agent with the native **A2A Client connector** as its tool (`Remote A2A agent`) plus the native polling catch event, end | The connector (Camunda 8.9+) |
| Server | `03` `a2a-card-dispute`: start, server AI agent with `echo_placeholder`, end | `04` `a2a-task`: calls 03, cancel, Task revision, optional push, settled signal |
| Server entry | | `02` `a2a-rpc`: the single executable RPC server |

There is no native A2A server connector, so the server side (02, 04) is custom BPMN.

## How push works

Push is optional for the remote client; the client side works either way.

- **Client (01)** uses the native A2A Client connector in `aiAgentTool` mode. The AI agent chooses
  the operation (`fetchAgentCard` or `sendMessage`) and its parameters. The retrieval mode of
  `sendMessage` is a property of the connector: `blocking` (wait inside the call), `polling`
  (the connector returns the Task with polling data and the *A2A Client Polling* catch event
  `Remote task settled` polls until a final state) or `notification` (push). Polling is configured
  in 01. For `notification`, set the mode to `notification`, set the connector's webhook URL
  (copied from the Modeler's Webhooks tab) and token, and replace the polling catch event with the
  *A2A Client Webhook* catch event; the retrieval mode alone does not switch the catch event.
  Push works only if the remote Agent Card advertises push support.
- **Server task (04)** starts per task from 02, calls the business agent (03) through a call
  activity, maps agent failure (`AGENT_FAILED`) and `a2a-cancel` to the Task outcome, and builds the
  next Task revision. When a push config was supplied it POSTs the Task to the client; then it
  throws the signal `a2a-settled:<taskId>:<rev>`. 02 and 04 accept the push config as
  `taskPushNotificationConfig` (A2A 1.0) or as `pushNotificationConfig` with `authentication`
  `schemes` and `credentials` (the shape the connector's SDK sends).
- **Server (02)** subscribes to that signal in parallel with starting 04, because signals are not
  buffered. `SendMessage`, `GetTask` and `CancelTask` answer from the settled Task of the `a2a-task`
  instance.
- Standalone Create/Get/List/Delete push-config methods return `UNSUPPORTED_OPERATION`; supply the
  config inline in `SendMessage`.

Per task there is one `a2a-task` instance and one `a2a-card-dispute` instance. Per delegation on
the client side there is one `a2a-client` instance.

## Working with external agents

- The native client connector handles the A2A protocol version, message construction and result
  retrieval itself. It speaks A2A 0.3.x according to its documentation, while the custom server
  (02) accepts A2A 1.0 requests only. The connector therefore targets external agents such as
  the ADK agent in `adk/`; talking to 02 needs a 0.3 translation that is not part of this
  blueprint. This wire compatibility was not verified.
- 01's prompt makes the agent send the request as message text (JSON of `demoInput`), because ADK
  passes only text parts to the model.
- 03 reads the request from the data part, or from JSON in a text part. `from json` and `to json`
  need Camunda 8.9, so the repository `.bpmnlintrc` targets 8.9.

## Contents

| Resource | Purpose |
| --- | --- |
| `01-client-agent.bpmn` | Client agent using the native A2A Client connector |
| `02-a2a-server.bpmn` | The single executable A2A server (`a2a-rpc`), Basic-auth platform calls |
| `03-server-agent-card-dispute.bpmn` | Server agent with a placeholder script tool (`echo_placeholder`) |
| `04-a2a-task.bpmn` | Per-task server protocol (`a2a-task`) |
| `adk/` | External A2A agent (Google ADK) used to check interoperability |
| `server-request-validation.dmn` | Protocol request validation |
| `.camunda/element-templates/` | Custom A2A element templates (server RPC, Agent Card, client); Desktop Modeler resolves them from here. The HTTP JSON v13 and AI Agent v5 templates are provided out of the box and are not bundled |
| `*.test.json` | Test Studio / CPT scenarios, one per process |

No forms. Deploy only one server profile; the OAuth variant lives in the source repository.

## Import into Camunda SaaS

[Import all resources into Web Modeler](https://modeler.cloud.camunda.io/import/resources?source=https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/01-client-agent.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/02-a2a-server.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/03-server-agent-card-dispute.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/04-a2a-task.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/server-request-validation.dmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/.camunda/element-templates/server-a2a-rpc-endpoint.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/.camunda/element-templates/server-agent-card-endpoint.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/01-client-agent.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/02-a2a-server.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/03-server-agent-card-dispute.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/04-a2a-task.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/README.md&title=A2A%20Async%20Blueprint)

The link loads the files from `main` and only works once this solution is merged there. It includes the BPMNs, DMN, the three custom element templates from `.camunda/element-templates/`, the tests and this README.

## Setup

Tested by the source: Camunda 8.9.26, Connectors 8.9.17, CPT 8.9.26, Java 21 (bounded
checks only; not full model/SaaS execution).

Configure connector secrets (no credentials are bundled; templates use `{{secrets.NAME}}`):

| Secret | Purpose |
| --- | --- |
| `ENGINE_URL` | REST base URL without `/v2` |
| `ENGINE_USERNAME`, `ENGINE_PASSWORD` | Basic auth for platform calls |
| `CAMUNDA_PROVIDED_LLM_API_ENDPOINT`, `CAMUNDA_PROVIDED_LLM_API_KEY`, `CAMUNDA_PROVIDED_LLM_DEFAULT_MODEL` | Agent execution only |

Set the `A2A_REMOTE_SERVER_URL` secret for 01 and replace `CardRequested`'s RPC URL (a deliberately
nonfunctional example HTTPS URL) with your reachable connector endpoint.

## Customization

Edit `demoInput` in `QuestionAsked`, then replace `echo_placeholder`. 04 publishes its evidence as
the `placeholder` artifact; adjust it there if you change the tool result.

## Source and licensing

Imported from [HanselIdes/camunda-a2a](https://github.com/HanselIdes/camunda-a2a)
(`experiment-3/blueprint`), branch `a2a-layout-card-consolidation`, local state of 2026-11-02.
This solution follows the repository's license; no separate license is bundled. The source is Camunda License 1.0 (non-production only), so confirm it permits public distribution. The out-of-the-box HTTP JSON (v13) and AI Agent (v5) templates are not redistributed here.

## Known gaps

- Duplicate or out-of-order push callbacks and push delivery retries beyond the HTTP connector's three tries are not modeled. Push is not yet run end to end against a live engine; the Maven tests cover 01, 03 and 04 with mocked jobs and child processes; the native connector itself cannot run in Camunda Process Test, so its jobs are completed with mocked results. Multi-turn follow-up (resuming an input-required Task) is not part of 01.
- Source Test Studio scenarios are canned examples; Java CPT tests (<20 s target) are not imported.
- No `camunda-example.json` yet.
