# A2A blueprint (import draft)

> **Status: imported draft for visual fine-tuning, not yet published.** It tracks
> [camunda/agentic-orchestration-pod#147](https://github.com/camunda/agentic-orchestration-pod/issues/147).
> Task updates are pushed, not polled: `SendMessage` returns the accepted Task at once and the
> server later POSTs the final Task to the client's webhook.

## How push works

- **Client (01)** sends `taskPushNotificationConfig` (URL, token, Bearer credentials) with
  `SendMessage`, then waits on an inbound webhook event (`AwaitPush`, 5 min timeout). The webhook
  validates the `Authorization` header against the `A2A_CALLBACK_SECRET` connector secret.
- **Server agent (03)** POSTs the Task to the client when a push config was supplied, then throws
  the signal `a2a-settled:<taskId>:<rev>`. Signals are engine-native; message throw events need a
  job worker.
- **Server (02)** subscribes to that signal in parallel with handing work to 03, because signals
  are not buffered. `SendMessage`, `GetTask` and `CancelTask` answer from the settled Task.
- Standalone Create/Get/List/Delete push-config methods return `UNSUPPORTED_OPERATION`; supply the
  config inline in `SendMessage`.

Agent2Agent (A2A) example with a neutral business placeholder: one executable A2A server
process, a separate client agent and a separate server-side business agent.

## Contents

| Resource | Purpose |
| --- | --- |
| `01-client-agent.bpmn` | Client agent: discovery and one delegation tool |
| `02-a2a-server.bpmn` | The single executable A2A server (`a2a-rpc`), Basic-auth platform calls |
| `03-server-agent-card-dispute.bpmn` | Server agent with a placeholder script tool (`echo_placeholder`) |
| `server-request-validation.dmn` | Protocol request validation |
| `.camunda/element-templates/` | Custom A2A element templates (server RPC, Agent Card, client); Desktop Modeler resolves them from here. The HTTP JSON v13 and AI Agent v5 templates are provided out of the box and are not bundled |
| `*.test.json` | Test Studio / CPT scenarios, one per process |

No forms. Deploy only one server profile; the OAuth variant lives in the source repository.

## Import into Camunda SaaS

[Import all resources into Web Modeler](https://modeler.cloud.camunda.io/import/resources?source=https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/01-client-agent.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/02-a2a-server.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/03-server-agent-card-dispute.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/server-request-validation.dmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/.camunda/element-templates/server-a2a-rpc-endpoint.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/.camunda/element-templates/server-agent-card-endpoint.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/.camunda/element-templates/client-a2a.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/01-client-agent.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/02-a2a-server.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/03-server-agent-card-dispute.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/README.md&title=A2A%20Async%20Blueprint)

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

Replace the client's discovery/Send/Get URLs and `CardRequested`'s RPC URL (a deliberately
nonfunctional example HTTPS URL) with your reachable connector endpoint.

## Customization

Edit `demoInput` in `QuestionAsked`, then replace `echo_placeholder` and update the
client/server result guards (artifact `placeholder`, data `{value: ...}`) together.

## Source and licensing

Imported from [HanselIdes/camunda-a2a](https://github.com/HanselIdes/camunda-a2a)
(`experiment-3/blueprint`), branch `a2a-layout-card-consolidation`, local state of 2026-11-02.
This solution follows the repository's license; no separate license is bundled. The source is Camunda License 1.0 (non-production only), so confirm it permits public distribution. The out-of-the-box HTTP JSON (v13) and AI Agent (v5) templates are not redistributed here.

## Known gaps

- Duplicate or out-of-order push callbacks and push delivery retries beyond the HTTP connector's three tries are not modeled. Push is not yet run end to end against a live engine (only 03 is covered by the Maven tests).
- Source Test Studio scenarios are canned examples; Java CPT tests (<20 s target) are not imported.
- No `camunda-example.json`, `test/pom.xml` yet.
