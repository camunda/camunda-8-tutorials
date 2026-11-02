# A2A blueprint (import draft)

> **Status: imported draft for visual fine-tuning, not yet published.** It tracks
> [camunda/agentic-orchestration-pod#147](https://github.com/camunda/agentic-orchestration-pod/issues/147).

Agent2Agent (A2A) example with a neutral business placeholder. The business-agent diagrams stay
minimal; the protocol work lives in separate protocol processes.

| Side | Business agent (minimal) | Protocol process |
| --- | --- | --- |
| Client | `01` `a2a-client`: start, client AI agent with one tool `DelegateRequest`, end | `05` `a2a-client-protocol`: discovery, `SendMessage`, push or polling, result extraction |
| Server | `03` `a2a-card-dispute`: start, server AI agent with `echo_placeholder`, end | `04` `a2a-task`: calls 03, cancel, Task revision, optional push, settled signal |
| Server entry | | `02` `a2a-rpc`: the single executable RPC server |

## How push works

Push is optional for the remote client; the client side works either way.

- **Client (05)** always offers a push config (callback URL, token and credentials from the
  `A2A_CALLBACK_SECRET` secret) with `SendMessage`. If the first response already carries a
  terminal Task, that Task is final and nothing is awaited. Otherwise `PushRace` waits for the
  `a2a-push` webhook (the webhook validates the `Authorization` header) or a 30 s timer. On the
  timer the client polls `GetTask` and repeats, at most 20 polls, until the Task is terminal or
  needs input. A server that ignores the push config is therefore served by polling.
- **Server task (04)** starts per task from 02, calls the business agent (03) through a call
  activity, maps agent failure (`AGENT_FAILED`) and `a2a-cancel` to the Task outcome, and builds the
  next Task revision. When a push config was supplied it POSTs the Task to the client; then it
  throws the signal `a2a-settled:<taskId>:<rev>`. Signals are engine-native; message throw events
  need a job worker.
- **Server (02)** subscribes to that signal in parallel with starting 04, because signals are not
  buffered. `SendMessage`, `GetTask` and `CancelTask` answer from the settled Task of the `a2a-task`
  instance.
- Standalone Create/Get/List/Delete push-config methods return `UNSUPPORTED_OPERATION`; supply the
  config inline in `SendMessage`.

Per task there is one `a2a-task` instance and one `a2a-card-dispute` instance. Per delegation on
the client side there is one `a2a-client` and one `a2a-client-protocol` instance.

## Working with external agents

Findings from `adk/` (a Google ADK agent) shaped the Camunda side:

- 05 sends the `A2A-Version: 1.0` header and the request as a text part (JSON text of `demoInput`)
  in addition to the data part, because ADK passes only text parts to the model.
- A terminal Task in the first `SendMessage` response is final: no push wait, no polling.
- 05 extracts the result from any completed Task: the first artifact data part if present, else all
  text parts joined. The artifact name is not checked. 01 returns it as `result` next to `response`
  and `task`.
- 03 reads the request from the data part, or from JSON in a text part. `from json` and `to json`
  need Camunda 8.9; the repository's `.bpmnlintrc` targets 8.8, so lint these files with the 8.9
  `camunda-compat` ruleset.

## Contents

| Resource | Purpose |
| --- | --- |
| `01-client-agent.bpmn` | Client agent with one delegation tool (call activity to 05) |
| `02-a2a-server.bpmn` | The single executable A2A server (`a2a-rpc`), Basic-auth platform calls |
| `03-server-agent-card-dispute.bpmn` | Server agent with a placeholder script tool (`echo_placeholder`) |
| `04-a2a-task.bpmn` | Per-task server protocol (`a2a-task`) |
| `05-a2a-client-protocol.bpmn` | Client protocol (`a2a-client-protocol`) |
| `adk/` | External A2A agent (Google ADK) used to check interoperability |
| `server-request-validation.dmn` | Protocol request validation |
| `.camunda/element-templates/` | Custom A2A element templates (server RPC, Agent Card, client); Desktop Modeler resolves them from here. The HTTP JSON v13 and AI Agent v5 templates are provided out of the box and are not bundled |
| `*.test.json` | Test Studio / CPT scenarios, one per process |

No forms. Deploy only one server profile; the OAuth variant lives in the source repository.

## Import into Camunda SaaS

[Import all resources into Web Modeler](https://modeler.cloud.camunda.io/import/resources?source=https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/01-client-agent.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/02-a2a-server.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/03-server-agent-card-dispute.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/04-a2a-task.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/05-a2a-client-protocol.bpmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/server-request-validation.dmn,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/.camunda/element-templates/server-a2a-rpc-endpoint.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/.camunda/element-templates/server-agent-card-endpoint.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/.camunda/element-templates/client-a2a.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/01-client-agent.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/02-a2a-server.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/03-server-agent-card-dispute.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/04-a2a-task.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/05-a2a-client-protocol.test.json,https://raw.githubusercontent.com/camunda/camunda-8-tutorials/refs/heads/main/solutions/a2a-async-blueprint/README.md&title=A2A%20Async%20Blueprint)

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

Replace the discovery/Send/Get URLs in 05 and `CardRequested`'s RPC URL (a deliberately
nonfunctional example HTTPS URL) with your reachable connector endpoint.

## Customization

Edit `demoInput` in `QuestionAsked`, then replace `echo_placeholder`. 04 publishes its evidence as
the `placeholder` artifact; adjust it there if you change the tool result.

## Source and licensing

Imported from [HanselIdes/camunda-a2a](https://github.com/HanselIdes/camunda-a2a)
(`experiment-3/blueprint`), branch `a2a-layout-card-consolidation`, local state of 2026-11-02.
This solution follows the repository's license; no separate license is bundled. The source is Camunda License 1.0 (non-production only), so confirm it permits public distribution. The out-of-the-box HTTP JSON (v13) and AI Agent (v5) templates are not redistributed here.

## Known gaps

- Duplicate or out-of-order push callbacks and push delivery retries beyond the HTTP connector's three tries are not modeled. Push is not yet run end to end against a live engine; the Maven tests cover 01, 03, 04 and 05 with mocked jobs and child processes. Multi-turn follow-up (resuming an input-required Task) is not part of 01.
- Source Test Studio scenarios are canned examples; Java CPT tests (<20 s target) are not imported.
- No `camunda-example.json` yet.
