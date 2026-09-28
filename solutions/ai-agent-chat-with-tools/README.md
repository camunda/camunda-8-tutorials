# AI Agent Chat With Tools

This illustrative Camunda 8.10 blueprint shows an AI Agent Sub-process that can answer a request, select one or more tools, and ask for human feedback. It is designed to demonstrate agent orchestration rather than provide a production-ready chat application.

## What runs without customer credentials

On an eligible Camunda 8.10 SaaS cluster, the process uses the Camunda-provided LLM and four public, keyless HTTP APIs:

| Tool | Purpose | External service |
|---|---|---|
| List users | Return fictional users | JSONPlaceholder |
| Search recipe | Search recipes by query | DummyJSON |
| Jokes API | Return a random safe-mode joke | JokeAPI |
| Get list of Tech Stuff | Return sample technology products | restful-api.dev |

The tools require outbound internet access. They are public demonstration services, so availability and returned data are not controlled by Camunda.

## Prerequisites

- A Camunda 8.10 SaaS cluster with Connectors
- Camunda AI features enabled for the organization
- Available Camunda-provided LLM budget
- Outbound access to the four public APIs listed above

The managed `CAMUNDA_PROVIDED_LLM_API_ENDPOINT` and `CAMUNDA_PROVIDED_LLM_API_KEY` secrets are supplied by eligible SaaS clusters. Enterprise organizations may need an administrator to enable AI features. Calls can fail when the shared organization budget is exhausted.

Self-Managed users must replace the Camunda-provided LLM configuration with a supported provider and configure its credentials.

## Import and run

1. Import these resources into the same Web Modeler project:
   - `ai-agent-chat-with-tools.bpmn`
   - `ai-agent-chat-initial-request.form`
   - `ai-agent-chat-user-feedback.form`
   - `ai-agent-chat-with-tools.integration.test.json`
   - `ai-agent-chat-with-tools.test.json`
2. Deploy the BPMN process and both forms to a Camunda 8.10 development cluster.
3. Open `ai-agent-chat-with-tools.test.json` in Test Studio and run a scenario.

No customer-managed API key is required on an eligible SaaS cluster. The live scenarios start directly before the agent and terminate at the earliest useful boundary to avoid rerunning unrelated process steps.

## Process behavior

1. A user submits an initial request.
2. The AI Agent Sub-process decides whether one or more documented tools are needed.
3. Requested tools run inside the ad-hoc subprocess and return structured results.
4. The agent produces a response using the tool results.
5. A user can accept the response or provide follow-up input, which loops back to the agent with conversation context.

Example requests:

- `Tell me a safe joke.`
- `Find a pasta recipe.`
- `List all available users.`
- `Which sample technology products are available?`
- `Tell me a safe joke and find a pasta recipe.` — the agent should call both relevant tools; their order is not significant.

Agent responses and tool ordering are nondeterministic. Tests assert modeled paths and expected tool use for purpose-built prompts, not exact response wording.

## Test assets

### What is mocked

| Suite | Agent/LLM | HTTP connectors | Payload assertions | Test Studio import |
|---|---|---|---|---|
| Deterministic process tests | Mocked | Mocked | Fixed test data only | Compatible, but intended for automated CPT |
| Live connector integration tests | Mocked or bypassed | **Real public APIs** | **Non-empty live payload and representative field** | Yes |
| Live E2E test | **Real Camunda-provided LLM** | **Real public APIs** | **Non-empty joke and recipe payloads** | Yes |

The deterministic CPT suite changes the agent and HTTP connector job types only in its in-memory deployment. It never modifies the production BPMN. The integration deployment changes only the agent job type; it does not mock, stub, intercept, or replace HTTP. The Test Studio integration suite starts directly at each connector and therefore bypasses the agent without mocking it.

### Importable live connector integration suite

`ai-agent-chat-with-tools.integration.test.json` contains one isolated scenario per connector. Each scenario:

- starts directly before the connector and terminates immediately after it;
- calls the public endpoint configured in the production BPMN;
- asserts connector completion and a non-empty `toolCallResult`;
- checks a representative payload field such as a user, recipe, or product name;
- uses no LLM, mock server, Mailpit, WireMock, Testcontainers, or local worker.

### Importable live E2E suite

`ai-agent-chat-with-tools.test.json` contains three real model-driven E2E scenarios. They:

- use the Camunda-provided LLM to select joke plus recipe, and users plus technology products;
- call all four real public APIs across the two scenarios;
- assert that both expected tools complete in each scenario;
- assert the stable user, recipe, and technology-product fixture IDs and names;
- assert the random joke by type and non-empty shape rather than exact content;
- reject unexpected tool results without asserting tool order or generated response wording.

The full-process scenario starts with a users request, rejects the first response with a technology-products follow-up, waits for a second agent response, approves it, and asserts that the process ends after exactly two agent and user-feedback passes.

The managed integration suite contains the same full-process topology so it appears in the local CPT report. That local test uses live users and technology connectors with exact fixture assertions, but mocks the agent's two tool-selection decisions. The importable Test Studio scenario is the real-LLM counterpart.

Live execution depends on the SaaS prerequisites and public services above, so it is intentionally not part of CI.

### CPT process and connector coverage

`test/src/test/resources/test-cases/ai-agent-chat-with-tools.test.json` controls agent and connector jobs to cover every reachable BPMN element and sequence flow, including the feedback loop and all four tools.

The same Maven run also executes five managed-runtime integration tests:

- one live test for each of the four public HTTP connectors;
- one multi-connector integration test that completes both the joke and recipe tools in a single mocked-agent segment.

Each connector test starts directly at its tool inside the agent subprocess, terminates immediately after that tool, asserts a non-empty live payload, and asserts that no other tool or user-feedback task was activated. The multi-connector segment starts immediately before the agent and terminates immediately after it, before user feedback.

The integration tests derive their deployed model from the production BPMN and replace only the agent worker, so the real HTTP connectors run while CI avoids paid, nondeterministic LLM calls. This is not labeled E2E because the Java test selects the tools instead of the LLM. Live model-driven tool selection is covered only by the importable Test Studio E2E suite.

```bash
cd test
mvn clean test
```

The harness currently uses Camunda Process Test `8.10.0-rc2` until the 8.10 GA artifact is published. Replace the version with `8.10.0` before release.

## Benchmarking

The release benchmark is separate from CI and from the pass/fail process tests. Run repeated representative prompts on the same 8.10 SaaS cluster while comparing prompt caching and reasoning configurations. Record the prompt set, model and configuration, run count, date, expected-tool selection, complete-task rate, model calls, latency, token usage, estimated cost, raw results, and the quality/cost trade-off. Do not encode preferred prose as an expected answer.

## AI-generated content disclosure

The feedback form labels the response as AI-generated content. Keep that disclosure visible on every response turn and review the wording for the deployment's legal and product requirements.

See [Camunda-provided LLM](https://docs.camunda.io/docs/components/agentic-orchestration/camunda-provided-llm/) for current eligibility and configuration details.
