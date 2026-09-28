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

### Live Test Studio scenarios

`ai-agent-chat-with-tools.test.json` is the importable live suite. It:

- contains one E2E agent run that must reach both the joke and recipe tools;
- covers the list-users and technology-products tools with short segments;
- exercises all four HTTP connectors against their real, keyless endpoints;
- uses no Mailpit, WireMock, Testcontainers, local worker, or customer credential.

Live execution depends on the SaaS prerequisites and public services above, so it is intentionally not part of CI.

### CPT process and connector coverage

`test/src/test/resources/test-cases/ai-agent-chat-with-tools.test.json` controls agent and connector jobs to cover every reachable BPMN element and sequence flow, including the feedback loop and all four tools.

The same Maven run also executes five managed-runtime integration tests:

- one live test for each of the four public HTTP connectors;
- one E2E process test that completes both the joke and recipe tools in a single agent turn.

Each connector test starts directly at its tool inside the agent subprocess, terminates immediately after that tool, and asserts that no other tool or user-feedback task was activated. The E2E agent segment starts immediately before the agent and terminates immediately after it, before user feedback.

The integration tests derive their deployed model from the production BPMN and replace only the agent worker, so the real HTTP connectors run while CI avoids paid, nondeterministic LLM calls. Live model-driven tool selection remains covered by the importable Test Studio suite.

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
