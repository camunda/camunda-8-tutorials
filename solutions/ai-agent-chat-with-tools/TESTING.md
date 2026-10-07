# AI Agent Chat With Tools test plan

The six deterministic cases in `ai-agent-chat-with-tools.test.json` are shared by Test Studio Test mode and the Maven CPT runner. Live agent/tool tests are kept in `ai-agent-chat-with-tools.integration.test.json` and require an eligible SaaS environment.

## Deterministic process coverage

The shared suite mocks agent and tool jobs to cover all reachable BPMN elements and sequence flows without LLM calls or external services.

| Case | Covered path |
|---|---|
| Happy path — user satisfied on first response (no tool calls) | Start → retry gateway → agent → feedback → satisfaction gateway → end |
| Loop path — user not satisfied, then satisfied on second try | Start → retry gateway → agent → feedback → rejection loop → agent → feedback → satisfaction gateway → end |
| LookupSampleUsers tool — agent calls LookupSampleUsers then responds | Agent → sample-user tool → feedback |
| SearchRecipes tool — agent searches for a recipe | Agent → recipe-search tool → feedback |
| FetchSafeJoke tool — agent fetches a random joke | Agent → safe-joke tool → feedback |
| ListSampleTechnologyProducts tool — agent gets list of tech stuff | Agent → sample-technology tool → feedback |

The first two cases cover all six sequence flows, both gateway outcomes, the start/end events, user task, and agent subprocess. The remaining cases cover each of the four tool activities. The latest CPT report is generated at `test/target/coverage-report/report.html`; the machine-readable report is `test/target/coverage-report/report.json`.

`JsonProcessTest` reads the root `ai-agent-chat-with-tools.test.json` directly; there is no separately maintained copy of those case definitions.

## Live Test Studio integration

Import both JSON files into Test Studio. The integration suite has 12 cases:

| Cases | Start point | Expected assertions |
|---|---|---|
| 7 agent segments | Immediately before `AI_Agent` | No-tool response, each of four individual tool paths, and two explicit two-tool sets |
| 4 connector segments | Directly before each tool activity | Tool completion and `toolCallResult` presence |
| 1 full E2E | Process start | Joke/recipe first turn, rejected feedback, users/products follow-up, user approval, completed process |

Every agent segment has an explicit expected tool set and stops after the agent or expected tool completes. Test Studio exposes element assertions as singular checks; these prove the expected tools completed but cannot reject additional tool activation. Tests do not assert tool order, exact response wording, or semantic answer quality. The Test Studio instructions only check that connector result variables exist.

## Java-only connector checks

The four Java CPT tests execute live HTTP connectors and assert stable response content and shape (known JSONPlaceholder user, DummyJSON recipe, non-empty JokeAPI text, and a sample product). These FEEL result-shape assertions are retained in Java because the imported instruction format cannot express them. Agent jobs remain controlled in Maven; Maven does not make LLM calls.

## Manual checks

These require a human using the running forms and public services:

| Journey | Pass condition |
|---|---|
| Users and products | Both sample sources return usable data and the user approves the answer. |
| Joke and recipe | Both sources return usable data and the user approves the answer. |
| Feedback retry | The user rejects the first answer, provides a follow-up, then approves the second response. |

Do not judge exact wording or tool order. Test Studio and Maven results do not replace these user-facing checks.

## Run and inspect

Prerequisites for Maven: Java 21+, Maven, and a Docker-compatible runtime. Public API access is required for its four connector tests. The live Test Studio suite additionally requires Camunda 8.10 SaaS, AI features enabled, available Camunda-provided LLM budget, and outbound internet access.

```bash
cd solutions/ai-agent-chat-with-tools/test
mvn clean test
```

Run the six deterministic cases in Test mode and the 12 live scenarios in the integration suite. Review the live run history for the no-tool segment, because the test format cannot assert the absence of tool activation. Perform the three manual journeys separately.

Reports:

- CPT coverage: `test/target/coverage-report/report.html` and `test/target/coverage-report/report.json`
- JUnit results: `test/target/surefire-reports/`
- Live Test Studio results: Test Studio run history

The latest local Maven run passed all 10 tests (6 deterministic process cases and 4 live HTTP connector checks). The deterministic suite covers all 10 executable BPMN nodes and all 6 sequence flows; the connector checks separately verify each external tool's response shape.

## Artifacts

- [Source BPMN](./ai-agent-chat-with-tools.bpmn)
- [Shared deterministic Test mode/Maven suite](./ai-agent-chat-with-tools.test.json)
- [Live Test Studio integration scenarios](./ai-agent-chat-with-tools.integration.test.json)
- [Java-only connector result-shape tests](./test/src/test/java/io/camunda/tests/LiveConnectorIntegrationTest.java)
- [Quick-start prerequisites](./README.md)
- [Camunda Process Test documentation](https://docs.camunda.io/docs/apis-tools/testing/getting-started/)
