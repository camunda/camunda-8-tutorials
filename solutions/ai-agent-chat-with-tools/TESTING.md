# AI Agent Chat With Tools test plan

The four test layers answer progressively broader questions: does the process route correctly, does each integration work in isolation, does the complete process reach its business outcome, and does a person observe the expected external behavior?

## Process tests

- **Verifies:** Every reachable BPMN element and sequence flow, including no-tool, each tool, rejection, retry, and approval.
- **Required evidence:** 10/10 reachable elements and 6/6 sequence flows in the CPT coverage report.
- **Mocks:** All external systems.

| ID | Test | Guarantee |
|---|---|---|
| P-1 | `process/no-tool` | A direct answer can complete without a tool. |
| P-2 | `process/feedback-retry` | Rejected feedback retries and later approval completes. |
| P-3 | `process/all-tools` | All four tools are reachable through the agent subprocess. |

## Segment integration tests

- **Verifies:** The real agent prompt selects the expected tool behavior, and each connector path independently returns its documented stable shape.
- **Required evidence:** All 5 Test Studio-visible agent scenarios complete the expected agent or tool element, and all 4 connector contracts pass.
- **Mocks:** None. Agent-selection tests use the real agent and live tool workers; connector tests bypass the agent.

| ID | Test | Guarantee |
|---|---|---|
| S-1 | `segment/agent-no-tool` | A direct-answer prompt completes the agent and exposes its response. Confirm no tool execution in the Test Studio run view. |
| S-2 | `segment/agent-list-users` | A user-directory prompt completes the user-directory tool, then the instance is cancelled. |
| S-3 | `segment/agent-search-recipe` | A recipe prompt completes the recipe-search tool, then the instance is cancelled. |
| S-4 | `segment/agent-jokes-api` | A joke prompt completes the jokes tool, then the instance is cancelled. |
| S-5 | `segment/agent-technology-products` | A technology-products prompt completes the technology-products tool, then the instance is cancelled. |
| S-6 | `segment/connector-list-users` | The user-directory connector returns the documented user shape. |
| S-7 | `segment/connector-search-recipe` | The recipe-search connector returns the documented recipe shape. |
| S-8 | `segment/connector-jokes-api` | The jokes connector returns non-empty text. |
| S-9 | `segment/connector-technology-products` | The technology-products connector returns the documented product shape. |

**Limitation:** Test Studio can terminate after an element completes, not between agent selection and tool activation. The selected live tool therefore executes before cancellation. The visible assertions prove expected completion but do not reject additional tool activation or validate the generated tool inputs.

## Process integration tests

- **Verifies:** A real agent selects the expected tool set, real connectors return usable results, and the complete process reaches the expected outcome.
- **Required evidence:** 3/3 automated scenarios pass.
- **Mocks:** None.
- **Boundary:** These tests verify process behavior, not external-system impacts.

| ID | Test | Guarantee |
|---|---|---|
| PI-1 | `process-integration/users-and-products` | A users-and-products request completes the user-directory and technology-products tools, then completes. |
| PI-2 | `process-integration/joke-and-recipe` | A joke-and-recipe request completes the jokes and recipe-search tools, then completes. |
| PI-3 | `process-integration/feedback-retry` | The first turn completes jokes and recipe search; rejected feedback triggers a second turn completing user directory and technology products; later approval completes. |

Tool sets are unordered. Tests assert expected tool completion, result-variable existence, feedback topology, and terminal state, but not exact generated wording.

**Limitation:** Test Studio only displays editable summaries for singular element assertions and basic variable assertions. The importable scenarios therefore prove that expected tools complete and result variables exist, but do not automatically reject additional tool activation or validate result shape with FEEL. The managed segment tests retain shape and isolation assertions; manual tests verify the human-facing tool choice.

**Assertion strategy:** This plan prioritizes business visibility for importable live scenarios, accepting weaker Test Studio assertions such as checking that `toolCallResult` exists. Managed CPT tests retain stronger native assertions such as FEEL result-shape expressions. Do not silently weaken an assertion: choose and document whether a suite optimizes for CPT power or Test Studio visibility.

## Manual tests

- **Verifies:** A person can complete the expected journeys and observe the expected behavior in the process and external systems.
- **Required evidence:** 3/3 policy-required checks pass once.
- **Mocks:** None.

| ID | Test | Steps and pass condition |
|---|---|---|
| M-1 | Users and products | Ask for the available users and sample technology products. Confirm both external services return usable information, the response includes both categories, and approval completes the process. |
| M-2 | Joke and recipe | Ask for a safe joke and a pasta recipe. Confirm both external services return usable information, the response includes both results, and approval completes the process. |
| M-3 | Feedback retry | Ask for a joke and recipe, reject the response, then ask for users and technology products. Confirm both turns use the appropriate external services and approval completes the process after two feedback steps. |

Do not judge exact wording or tool order. Repeating these checks to measure model reliability is optional.

## Run and inspect

Prerequisites: Java 21+, Maven, a Docker-compatible runtime, an eligible Camunda 8.10 SaaS cluster, Camunda-provided LLM budget, and access to the public services.

Run the process and segment-integration suites:

```bash
cd solutions/ai-agent-chat-with-tools/test
mvn test
```

Run all 12 scenarios in `ai-agent-chat-with-tools.test.json` in Test Studio: nine segment scenarios and three process-integration scenarios. The feedback-retry scenario omits an immediate `User_Feedback IS_ACTIVE` assertion after process creation because it races asynchronous agent and connector work. Perform the policy-required manual tests separately.

Reports:

- Interactive coverage: `test/target/coverage-report/report.html`
- Machine coverage: `test/target/coverage-report/report.json`
- JUnit results: `test/target/surefire-reports/`
- Automated process-integration results: Test Studio run history
- Manual acceptance: policy checklist

## Artifacts

- [Source BPMN](./ai-agent-chat-with-tools.bpmn)
- [Deterministic CPT scenarios](./test/src/test/resources/test-cases/ai-agent-chat-with-tools.test.json)
- [Managed segment-integration tests](./test/src/test/java/io/camunda/tests/LiveConnectorIntegrationTest.java)
- [All live Test Studio scenarios](./ai-agent-chat-with-tools.test.json)
- [Solution prerequisites and test details](./README.md)
- [Camunda Process Test documentation](https://docs.camunda.io/docs/apis-tools/testing/getting-started/)
