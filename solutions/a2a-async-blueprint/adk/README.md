# Google ADK counterparts (interop testing)

The Camunda blueprint is only useful if its A2A client and server also work with agents that are not
built on Camunda. Camunda 8.9's native A2A Client connector uses the A2A Java SDK 0.3.3, so it speaks
A2A 0.3 only. The ADK server therefore answers both versions on one endpoint. This folder holds equivalents of the two Camunda agents, written with
the [Google Agent Development Kit](https://adk.dev) (`google-adk`, `a2a-sdk` 1.x, A2A 1.0 and 0.3 JSON-RPC):

| Camunda | ADK counterpart | Behaviour |
| --- | --- | --- |
| `03-server-agent.bpmn` | `server_agent/` | One skill, one tool `upper_case`; served with `to_a2a()` |
| `01-client-agent.bpmn` | `client_agent/` | Root agent that delegates to a `RemoteA2aAgent` |

Any pairing works: Camunda client to ADK server, ADK client to Camunda server, and ADK to ADK.

## Run

```bash
uv venv --python 3.13 .venv && uv pip install --python .venv/bin/python -e ".[test]"
export GOOGLE_API_KEY=...   # Gemini; not needed with ADK_OFFLINE=1
.venv/bin/uvicorn server_agent.app:a2a_app --port 8001       # card: http://localhost:8001/.well-known/agent-card.json
REMOTE_AGENT_CARD_URL=http://localhost:8001/.well-known/agent-card.json \
  .venv/bin/adk web .                                         # client_agent against any A2A server
```

To test the Camunda client against the ADK server, point the client's card URL at the ADK card. To test
the ADK client against Camunda, set `REMOTE_AGENT_CARD_URL` to the Camunda Agent Card URL.

## Test

```bash
.venv/bin/python -m pytest          # ADK_OFFLINE=1 is set by the tests: no model, no API key
CAMUNDA_CARD_URL=https://<connector-host>/.../agent-card.json .venv/bin/python -m pytest   # adds ADK client -> Camunda server
```

The offline tests check the Agent Card (1.0 `supportedInterfaces` plus the 0.3 `url` and
`protocolVersion`), A2A 1.0 `SendMessage` and `GetTask`, A2A 0.3 `message/send` and `tasks/get`, an
inline push config, and an ADK client delegating to the ADK server.

## Interoperability notes

What the interop tests showed about agents not built on Camunda:

- a2a-sdk 1.x serves both dialects on the JSON-RPC route when its v0.3 compatibility is on (the
  default in `google.adk.a2a._compat.attach_a2a_routes_to_app`). A request is handled as 0.3 when
  its method is `message/send`, `tasks/get` and so on, and as 1.0 when it is `SendMessage` and so on.
- The card from a2a-sdk 1.x has only `supportedInterfaces`. The 0.3 Java SDK needs a top-level `url`
  and `protocolVersion`, so `server_agent/app.py` adds them to the served card.
- ADK passes only text parts to the model. A request that carries `demoInput` only as a `data` part
  reaches the agent empty, so the Camunda client must also send the request as text.
- ADK returns the answer as an unnamed artifact with a text part. The blueprint's result guard
  (artifact `placeholder` with a data part) accepts only Camunda-built servers, so it must accept any
  completed task and read the text.
- ADK settles within `SendMessage` (completed Task), so the client must treat a terminal Task in the
  first response as final and not wait for a push or poll.
