"""Interop checks for the ADK agents against the dialect used by the Camunda blueprint (A2A 1.0).

Set CAMUNDA_A2A_URL (Camunda server RPC endpoint) and CAMUNDA_CARD_URL to also run the ADK client
against the Camunda server agent.
"""
import asyncio
import json
import os
import uuid

import httpx
import pytest

PLACEHOLDER = {"value": "Example input"}
TRANSFORMED = {"received": PLACEHOLDER, "uppercase": "EXAMPLE INPUT", "length": 13}
HEADERS = {"A2A-Version": "1.0", "Content-Type": "application/json"}


def rpc(url: str, method: str, params: dict) -> dict:
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    response = httpx.post(url, json=body, headers=HEADERS, timeout=30)
    response.raise_for_status()
    return response.json()


def message(text: str) -> dict:
    return {"messageId": str(uuid.uuid4()), "role": "ROLE_USER", "parts": [{"text": text}]}


def test_agent_card_uses_a2a_1_0_and_jsonrpc(adk_server_url):
    card = httpx.get(f"{adk_server_url}/.well-known/agent-card.json").json()
    interface = card["supportedInterfaces"][0]
    assert interface["protocolBinding"] == "JSONRPC"
    assert interface["protocolVersion"] == "1.0"
    assert card["skills"]


def test_send_message_returns_completed_task_with_placeholder(adk_server_url):
    text = "Share the placeholder: " + json.dumps({"demoInput": PLACEHOLDER})
    task = rpc(adk_server_url, "SendMessage", {"message": message(text)})["result"]["task"]
    assert task["status"]["state"] == "TASK_STATE_COMPLETED"
    artifact_text = "".join(p.get("text", "") for a in task["artifacts"] for p in a["parts"])
    assert json.loads(artifact_text) == {"placeholder": TRANSFORMED}


def test_get_task_returns_the_settled_task(adk_server_url):
    sent = rpc(adk_server_url, "SendMessage", {"message": message(json.dumps({"demoInput": PLACEHOLDER}))})
    task_id = sent["result"]["task"]["id"]
    fetched = rpc(adk_server_url, "GetTask", {"id": task_id})["result"]
    assert fetched["id"] == task_id
    assert fetched["status"]["state"] == "TASK_STATE_COMPLETED"


def test_unknown_task_is_a_jsonrpc_error(adk_server_url):
    assert "error" in rpc(adk_server_url, "GetTask", {"id": "does-not-exist"})


def test_push_config_is_accepted_inline(adk_server_url):
    params = {
        "message": message(json.dumps({"demoInput": PLACEHOLDER})),
        "configuration": {"taskPushNotificationConfig": {"url": "http://localhost:9/unused", "token": "t"}},
    }
    response = rpc(adk_server_url, "SendMessage", params)
    assert "result" in response, response


def _run_client(card_url: str) -> str:
    os.environ["REMOTE_AGENT_CARD_URL"] = card_url
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    import importlib
    import client_agent.agent as client_module

    client = importlib.reload(client_module)
    runner = InMemoryRunner(agent=client.root_agent, app_name="client")

    async def go() -> str:
        session = await runner.session_service.create_session(app_name="client", user_id="u")
        content = types.Content(role="user", parts=[types.Part(text=json.dumps({"demoInput": PLACEHOLDER}))])
        texts = []
        async for event in runner.run_async(user_id="u", session_id=session.id, new_message=content):
            texts += [p.text for p in (event.content.parts if event.content else []) if p.text]
        return " ".join(texts)

    return asyncio.run(go())


def test_adk_client_delegates_to_adk_server(adk_server_url):
    answer = _run_client(f"{adk_server_url}/.well-known/agent-card.json")
    assert "Example input" in answer


@pytest.mark.skipif(not os.getenv("CAMUNDA_CARD_URL"), reason="needs a deployed Camunda A2A server")
def test_adk_client_delegates_to_camunda_server():
    answer = _run_client(os.environ["CAMUNDA_CARD_URL"])
    assert "Example input" in answer
