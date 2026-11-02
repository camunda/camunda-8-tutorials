"""The same ADK server also answers the A2A 0.3 dialect spoken by the native Camunda A2A Client connector."""
import json
import uuid

import httpx

PLACEHOLDER = {"value": "Example input"}
TRANSFORMED = {"received": PLACEHOLDER, "uppercase": "EXAMPLE INPUT", "length": 13}


def rpc03(url: str, method: str, params: dict) -> dict:
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    response = httpx.post(url, json=body, headers={"Content-Type": "application/json"}, timeout=30)
    response.raise_for_status()
    return response.json()


def message03(text: str) -> dict:
    return {"kind": "message", "messageId": str(uuid.uuid4()), "role": "user", "parts": [{"kind": "text", "text": text}]}


def test_message_send_returns_completed_task_with_placeholder(adk_server_url):
    text = "Share the placeholder: " + json.dumps({"demoInput": PLACEHOLDER})
    result = rpc03(adk_server_url, "message/send", {"message": message03(text)})["result"]
    assert result["kind"] == "task"
    assert result["status"]["state"] == "completed"
    artifact_text = "".join(p.get("text", "") for a in result["artifacts"] for p in a["parts"])
    assert json.loads(artifact_text) == {"placeholder": TRANSFORMED}


def test_tasks_get_returns_the_settled_task(adk_server_url):
    sent = rpc03(adk_server_url, "message/send", {"message": message03(json.dumps({"demoInput": PLACEHOLDER}))})
    task_id = sent["result"]["id"]
    fetched = rpc03(adk_server_url, "tasks/get", {"id": task_id})["result"]
    assert fetched["id"] == task_id
    assert fetched["status"]["state"] == "completed"


def test_unknown_task_is_a_jsonrpc_error(adk_server_url):
    assert "error" in rpc03(adk_server_url, "tasks/get", {"id": "does-not-exist"})


def test_agent_card_has_0_3_fields_next_to_1_0_interfaces(adk_server_url):
    card = httpx.get(f"{adk_server_url}/.well-known/agent-card.json").json()
    assert card["url"].startswith("http")
    assert card["protocolVersion"] == "0.3.0"
    assert card["preferredTransport"] == "JSONRPC"
    assert card["supportedInterfaces"][0]["protocolVersion"] == "1.0"
