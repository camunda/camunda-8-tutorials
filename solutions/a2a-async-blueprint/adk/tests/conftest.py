import os
import socket
import threading
import time

import httpx
import pytest
import uvicorn

os.environ["ADK_OFFLINE"] = "1"
os.environ.setdefault("PYTHONWARNINGS", "ignore")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def adk_server_url():
    """The ADK server agent on a free port, or an already running A2A server from ADK_SERVER_URL."""
    if os.getenv("ADK_SERVER_URL"):
        yield os.environ["ADK_SERVER_URL"].rstrip("/")
        return
    port = _free_port()
    os.environ["PORT"] = str(port)
    from server_agent.app import a2a_app

    server = uvicorn.Server(uvicorn.Config(a2a_app, port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    url = f"http://localhost:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{url}/.well-known/agent-card.json").status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    yield url
    server.should_exit = True
    thread.join(timeout=5)
