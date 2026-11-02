"""Serve the ADK server agent over A2A: ``uvicorn server_agent.app:a2a_app --port 8001``.

One endpoint answers A2A 1.0 and A2A 0.3 (the a2a-sdk v0.3 compatibility routes are on). The Agent
Card served by a2a-sdk 1.x only has ``supportedInterfaces``; the 0.3 Java SDK behind Camunda's native
A2A Client connector needs the top-level ``url`` and ``protocolVersion``, so ``_with_v03_fields``
adds them next to the 1.0 fields.
"""
import json
import os

from google.adk.a2a.utils.agent_to_a2a import to_a2a
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .agent import root_agent

PORT = int(os.getenv("PORT", "8001"))
CARD_PATH = "/.well-known/agent-card.json"


def _with_v03_fields(card: dict) -> dict:
    interfaces = card.get("supportedInterfaces") or []
    if not interfaces or "url" in card:
        return card
    first = interfaces[0]
    return {
        **card,
        "url": first["url"],
        "protocolVersion": "0.3.0",
        "preferredTransport": first.get("protocolBinding", "JSONRPC"),
    }


class DualVersionCard(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.url.path != CARD_PATH or response.status_code != 200:
            return response
        body = b"".join([chunk async for chunk in response.body_iterator])
        headers = {k: v for k, v in response.headers.items() if k.lower() not in ("content-length", "etag")}
        return Response(json.dumps(_with_v03_fields(json.loads(body))), status_code=200,
                        headers=headers, media_type="application/json")


a2a_app = to_a2a(root_agent, host=os.getenv("PUBLIC_HOST", "localhost"), port=PORT,
                 protocol=os.getenv("PUBLIC_PROTOCOL", "http"))
a2a_app.add_middleware(DualVersionCard)
