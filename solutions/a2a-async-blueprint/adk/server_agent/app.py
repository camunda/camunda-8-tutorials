"""Serve the ADK server agent over A2A: ``uvicorn server_agent.app:a2a_app --port 8001``."""
import os

from google.adk.a2a.utils.agent_to_a2a import to_a2a

from .agent import root_agent

PORT = int(os.getenv("PORT", "8001"))
a2a_app = to_a2a(root_agent, host=os.getenv("PUBLIC_HOST", "localhost"), port=PORT,
                 protocol=os.getenv("PUBLIC_PROTOCOL", "http"))
