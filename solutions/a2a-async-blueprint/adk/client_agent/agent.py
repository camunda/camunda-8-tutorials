"""ADK counterpart of 01-client-agent.bpmn.

``REMOTE_AGENT_CARD_URL`` points at any A2A server: the Camunda ``02-a2a-server.bpmn`` Agent Card
or the ADK server in ``server_agent``. ``ADK_OFFLINE=1`` replaces the Gemini root agent with one
that always delegates, so interop tests need no API key.
"""
import os
from typing import AsyncGenerator

from google.adk.agents import Agent, BaseAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
from google.adk.events import Event

CARD_URL = os.getenv("REMOTE_AGENT_CARD_URL", "http://localhost:8001/.well-known/agent-card.json")

remote_agent = RemoteA2aAgent(
    name="remote_placeholder_agent",
    description="Remote agent that shares a placeholder value over A2A.",
    agent_card=CARD_URL,
)


class OfflineDelegatingAgent(BaseAgent):
    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        async for event in remote_agent.run_async(ctx):
            yield event


def build_agent():
    if os.getenv("ADK_OFFLINE") == "1":
        return OfflineDelegatingAgent(name="client_agent", description="Delegates every request.",
                                      sub_agents=[remote_agent])
    return Agent(
        model=os.getenv("ADK_MODEL", "gemini-flash-latest"),
        name="client_agent",
        description="Delegates the placeholder request to the remote A2A agent.",
        instruction="Delegate the user's request to the remote placeholder agent and report its answer.",
        sub_agents=[remote_agent],
    )


root_agent = build_agent()
