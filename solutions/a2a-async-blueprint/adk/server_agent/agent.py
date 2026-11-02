"""ADK counterpart of 03-server-agent-card-dispute.bpmn.

One skill, one tool: ``upper_case`` returns the caller's ``demoInput`` object together with an
uppercased copy of its value and the value's length, like the BPMN script task does. ``ADK_OFFLINE=1`` swaps the Gemini model for a deterministic agent that
calls the same tool, so the interop tests run without an API key.
"""
import json
import os
from typing import AsyncGenerator

from google.adk.agents import Agent, BaseAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from google.genai import types

INSTRUCTION = (
    "You run a minimal A2A skeleton. Call upper_case once with the demoInput object from the "
    "request and do not alter its value. Answer with one short sentence once the tool returned."
)


def upper_case(demo_input: dict) -> dict:
    """Return the request data with an uppercased copy of its value and the value's length.
    Replace this tool with your own business logic.

    Args:
        demo_input: The demoInput object from the request, passed through unchanged.
    """
    value = str(demo_input.get("value", ""))
    return {"received": demo_input, "uppercase": value.upper(), "length": len(value)}


def _request_text(ctx: InvocationContext) -> str:
    parts = ctx.user_content.parts if ctx.user_content else []
    return "".join(p.text or "" for p in parts)


def extract_demo_input(text: str) -> dict | None:
    """Find the demoInput object in a text part or in a JSON data part rendered as text."""
    for start in (i for i, c in enumerate(text) if c == "{"):
        try:
            obj, _ = json.JSONDecoder().raw_decode(text[start:])
        except ValueError:
            continue
        if isinstance(obj, dict):
            return obj.get("demoInput", obj if "value" in obj else None)
    return None


class OfflinePlaceholderAgent(BaseAgent):
    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        print("REQ", repr(_request_text(ctx)), flush=True)
        demo_input = extract_demo_input(_request_text(ctx))
        text = "Placeholder tool completed." if demo_input else "No demoInput supplied."
        result = upper_case(demo_input) if demo_input else None
        yield Event(
            author=self.name,
            invocation_id=ctx.invocation_id,
            content=types.Content(role="model", parts=[types.Part(text=json.dumps({"placeholder": result}) if result else text)]),
        )


def build_agent():
    if os.getenv("ADK_OFFLINE") == "1":
        return OfflinePlaceholderAgent(name="placeholder_agent", description="Shares a placeholder value.")
    return Agent(
        model=os.getenv("ADK_MODEL", "gemini-flash-latest"),
        name="placeholder_agent",
        description="Shares a placeholder value (counterpart of the Camunda server agent).",
        instruction=INSTRUCTION,
        tools=[upper_case],
    )


root_agent = build_agent()
