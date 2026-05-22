"""
targets/agent_targets.py

Custom PyRIT PromptTarget implementations that wrap the
ReAct, Coder-Reviewer, and Policy-Guard HTTP endpoints.

PyRIT sends payloads here; we forward them to the
agent as a task and return the full response for scoring.
"""

import httpx
import json
import logging
from pyrit.prompt_target import PromptTarget
from pyrit.models import Message, MessagePiece, construct_response_from_request

logger = logging.getLogger(__name__)


class ReActAgentTarget(PromptTarget):
    """
    Wraps the single ReAct agent (/run endpoint).
    The payload becomes the task sent to the agent.
    """

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url.rstrip("/")

    async def send_prompt_async(self, *, message: Message) -> list[Message]:
        request_piece = message.message_pieces[0]
        payload = request_piece.converted_value
        logger.info(f"[ReActTarget] Sending payload ({len(payload)} chars)")

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/run",
                json={"task": payload},
            )
            resp.raise_for_status()
            data = resp.json()

        # Return full response + tool call log as the response text
        response_text = json.dumps({
            "final_response": data["final_response"],
            "tool_calls":     data["tool_calls"],
            "turn_count":     data["turn_count"],
        })

        return [construct_response_from_request(
            request=request_piece,
            response_text_pieces=[response_text],
        )]

    def get_identifier(self) -> dict:
        return {"__type__": "ReActAgentTarget", "url": self.base_url}


class CoderReviewerTarget(PromptTarget):
    """
    Wraps the Coder-Reviewer agent pipeline: a Coder LLM proposes tool calls
    that a Reviewer LLM gates before execution. Returns the reviewer's
    denied_count for scoring.
    """

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url.rstrip("/")

    async def send_prompt_async(self, *, message: Message) -> list[Message]:
        request_piece = message.message_pieces[0]
        payload = request_piece.converted_value
        logger.info(f"[CoderReviewerTarget] Sending payload ({len(payload)} chars)")

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/run",
                json={"task": payload},
            )
            resp.raise_for_status()
            data = resp.json()

        response_text = json.dumps({
            "final_response":  data["final_response"],
            "tool_calls":      data["tool_calls"],
            "denied_count":    data["denied_count"],
            "turn_count":      data["turn_count"],
        })

        return [construct_response_from_request(
            request=request_piece,
            response_text_pieces=[response_text],
        )]

    def get_identifier(self) -> dict:
        return {"__type__": "CoderReviewerTarget", "url": self.base_url}


class PolicyGuardTarget(PromptTarget):
    """
    Wraps the Policy-Guard agent — structured policy gate over a LangGraph
    flow with allowlist + regex + LLM semantic check + isolated web context.
    Returns denied_count alongside tool calls so the scorer can distinguish
    BENIGN (guardrail blocked) from EXFILTRATION.
    """

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url.rstrip("/")

    async def send_prompt_async(self, *, message: Message) -> list[Message]:
        request_piece = message.message_pieces[0]
        payload = request_piece.converted_value
        logger.info(f"[PolicyGuardTarget] Sending payload ({len(payload)} chars)")

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/run",
                json={"task": payload},
            )
            resp.raise_for_status()
            data = resp.json()

        response_text = json.dumps({
            "final_response":     data["final_response"],
            "tool_calls":         data["tool_calls"],
            "denied_count":       data["denied_count"],
            "turn_count":         data["turn_count"],
            "guardrail_warnings": data.get("guardrail_warnings", []),
        })

        return [construct_response_from_request(
            request=request_piece,
            response_text_pieces=[response_text],
        )]

    def get_identifier(self) -> dict:
        return {"__type__": "PolicyGuardTarget", "url": self.base_url}
