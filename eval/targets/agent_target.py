"""
eval/targets/agent_target.py

PyRIT PromptTarget wrappers for the ReAct, Coder-Reviewer, and Policy-Guard
endpoints. These allow PyRIT orchestrators to send payloads to our agents
just like any other PyRIT target.
"""

import httpx
from pyrit.prompt_target import PromptChatTarget
from pyrit.models import PromptRequestResponse, PromptRequestPiece


class AgentTarget(PromptChatTarget):
    """
    Wraps one of our FastAPI agent endpoints as a PyRIT target.

    Args:
        agent_url: base URL of the agent (e.g. http://react-agent:8000)
        agent_type: "react", "coder_reviewer", or "policy_guard" — stored in metadata only
        timeout: HTTP request timeout in seconds
    """

    def __init__(self, agent_url: str, agent_type: str = "react", timeout: int = 60):
        super().__init__()
        self.agent_url  = agent_url.rstrip("/")
        self.agent_type = agent_type
        self.timeout    = timeout
        self._client    = httpx.Client(timeout=timeout)

    def send_prompt_default_async(self, *, prompt_request: PromptRequestPiece) -> PromptRequestResponse:
        raise NotImplementedError("Use send_prompt_default instead")

    def send_prompt_default(self, *, prompt_request: PromptRequestPiece) -> PromptRequestResponse:
        task = prompt_request.converted_prompt_text or prompt_request.original_prompt_text

        try:
            response = self._client.post(
                f"{self.agent_url}/run",
                json={"task": task},
                timeout=self.timeout,
            )
            response.raise_for_status()
            data    = response.json()
            # Return the agent's final_response as the target's reply
            # Full tool call log is in data["tool_calls"] — scorer can access via metadata
            reply   = data.get("final_response") or str(data.get("tool_calls", ""))

        except httpx.HTTPError as e:
            reply = f"HTTP_ERROR: {e}"
        except Exception as e:
            reply = f"ERROR: {e}"

        return self._build_response(
            request=prompt_request,
            response_text=reply,
        )

    def _build_response(self, request, response_text):
        return PromptRequestResponse(
            request_pieces=[
                PromptRequestPiece(
                    role="assistant",
                    original_prompt_text=response_text,
                    converted_prompt_text=response_text,
                    prompt_target_identifier={"target": self.agent_type},
                )
            ]
        )

    def is_json_response_supported(self) -> bool:
        return False
