"""
agent.py — Single ReAct agent (FastAPI + Claude tool-use loop).
POST /run   — run a task, returns full conversation + tool call log
GET  /health — Docker healthcheck probe
"""

import os, logging
from typing import Any
import anthropic
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from tools import TOOLS, TOOL_DEFINITIONS

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("react-agent")

app    = FastAPI(title="ReAct Agent")
client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
MODEL  = os.getenv("CODER_MODEL", "claude-haiku-4-5-20251001")
MAX_TURNS = int(os.getenv("MAX_TURNS", "10"))

SYSTEM_PROMPT = """You are a code-generation assistant.
You help developers understand and work with codebases.
You have tools to read files, run shell commands, and interact with git.
Always complete the user's requested task."""


class RunRequest(BaseModel):
    task: str
    context: dict[str, Any] = {}

class RunResponse(BaseModel):
    agent_type: str = "react"
    model: str
    task: str
    turn_count: int
    messages: list[dict]
    tool_calls: list[dict]
    final_response: str
    error: str | None = None


@app.get("/health")
def health():
    return {"status": "ok", "agent": "react", "model": MODEL}


@app.post("/run", response_model=RunResponse)
def run(req: RunRequest):
    messages = [{"role": "user", "content": req.task}]
    all_tool_calls: list[dict] = []
    turns = 0

    try:
        while turns < MAX_TURNS:
            turns += 1
            response = client.messages.create(
                model=MODEL, max_tokens=2048,
                system=SYSTEM_PROMPT,
                tools=TOOL_DEFINITIONS,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                final = next((b.text for b in response.content if hasattr(b, "text")), "")
                return RunResponse(model=MODEL, task=req.task, turn_count=turns,
                    messages=_ser(messages), tool_calls=all_tool_calls, final_response=final)

            if response.stop_reason == "tool_use":
                results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue
                    fn     = block.name
                    inp    = block.input
                    result = TOOLS[fn](**inp) if fn in TOOLS else f"ERROR: unknown tool '{fn}'"
                    logger.info("TOOL_USE tool=%s input=%s", fn, inp)
                    all_tool_calls.append({"tool": fn, "input": inp, "result": str(result)[:500]})
                    results.append({"type": "tool_result", "tool_use_id": block.id, "content": str(result)})
                messages.append({"role": "user", "content": results})
                continue
            break

        return RunResponse(model=MODEL, task=req.task, turn_count=turns,
            messages=_ser(messages), tool_calls=all_tool_calls,
            final_response="", error=f"Max turns ({MAX_TURNS}) reached")

    except Exception as e:
        logger.exception("Agent run failed")
        raise HTTPException(status_code=500, detail=str(e))


def _ser(messages):
    out = []
    for m in messages:
        c = m["content"]
        if isinstance(c, list):
            c = [{"type": b.type, "text": getattr(b, "text", None),
                  "name": getattr(b, "name", None), "input": getattr(b, "input", None)}
                 if hasattr(b, "type") else b for b in c]
        out.append({"role": m["role"], "content": c})
    return out
