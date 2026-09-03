"""The agent loop.

A manual tool-use loop over the Messages API (streaming). It is deliberately
not the SDK tool runner: the approval checkpoint has to be able to interrupt
the loop, the operator sees the model's text as it streams, and the
conversation history must stay append-only so the transcript is an honest
record of what the agent said and did.

Model defaults to Claude Fable 5.1 because the operating procedure was
written for it. Fable's safety classifiers can decline cybersecurity-adjacent
requests, so the request opts into server-side refusal fallbacks
(`fallbacks="default"`), which re-runs a declined turn on an Opus-tier model.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

import anthropic

from .tools import ToolBox

DEFAULT_MODEL = "claude-fable-5-1"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
DEFAULT_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "ad_endpoint_hardening_system_prompt.md"

HARNESS_NOTES = """
## Harness notes (this session)

You are running inside a CLI harness with tools. Practical rules:

- Discovery data is already loaded; start with `list_findings` and `rank_findings` rather than asking the operator
  to paste data. Use `get_finding` / `get_guidance` for detail on demand; do not dump every entry into your reply.
- `request_remediation_approval` IS the approval checkpoint. It shows the operator the checkpoint text and blocks
  for their reply. Never claim a change was made unless that tool returned status "executed"; a "dry-run" result
  means nothing changed on the domain. Do not simulate approval in prose.
- After a "stopped" result, do not request more approvals: verify what was already changed, then write the summary.
- Tier 0 changes need `tier0: true` on the approval call and are approved only with the phrase "yes tier0".
- Use `run_validation_query` (read-only) to confirm a finding or verify a fix; record outcomes with
  `record_verification`. If the executor is in dry-run mode, mark findings "unverified" rather than "pass".
- When the operator asks for the report, or the session is ending, produce the summary report (section 7 of the
  procedure) and save it with `save_report`.
- Keep replies dense and analyst-grade: findings, attack-path mapping, severity, confidence, then the proposal.
"""


def load_system_prompt(path: str | Path | None = None) -> str:
    p = Path(path) if path else DEFAULT_PROMPT_PATH
    return p.read_text(encoding="utf-8").rstrip() + "\n" + HARNESS_NOTES


class HardeningAgent:
    def __init__(
        self,
        toolbox: ToolBox,
        client: anthropic.Anthropic | None = None,
        model: str = DEFAULT_MODEL,
        system_prompt: str | None = None,
        effort: str = "high",
        max_tokens: int = 64000,
        use_fallbacks: bool = True,
        on_text: Callable[[str], None] | None = None,
        max_tool_rounds: int = 60,
    ):
        self.toolbox = toolbox
        self.client = client or anthropic.Anthropic()
        self.model = model
        self.system_prompt = system_prompt or load_system_prompt()
        self.effort = effort
        self.max_tokens = max_tokens
        self.use_fallbacks = use_fallbacks
        self.on_text = on_text or (lambda s: (sys.stdout.write(s), sys.stdout.flush()))
        self.max_tool_rounds = max_tool_rounds
        self.messages: list[dict] = []
        self.last_usage = None

    # ------------------------------------------------------------------
    def _request_params(self) -> dict:
        params = dict(
            model=self.model,
            max_tokens=self.max_tokens,
            system=[{"type": "text", "text": self.system_prompt, "cache_control": {"type": "ephemeral"}}],
            tools=self.toolbox.definitions(),
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort},
            messages=self.messages,
        )
        if self.use_fallbacks:
            params["fallbacks"] = "default"
            params["betas"] = [FALLBACK_BETA]
        return params

    def _send(self):
        """One streamed request. Streams text to on_text, returns the final message."""
        with self.client.beta.messages.stream(**self._request_params()) as stream:
            for event in stream:
                if event.type == "content_block_delta" and getattr(event.delta, "type", "") == "text_delta":
                    self.on_text(event.delta.text)
            return stream.get_final_message()

    # ------------------------------------------------------------------
    def run_turn(self, user_text: str) -> str:
        """Send one operator message and run tool calls until the model ends its turn.
        Returns the concatenated assistant text for the turn."""
        self.messages.append({"role": "user", "content": user_text})
        collected: list[str] = []

        for _ in range(self.max_tool_rounds):
            message = self._send()
            self.last_usage = getattr(message, "usage", None)

            if message.stop_reason == "refusal":
                # Content is empty or partial; do not append it. Roll back the user turn so history stays valid.
                details = getattr(message, "stop_details", None)
                category = getattr(details, "category", None) if details else None
                self.messages.pop()
                note = (f"\n[refusal] The model declined this request (category: {category}). "
                        "Nothing was changed. Rephrase, or run with --model claude-opus-5.\n")
                self.on_text(note)
                collected.append(note)
                return "".join(collected)

            self.messages.append({"role": "assistant", "content": message.content})
            collected.extend(b.text for b in message.content if getattr(b, "type", "") == "text")

            if message.stop_reason == "pause_turn":
                continue
            if message.stop_reason == "max_tokens":
                self.on_text("\n[warning] output hit max_tokens; ask the model to continue.\n")
                break

            tool_uses = [b for b in message.content if getattr(b, "type", "") == "tool_use"]
            if not tool_uses:
                break

            results = []
            for tu in tool_uses:
                self.on_text(f"\n[tool] {tu.name}({_short(tu.input)})\n")
                content, is_error = self.toolbox.dispatch(tu.name, dict(tu.input or {}))
                block = {"type": "tool_result", "tool_use_id": tu.id, "content": content}
                if is_error:
                    block["is_error"] = True
                results.append(block)
            # all results for the round go back in ONE user message
            self.messages.append({"role": "user", "content": results})
            self.on_text("\n")
        else:
            self.on_text("\n[warning] tool-round limit reached for this turn.\n")

        return "".join(collected)


def _short(inp, limit: int = 160) -> str:
    s = ", ".join(f"{k}={str(v)[:60]!r}" for k, v in (inp or {}).items())
    return s if len(s) <= limit else s[:limit] + "..."
