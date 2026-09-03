"""Agent loop test with a scripted model: no network, no API key."""
import json
from pathlib import Path
from types import SimpleNamespace

from adagent.agent import HardeningAgent, load_system_prompt
from adagent.catalog import Catalog
from adagent.findings import import_sharphound
from adagent.knowledge_base import KnowledgeBase
from adagent.state import EngagementState
from adagent.tools import ToolBox

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def block(**kw):
    return SimpleNamespace(**kw)


class ScriptedAgent(HardeningAgent):
    """Replaces the network call with a canned sequence of model responses."""

    def __init__(self, toolbox, script):
        super().__init__(toolbox, client=object(), on_text=lambda s: None)
        self.script = list(script)
        self.requests = []

    def _send(self):
        self.requests.append([dict(m) for m in self.messages])
        return self.script.pop(0)


def make(tmp_path, answers=()):
    cat = Catalog.load()
    imp = import_sharphound(SAMPLES, cat)
    kb = KnowledgeBase(); kb.merge_edges(imp.edges)
    it = iter(answers)
    state = EngagementState(authorized=True, authorized_by="t", output_dir=tmp_path, ask_operator=lambda _: next(it))
    return ToolBox(cat, kb, imp.findings, state, printer=lambda s: None), state


def test_system_prompt_includes_procedure_and_harness_notes():
    sp = load_system_prompt()
    assert "Approval checkpoint" in sp and "Harness notes" in sp


def test_tool_loop_round_trips_results(tmp_path):
    tb, state = make(tmp_path, ["yes"])
    script = [
        block(stop_reason="tool_use", usage=None, content=[
            block(type="text", text="Listing."),
            block(type="tool_use", id="t1", name="list_findings", input={"severity": "Critical"}),
            block(type="tool_use", id="t2", name="rank_findings", input={}),
        ]),
        block(stop_reason="tool_use", usage=None, content=[
            block(type="tool_use", id="t3", name="request_remediation_approval", input={
                "finding_id": "ADR-KERB-002", "ready_to_fix": "x", "risk_if_not": "x", "risk_if_breaks": "x",
                "commands": ["Set-ADAccountControl -Identity jdoe -DoesNotRequirePreAuth $false"],
                "rollback": "x", "script_source": "catalog"}),
        ]),
        block(stop_reason="end_turn", usage=None, content=[block(type="text", text="Done (dry-run).")]),
    ]
    agent = ScriptedAgent(tb, script)
    text = agent.run_turn("begin")
    assert "Done (dry-run)." in text
    # history: user, assistant, user(tool results x2), assistant, user(tool result), assistant
    roles = [m["role"] for m in agent.messages]
    assert roles == ["user", "assistant", "user", "assistant", "user", "assistant"]
    results = agent.messages[2]["content"]
    assert {r["tool_use_id"] for r in results} == {"t1", "t2"}          # both results in ONE user message
    assert json.loads(results[0]["content"])["count"] >= 1
    approval = json.loads(agent.messages[4]["content"][0]["content"])
    assert approval["approved"] and approval["status"] == "dry-run"
    assert state.approvals[-1]["decision"] == "approved"


def test_refusal_rolls_back_user_turn(tmp_path):
    tb, _ = make(tmp_path)
    script = [block(stop_reason="refusal", usage=None, content=[],
                    stop_details=SimpleNamespace(category="cyber"))]
    agent = ScriptedAgent(tb, script)
    out = agent.run_turn("x")
    assert "[refusal]" in out and agent.messages == []


def test_request_params_shape(tmp_path):
    tb, _ = make(tmp_path)
    agent = ScriptedAgent(tb, [])
    p = agent._request_params()
    assert p["model"] == "claude-fable-5-1" and p["fallbacks"] == "default"
    assert p["betas"] == ["server-side-fallback-2026-07-01"]
    assert p["thinking"] == {"type": "adaptive"} and p["output_config"] == {"effort": "high"}
    assert p["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert "tool_choice" not in p
    agent.use_fallbacks = False
    assert "fallbacks" not in agent._request_params()
