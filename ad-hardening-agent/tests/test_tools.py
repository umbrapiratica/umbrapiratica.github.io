import json
from pathlib import Path

from adagent.catalog import Catalog, DEFAULT_CATALOG_PATH
from adagent.executor import DryRunExecutor, ExecResult, is_read_only
from adagent.findings import import_sharphound
from adagent.knowledge_base import KnowledgeBase
from adagent.state import EngagementState
from adagent.tools import ToolBox, TOOL_DEFINITIONS

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def make_toolbox(tmp_path, answers, executor=None, authorized=True):
    cat = Catalog.load()
    kb = KnowledgeBase.load(scripts_path=SAMPLES / "scripts.json", host_history_path=SAMPLES / "host_history.json")
    kb.load_adremedy_catalog(DEFAULT_CATALOG_PATH)
    imp = import_sharphound(SAMPLES, cat)
    kb.merge_edges(imp.edges)
    it = iter(answers)
    state = EngagementState(scope=["OU=Servers,DC=corp,DC=local"], authorized_by="CISO" if authorized else "",
                            authorized=authorized, output_dir=tmp_path, ask_operator=lambda _: next(it))
    printed = []
    tb = ToolBox(cat, kb, imp.findings, state, executor=executor or DryRunExecutor(), printer=printed.append)
    return tb, state, printed


def test_definitions_have_handlers(tmp_path):
    tb, _, _ = make_toolbox(tmp_path, [])
    for d in TOOL_DEFINITIONS:
        assert hasattr(tb, f"tool_{d['name']}"), d["name"]
        assert d["input_schema"]["type"] == "object"


def test_readonly_tools(tmp_path):
    tb, _, _ = make_toolbox(tmp_path, [])
    out, err = tb.dispatch("list_findings", {"severity": "Critical"})
    assert not err and json.loads(out)["count"] >= 1
    out, _ = tb.dispatch("get_guidance", {"edge": "WriteDacl"})
    assert json.loads(out)["entries"][0]["id"] == "ADR-ACL-003"
    out, _ = tb.dispatch("lookup_script", {"query": "LLMNR"})
    assert json.loads(out)["found"]
    out, _ = tb.dispatch("check_host_history", {"hostname": "appsrv01.corp.local"})
    assert json.loads(out)["has_history"]
    out, _ = tb.dispatch("resolve_edge", {"edge": "GetChangesAll"})
    assert json.loads(out)["finding_id"] == "ADR-ACL-007"
    out, _ = tb.dispatch("classify_principal", {"name": "CORP\\Domain Admins"})
    assert json.loads(out)["is_default_principal"]
    out, _ = tb.dispatch("rank_findings", {})
    assert json.loads(out)["graph_available"]
    out, err = tb.dispatch("no_such_tool", {})
    assert err


def test_readonly_guard():
    assert is_read_only("Get-ADUser -Filter * | Measure-Object")[0]
    assert not is_read_only("Get-ADUser jdoe | Set-ADAccountControl -DoesNotRequirePreAuth $false")[0]
    assert not is_read_only("netdom trust corp.local /domain:x /quarantine:yes")[0]
    assert not is_read_only("Reset-ADAccountPassword -Identity krbtgt -Reset")[0]


def test_validation_query_rejects_state_change(tmp_path):
    tb, state, _ = make_toolbox(tmp_path, [])
    out, _ = tb.dispatch("run_validation_query", {"finding_id": "ADR-KERB-002", "purpose": "x",
                                                  "command": "Set-ADUser -Identity jdoe -PasswordNeverExpires $false"})
    assert json.loads(out)["rejected"]
    out, _ = tb.dispatch("run_validation_query", {"finding_id": "ADR-KERB-002", "purpose": "confirm"})
    r = json.loads(out)
    assert r["dry_run"] and not r["ran"] and r["verification_status"] == "unverified"
    assert state.executions[-1]["command"].startswith("Get-ADUser")


def test_approval_skip_yes_stop(tmp_path):
    tb, state, printed = make_toolbox(tmp_path, ["skip", "yes", "stop", "yes"])
    call = {"finding_id": "ADR-KERB-002", "ready_to_fix": "Re-enable preauth on jdoe", "risk_if_not": "roast",
            "risk_if_breaks": "legacy client", "commands": ["Set-ADAccountControl -Identity jdoe -DoesNotRequirePreAuth $false"],
            "rollback": "Set-ADAccountControl -Identity jdoe -DoesNotRequirePreAuth $true", "script_source": "catalog"}

    out, _ = tb.dispatch("request_remediation_approval", call)
    assert json.loads(out)["status"] == "skipped" and state.approvals[-1]["decision"] == "skip"
    assert not state.executions

    out, _ = tb.dispatch("request_remediation_approval", call)
    r = json.loads(out)
    assert r["approved"] and r["status"] == "dry-run" and r["results"][0]["dry_run"]
    assert state.executions[-1]["kind"] == "remediation" and not state.executions[-1]["executed"]
    assert any("APPROVAL CHECKPOINT" in line for line in printed)

    out, _ = tb.dispatch("request_remediation_approval", call)
    assert json.loads(out)["status"] == "stopped" and state.stopped

    out, _ = tb.dispatch("request_remediation_approval", call)   # after stop: refused without asking
    assert json.loads(out)["status"] == "stopped"


def test_tier0_requires_phrase(tmp_path):
    tb, state, printed = make_toolbox(tmp_path, ["yes", "yes tier0"])
    call = {"finding_id": "ADR-KERB-003", "ready_to_fix": "Rotate krbtgt", "risk_if_not": "golden ticket",
            "risk_if_breaks": "auth outage", "commands": ["Reset-ADAccountPassword -Identity krbtgt -Reset"],
            "rollback": "n/a", "script_source": "catalog", "tier0": True}
    out, _ = tb.dispatch("request_remediation_approval", call)
    assert not json.loads(out)["approved"] and "yes tier0" in json.loads(out)["reason"]
    assert any("TIER 0" in line for line in printed)
    out, _ = tb.dispatch("request_remediation_approval", call)
    assert json.loads(out)["approved"]


def test_unauthorized_blocks_remediation(tmp_path):
    tb, _, _ = make_toolbox(tmp_path, ["yes"], authorized=False)
    out, _ = tb.dispatch("request_remediation_approval", {"finding_id": "x", "ready_to_fix": "x", "risk_if_not": "x",
                                                          "risk_if_breaks": "x", "commands": ["Set-X"], "rollback": "x",
                                                          "script_source": "catalog"})
    assert json.loads(out)["status"] == "unauthorized"


class FailingExecutor:
    name = "fake"

    def run(self, command, timeout=120):
        return ExecResult(executed=True, dry_run=False, command=command, stderr="boom", return_code=1)


def test_failed_command_stops_batch(tmp_path):
    tb, state, _ = make_toolbox(tmp_path, ["yes"], executor=FailingExecutor())
    out, _ = tb.dispatch("request_remediation_approval", {"finding_id": "x", "ready_to_fix": "x", "risk_if_not": "x",
                                                          "risk_if_breaks": "x", "commands": ["Set-A", "Set-B"],
                                                          "rollback": "x", "script_source": "catalog"})
    r = json.loads(out)
    assert r["status"] == "executed" and len(r["results"]) == 1 and r["results"][0]["return_code"] == 1


def test_report_and_state_save(tmp_path):
    tb, state, _ = make_toolbox(tmp_path, [])
    tb.dispatch("record_verification", {"finding_id": "ADR-KERB-002", "status": "unverified", "note": "dry-run"})
    out, _ = tb.dispatch("save_report", {"markdown": "# report"})
    assert Path(json.loads(out)["path"]).read_text() == "# report"
    log = json.loads(state.save().read_text())
    assert log["verifications"][0]["status"] == "unverified" and log["reports"]
