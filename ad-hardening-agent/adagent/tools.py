"""Tool layer: what the model is allowed to do, and how each call is gated.

Read-only tools (findings, catalog, script library, host history, attack
graph) run freely. The two tools that can change state on a real domain
are gated in code, not just in the prompt:

  run_validation_query          - read-only verb guard + executor (dry-run by default)
  request_remediation_approval  - prints the checkpoint, blocks on the operator's
                                  yes / skip / stop, and only then executes

Tool definitions are plain JSON schemas so they can be sent to the Messages
API directly; `ToolBox.dispatch` executes them.
"""

from __future__ import annotations

import json
from typing import Any

from . import knowledge_base as kbmod
from .catalog import Catalog
from .executor import DryRunExecutor, is_read_only
from .findings import Finding
from .knowledge_base import KnowledgeBase
from .prioritize import rank_findings
from .state import EngagementState

APPROVE = {"yes", "y"}
SKIP = {"skip", "no", "n"}
STOP = {"stop", "abort", "quit"}
TIER0_PHRASE = "yes tier0"


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "list_findings",
        "description": "List the findings loaded for this engagement (summaries only). Filter by severity, category, "
                       "or finding_id. Use get_finding for affected objects and get_guidance for the remediation writeup.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]},
                "category": {"type": "string"},
                "finding_id": {"type": "string"},
            },
        },
    },
    {
        "name": "get_finding",
        "description": "Full detail for one finding id: evidence, every affected object (principals, targets, hosts) "
                       "and source-tool detail.",
        "input_schema": {
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
        },
    },
    {
        "name": "get_guidance",
        "description": "Look up the vetted ADRemedy remediation catalog: how the weakness is abused, the attack chain, "
                       "MITRE mapping, ordered remediation steps with commands, a validation query, and what could "
                       "break. Query by finding_id, BloodHound edge name, keyword, category or severity.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "edge": {"type": "string", "description": "BloodHound edge name, e.g. GenericAll, DCSync"},
                "keyword": {"type": "string"},
                "category": {"type": "string"},
                "severity": {"type": "string"},
                "detailed": {"type": "boolean", "description": "Return full writeups instead of summaries. Default true for a single id/edge."},
            },
        },
    },
    {
        "name": "rank_findings",
        "description": "Deterministic graph-based prioritization of all loaded findings: severity combined with "
                       "hops-to-Domain-Admins and path multiplicity, in the four ordered tiers from the operating "
                       "procedure, with a one-line reason per finding. Says explicitly when it is severity-only.",
        "input_schema": {
            "type": "object",
            "properties": {"domain_admins_node": {"type": "string", "description": "Override the Tier 0 target node name"}},
        },
    },
    {
        "name": "lookup_script",
        "description": "Search the vetted script/tooling library (including the ADRemedy catalog entries) by tag, "
                       "name fragment or keyword before writing any remediation script from scratch.",
        "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
    },
    {
        "name": "check_host_history",
        "description": "Prior incident / compromise / remediation history for a host. Use it to weight findings on "
                       "repeat-offender hosts and to avoid re-proposing a fix that already failed to hold.",
        "input_schema": {"type": "object", "properties": {"hostname": {"type": "string"}}, "required": ["hostname"]},
    },
    {
        "name": "query_attack_graph",
        "description": "Shortest attack path (BFS) between two nodes in the loaded BloodHound-style edge data, "
                       "e.g. from a user to DOMAIN ADMINS@CORP.LOCAL. Returns hops and the edge sequence.",
        "input_schema": {
            "type": "object",
            "properties": {"start_node": {"type": "string"}, "target_node": {"type": "string"}},
            "required": ["start_node", "target_node"],
        },
    },
    {
        "name": "path_multiplicity",
        "description": "How many distinct attack paths to the target pass through a node - the chokepoint signal for "
                       "prioritization.",
        "input_schema": {
            "type": "object",
            "properties": {
                "node": {"type": "string"},
                "target_node": {"type": "string"},
                "max_hops": {"type": "integer", "default": 6},
            },
            "required": ["node", "target_node"],
        },
    },
    {
        "name": "resolve_edge",
        "description": "Map a raw BloodHound edge name to its catalog finding id (DCSync component rights collapse "
                       "onto one entry; structural edges are reported as ignored).",
        "input_schema": {"type": "object", "properties": {"edge": {"type": "string"}}, "required": ["edge"]},
    },
    {
        "name": "classify_principal",
        "description": "Is this principal a built-in Tier 0 identity whose sweeping rights are expected (SYSTEM, "
                       "Domain Admins, Enterprise Admins...) rather than a finding?",
        "input_schema": {
            "type": "object",
            "properties": {"sid": {"type": "string"}, "name": {"type": "string"},
                           "include_default_principals": {"type": "boolean"}},
        },
    },
    {
        "name": "escalate_edge_severity",
        "description": "Raise an edge finding's severity to Critical when its affected objects include a Tier 0 target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_severity": {"type": "string"},
                "affected_objects": {
                    "type": "array",
                    "items": {"type": "object", "properties": {"target": {"type": "string"}, "target_type": {"type": "string"}}},
                },
            },
            "required": ["base_severity"],
        },
    },
    {
        "name": "run_validation_query",
        "description": "Run a READ-ONLY PowerShell query on the operator's host, e.g. a catalog validation query, to "
                       "confirm a finding or verify that a remediation landed. State-changing cmdlets are rejected. "
                       "In dry-run mode (the default) nothing executes and the command is only recorded; treat the "
                       "finding as unverified in that case.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "command": {"type": "string", "description": "PowerShell to run. Defaults to the catalog validation query for finding_id."},
                "purpose": {"type": "string", "description": "Why you are running it (confirm finding / verify fix)."},
            },
            "required": ["finding_id", "purpose"],
        },
    },
    {
        "name": "request_remediation_approval",
        "description": (
            "APPROVAL CHECKPOINT. Presents one logically distinct change to the human operator and blocks until they "
            "reply. Only if they reply 'yes' are the commands executed (dry-run unless the operator started the "
            "session with --execute). 'skip' defers the change; 'stop' halts the session - do not call this tool "
            "again after a stop. Tier 0 changes (DCs, Domain Admins/Enterprise Admins/krbtgt/AdminSDHolder, the "
            "domain object) must set tier0=true; they need the operator to type 'yes tier0'. Always include a "
            "rollback and state whether the script comes from the vetted library, is a modified library script, "
            "or is new and unvetted. Never call this for an object outside the declared scope."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "ready_to_fix": {"type": "string", "description": "Plain-language statement of the change, e.g. 'Remove Domain Users from local Administrators on WKS-014 (1 of 40 hosts)'"},
                "risk_if_not": {"type": "string"},
                "risk_if_breaks": {"type": "string"},
                "commands": {"type": "array", "items": {"type": "string"}, "description": "Exact commands to run, in order"},
                "rollback": {"type": "string", "description": "Exactly how to restore the previous state"},
                "current_state": {"type": "string", "description": "What the setting/membership is right now, for the rollback record"},
                "tier0": {"type": "boolean"},
                "script_source": {"type": "string", "enum": ["library", "modified-library", "new-unvetted", "catalog"]},
                "batch": {"type": "boolean", "description": "True when one approval covers the same low-risk change across many hosts"},
                "targets": {"type": "array", "items": {"type": "string"}, "description": "Objects/hosts this change touches"},
            },
            "required": ["finding_id", "ready_to_fix", "risk_if_not", "risk_if_breaks", "commands", "rollback", "script_source"],
        },
    },
    {
        "name": "record_verification",
        "description": "Record the verification outcome for a finding after remediation: pass, fail, or unverified, "
                       "with a note (e.g. hosts that did not pick up the change).",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string"},
                "status": {"type": "string", "enum": ["pass", "fail", "unverified", "deferred"]},
                "note": {"type": "string"},
            },
            "required": ["finding_id", "status", "note"],
        },
    },
    {
        "name": "save_report",
        "description": "Save the summary report (markdown) to the engagement output directory. Call this when the "
                       "operator asks for the report or the session is wrapping up.",
        "input_schema": {
            "type": "object",
            "properties": {"markdown": {"type": "string"}, "filename": {"type": "string"}},
            "required": ["markdown"],
        },
    },
]


class ToolBox:
    def __init__(self, catalog: Catalog, kb: KnowledgeBase, findings: list[Finding],
                 state: EngagementState, executor=None, printer=print):
        self.catalog = catalog
        self.kb = kb
        self.findings = findings
        self.state = state
        self.executor = executor or DryRunExecutor()
        self.printer = printer

    # -- helpers --------------------------------------------------------
    def _finding(self, fid: str) -> list[Finding]:
        return [f for f in self.findings if f.finding_id.lower() == (fid or "").lower()]

    def definitions(self) -> list[dict]:
        return TOOL_DEFINITIONS

    # -- dispatch -------------------------------------------------------
    def dispatch(self, name: str, tool_input: dict) -> tuple[str, bool]:
        """Returns (json_result, is_error)."""
        handler = getattr(self, f"tool_{name}", None)
        if handler is None:
            return json.dumps({"error": f"unknown tool '{name}'"}), True
        try:
            result = handler(tool_input or {})
        except Exception as exc:  # surfaced to the model as an error result, never crashes the loop
            return json.dumps({"error": f"{type(exc).__name__}: {exc}"}), True
        return json.dumps(result, default=str), False

    # -- read-only tools ------------------------------------------------
    def tool_list_findings(self, inp: dict) -> dict:
        rows = self.findings
        if inp.get("severity"):
            rows = [f for f in rows if f.severity.lower() == inp["severity"].lower()]
        if inp.get("category"):
            rows = [f for f in rows if f.category.lower() == inp["category"].lower()]
        if inp.get("finding_id"):
            rows = [f for f in rows if f.finding_id.lower() == inp["finding_id"].lower()]
        return {"count": len(rows), "findings": [f.summary() for f in rows],
                "graph_edges_loaded": len(self.kb.edges)}

    def tool_get_finding(self, inp: dict) -> dict:
        rows = self._finding(inp.get("finding_id", ""))
        if not rows:
            return {"found": False, "finding_id": inp.get("finding_id")}
        return {"found": True, "findings": [f.to_dict() for f in rows]}

    def tool_get_guidance(self, inp: dict) -> dict:
        if inp.get("finding_id"):
            entry = self.catalog.get(inp["finding_id"])
            if not entry:
                return {"found": False, "finding_id": inp["finding_id"]}
            return {"found": True, "entries": [entry] if inp.get("detailed", True) else [self.catalog.summary(entry)]}
        entries = self.catalog.search(keyword=inp.get("keyword"), category=inp.get("category"),
                                      severity=inp.get("severity"), edge=inp.get("edge"))
        detailed = inp.get("detailed", bool(inp.get("edge")))
        return {"found": bool(entries), "count": len(entries),
                "entries": entries if detailed else [self.catalog.summary(e) for e in entries]}

    def tool_rank_findings(self, inp: dict) -> dict:
        return rank_findings(self.findings, self.kb, da_node=inp.get("domain_admins_node"))

    def tool_lookup_script(self, inp: dict) -> dict:
        return kbmod.lookup_script(inp, self.kb)

    def tool_check_host_history(self, inp: dict) -> dict:
        return kbmod.check_host_history(inp, self.kb)

    def tool_query_attack_graph(self, inp: dict) -> dict:
        return kbmod.query_attack_graph(inp, self.kb)

    def tool_path_multiplicity(self, inp: dict) -> dict:
        return kbmod.path_multiplicity(inp, self.kb)

    def tool_resolve_edge(self, inp: dict) -> dict:
        return kbmod.resolve_edge(inp, self.kb)

    def tool_classify_principal(self, inp: dict) -> dict:
        return kbmod.classify_principal(inp, self.kb)

    def tool_escalate_edge_severity(self, inp: dict) -> dict:
        return kbmod.escalate_edge_severity(inp, self.kb)

    # -- gated tools ----------------------------------------------------
    def tool_run_validation_query(self, inp: dict) -> dict:
        fid = inp.get("finding_id", "")
        command = inp.get("command") or (self.catalog.get(fid) or {}).get("validation")
        if not command:
            return {"ran": False, "reason": f"no command given and no catalog validation query for {fid}"}
        ok, offending = is_read_only(command)
        if not ok:
            self.state.record_execution(kind="validation", finding_id=fid, command=command, rejected=True,
                                        reason=f"not read-only: '{offending}'")
            return {"ran": False, "rejected": True,
                    "reason": f"rejected: '{offending}' looks state-changing. Validation queries must be read-only; "
                              f"use request_remediation_approval for changes."}
        self.printer(f"\n[validation] {inp.get('purpose', '')}\n  PS> {command}")
        result = self.executor.run(command)
        self.state.record_execution(kind="validation", finding_id=fid, purpose=inp.get("purpose"), **result.to_dict())
        out = result.to_dict()
        out["ran"] = result.executed
        if not result.executed:
            out["verification_status"] = "unverified"
        return out

    def tool_request_remediation_approval(self, inp: dict) -> dict:
        if self.state.stopped:
            return {"approved": False, "status": "stopped",
                    "reason": "operator already said stop; no further remediation this session"}
        if not self.state.authorized:
            return {"approved": False, "status": "unauthorized",
                    "reason": "no authorization recorded for this engagement; confirm authorization with the operator first"}

        fid = inp.get("finding_id", "")
        tier0 = bool(inp.get("tier0"))
        commands = [c for c in (inp.get("commands") or []) if c and c.strip()]
        banner = "=" * 78
        lines = [
            "", banner,
            ("!! TIER 0 CHANGE - separately called-out approval required !!" if tier0 else "APPROVAL CHECKPOINT"),
            banner,
            f"Finding:            {fid}",
            f"Ready to fix:       {inp.get('ready_to_fix', '')}",
            f"Risk if I don't:    {inp.get('risk_if_not', '')}",
            f"Risk if this breaks something: {inp.get('risk_if_breaks', '')}",
            f"Script source:      {inp.get('script_source', '')}" + ("  <-- NEW / UNVETTED, review carefully" if inp.get("script_source") == "new-unvetted" else ""),
            f"Current state:      {inp.get('current_state', '(not stated)')}",
            f"Rollback:           {inp.get('rollback', '')}",
            f"Targets:            {', '.join(inp.get('targets') or []) or '(see commands)'}",
            f"Batch approval:     {'yes' if inp.get('batch') else 'no'}",
            f"Executor:           {self.executor.name}",
            "Commands:",
        ]
        lines += [f"  {i}. {c}" for i, c in enumerate(commands, 1)]
        lines += [banner,
                  (f"Type '{TIER0_PHRASE}' to proceed, 'skip' to leave it, or 'stop' to end remediation." if tier0
                   else "Reply 'yes' to proceed, 'skip' to leave this for later, or 'stop' to end remediation.")]
        self.printer("\n".join(lines))

        answer = (self.state.ask_operator("> ") or "").strip().lower()
        record = dict(finding_id=fid, ready_to_fix=inp.get("ready_to_fix"), tier0=tier0, commands=commands,
                      rollback=inp.get("rollback"), script_source=inp.get("script_source"), answer=answer)

        if answer in STOP:
            self.state.stopped = True
            self.state.record_approval(decision="stop", **record)
            return {"approved": False, "status": "stopped",
                    "reason": "operator said stop. End remediation now, verify what was already changed, and write the summary."}
        approved = (answer == TIER0_PHRASE) if tier0 else (answer in APPROVE)
        if not approved:
            decision = "skip" if answer in SKIP or not answer else "not-approved"
            self.state.record_approval(decision=decision, **record)
            if tier0 and answer in APPROVE:
                return {"approved": False, "status": "skipped",
                        "reason": f"Tier 0 changes require the operator to type '{TIER0_PHRASE}' exactly; plain 'yes' is not enough. Treat as skipped unless they re-approve."}
            return {"approved": False, "status": "skipped", "reason": f"operator replied '{answer or 'skip'}'; leave this finding for later"}

        self.state.record_approval(decision="approved", **record)
        results = []
        for cmd in commands:
            self.printer(f"[remediate] PS> {cmd}")
            r = self.executor.run(cmd)
            entry = self.state.record_execution(kind="remediation", finding_id=fid, **r.to_dict())
            results.append({k: entry[k] for k in ("command", "executed", "dry_run", "stdout", "stderr", "return_code", "note")})
            if r.executed and r.return_code not in (0, None):
                self.printer(f"[remediate] command failed (rc={r.return_code}); stopping this change.")
                break
        executed_any = any(r["executed"] for r in results)
        return {
            "approved": True,
            "status": "executed" if executed_any else "dry-run",
            "results": results,
            "next": ("Verify with a read-only query and record_verification." if executed_any
                     else "Dry-run: nothing changed. Record the finding as unverified/deferred unless the operator re-runs with --execute."),
        }

    def tool_record_verification(self, inp: dict) -> dict:
        entry = self.state.record_verification(finding_id=inp.get("finding_id"), status=inp.get("status"),
                                               note=inp.get("note"))
        return {"recorded": True, **entry}

    def tool_save_report(self, inp: dict) -> dict:
        self.state.output_dir.mkdir(parents=True, exist_ok=True)
        name = inp.get("filename") or "hardening-report.md"
        path = self.state.output_dir / name
        path.write_text(inp["markdown"], encoding="utf-8")
        self.state.reports.append(str(path))
        return {"saved": True, "path": str(path)}
