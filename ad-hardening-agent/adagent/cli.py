"""Command-line entry point.

  adagent chat    interactive session with the defensive agent (needs an Anthropic credential)
  adagent triage  offline graph-based prioritization, no model call
  adagent import  convert a SharpHound collection into findings JSON (offline)

Run `adagent chat --demo` to try it against the bundled sample domain.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .catalog import Catalog, DEFAULT_CATALOG_PATH, PACKAGE_ROOT
from .executor import DryRunExecutor, PowerShellExecutor
from .findings import Finding, import_sharphound, load_adremedy_export, save_findings
from .knowledge_base import KnowledgeBase
from .prioritize import rank_findings
from .state import EngagementState
from .tools import ToolBox

SAMPLES = PACKAGE_ROOT / "data" / "samples"


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def build_context(args) -> tuple[Catalog, KnowledgeBase, list[Finding], dict]:
    catalog = Catalog.load(args.catalog)
    kb = KnowledgeBase.load(scripts_path=args.scripts, host_history_path=args.host_history, edges_path=args.edges)
    kb.load_adremedy_catalog(args.catalog or DEFAULT_CATALOG_PATH)

    findings: list[Finding] = []
    loaded = {"findings_files": [], "sharphound": None, "edges": 0}

    if getattr(args, "demo", False):
        args.sharphound = args.sharphound or str(SAMPLES)
        if not args.scripts and (SAMPLES / "scripts.json").exists():
            kb2 = KnowledgeBase.load(scripts_path=SAMPLES / "scripts.json", host_history_path=SAMPLES / "host_history.json")
            kb.scripts.update(kb2.scripts)
            kb.host_history.update(kb2.host_history)

    for path in (args.findings or []):
        findings.extend(load_adremedy_export(path, catalog))
        loaded["findings_files"].append(str(path))

    if args.sharphound:
        imp = import_sharphound(args.sharphound, catalog, include_default_principals=args.include_default_principals)
        findings.extend(imp.findings)
        kb.merge_edges(imp.edges)
        loaded["sharphound"] = str(args.sharphound)

    loaded["edges"] = len(kb.edges)
    findings.sort(key=lambda f: (f.severity_rank, f.finding_id))
    return catalog, kb, findings, loaded


def add_data_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--findings", action="append", help="ADRemedy findings JSON export (repeatable)")
    p.add_argument("--sharphound", help="SharpHound JSON file or directory")
    p.add_argument("--edges", help="Extra BloodHound-style edges JSON [{source,target,edge_type}]")
    p.add_argument("--scripts", help="Vetted script library JSON")
    p.add_argument("--host-history", dest="host_history", help="Host incident history JSON")
    p.add_argument("--catalog", help="Remediation catalog JSON (default: bundled ADRemedy catalog)")
    p.add_argument("--include-default-principals", action="store_true",
                   help="Report edges held by built-in Tier 0 principals too")
    p.add_argument("--demo", action="store_true", help="Load the bundled sample domain (CORP.LOCAL)")


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_import(args) -> int:
    catalog = Catalog.load(args.catalog)
    imp = import_sharphound(args.sharphound, catalog, include_default_principals=args.include_default_principals)
    out = Path(args.out)
    save_findings(imp.findings, out)
    if args.edges_out:
        Path(args.edges_out).write_text(json.dumps(imp.edges, indent=2), encoding="utf-8")
    print(f"{len(imp.findings)} finding(s), {len(imp.edges)} graph edge(s) -> {out}")
    for f in imp.findings:
        print(f"  [{f.severity:8}] {f.finding_id}  {f.title} ({f.affected_count})")
    return 0


def cmd_triage(args) -> int:
    _, kb, findings, loaded = build_context(args)
    if not findings:
        print("No findings loaded. Pass --findings, --sharphound, or --demo.", file=sys.stderr)
        return 2
    result = rank_findings(findings, kb, da_node=args.da)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    print(f"Graph available: {result['graph_available']}  edges: {result['edges_loaded']}  "
          f"Tier 0 target: {result['domain_admins_node']}")
    print(result["note"])
    print()
    print(f"{'#':>2} {'tier':>4} {'sev':8} {'hops':>4} {'paths':>5}  {'finding':14} title")
    for r in result["ranked"]:
        hops = "-" if r["hops_to_da"] is None else r["hops_to_da"]
        print(f"{r['rank']:>2} {r['tier']:>4} {r['severity']:8} {hops:>4} {r['path_multiplicity']:>5}  "
              f"{r['finding_id']:14} {r['title']} [{r['affected_count']}]")
        print(f"{'':32}-> {r['reason']}")
    return 0


def engagement_brief(state: EngagementState, findings: list[Finding], loaded: dict, executor_name: str,
                     kb: KnowledgeBase) -> str:
    sev = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    lines = [
        "# Engagement brief",
        f"- Authorization: granted by {state.authorized_by or '(not stated)'} for the scope below. "
        "Treat everything outside it as report-only.",
        f"- Scope: {', '.join(state.scope) or '(entire loaded dataset)'}",
        f"- Executor mode: {executor_name}" + (" (nothing will change on the domain; treat all remediation as dry-run)"
                                                 if executor_name == "dry-run" else " (approved commands WILL run)"),
        f"- Findings loaded: {len(findings)} ({', '.join(f'{k}: {v}' for k, v in sorted(sev.items()))})",
        f"- Sources: {', '.join(loaded['findings_files']) or 'none'}"
        + (f"; SharpHound: {loaded['sharphound']}" if loaded["sharphound"] else ""),
        f"- Attack-graph edges: {loaded['edges']}" + ("" if loaded["edges"] else " (none: prioritization is severity-only)"),
        f"- Script library entries: {len(kb.scripts)}; hosts with incident history: {len(kb.host_history)}",
        "",
        "Begin with discovery and risk assessment: list and rank the findings, explain the top attack paths in plain "
        "language, then propose a mitigation plan. Do not request any approval until I have seen the plan.",
    ]
    return "\n".join(lines)


def cmd_chat(args) -> int:
    from .agent import HardeningAgent  # imported here so triage/import work without the SDK installed

    catalog, kb, findings, loaded = build_context(args)
    if not findings:
        print("No findings loaded. Pass --findings, --sharphound, or --demo.", file=sys.stderr)
        return 2

    state = EngagementState(
        scope=[s.strip() for s in (args.scope or "").split(",") if s.strip()],
        authorized_by=args.authorized_by or "",
        authorized=bool(args.authorized_by),
        output_dir=Path(args.output_dir),
    )
    if not state.authorized:
        print("No --authorized-by given: the agent can assess but will refuse every remediation checkpoint.")

    executor = PowerShellExecutor() if args.execute else DryRunExecutor()
    if args.execute:
        confirm = input("--execute is set: approved commands will run on this host via PowerShell. Type 'I understand' to continue: ")
        if confirm.strip().lower() != "i understand":
            print("Aborted.")
            return 1

    toolbox = ToolBox(catalog, kb, findings, state, executor=executor)
    agent = HardeningAgent(toolbox, model=args.model, effort=args.effort, use_fallbacks=not args.no_fallbacks,
                           system_prompt=None if not args.system_prompt else Path(args.system_prompt).read_text(encoding="utf-8"))

    print(f"AD hardening agent  model={args.model}  effort={args.effort}  executor={executor.name}  "
          f"fallbacks={'on' if not args.no_fallbacks else 'off'}")
    print("Type 'report' for the summary report, 'exit' to end the session.\n")

    brief = engagement_brief(state, findings, loaded, executor.name, kb)
    try:
        agent.run_turn(brief)
        print()
        while True:
            try:
                text = input("\noperator> ").strip()
            except EOFError:
                break
            if not text:
                continue
            if text.lower() in {"exit", "quit"}:
                break
            if text.lower() == "report":
                text = ("Write the summary report now (found / fixed / deferred and why / which findings shortened the "
                        "path to Domain Admins) and save it with save_report.")
            agent.run_turn(text)
            print()
    except KeyboardInterrupt:
        print("\ninterrupted")
    finally:
        path = state.save()
        print(f"\nsession log: {path}")
        for r in state.reports:
            print(f"report: {r}")
    return 0


# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="adagent", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_chat = sub.add_parser("chat", help="interactive defensive-agent session")
    add_data_args(p_chat)
    p_chat.add_argument("--scope", help="Comma-separated OUs/hosts/domains in scope")
    p_chat.add_argument("--authorized-by", dest="authorized_by", help="Who authorized this assessment (required for any remediation)")
    p_chat.add_argument("--model", default="claude-fable-5-1")
    p_chat.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    p_chat.add_argument("--no-fallbacks", action="store_true", help="Disable server-side refusal fallbacks")
    p_chat.add_argument("--execute", action="store_true", help="Run approved commands via PowerShell (default: dry-run)")
    p_chat.add_argument("--output-dir", dest="output_dir", default="./adagent-output")
    p_chat.add_argument("--system-prompt", dest="system_prompt", help="Override the bundled system prompt file")
    p_chat.set_defaults(func=cmd_chat)

    p_triage = sub.add_parser("triage", help="offline graph-based prioritization")
    add_data_args(p_triage)
    p_triage.add_argument("--da", help="Tier 0 target node (default: auto-detect DOMAIN ADMINS@...)")
    p_triage.add_argument("--json", action="store_true")
    p_triage.set_defaults(func=cmd_triage)

    p_imp = sub.add_parser("import", help="convert SharpHound JSON into findings")
    p_imp.add_argument("--sharphound", required=True)
    p_imp.add_argument("--out", default="findings.json")
    p_imp.add_argument("--edges-out", dest="edges_out")
    p_imp.add_argument("--catalog")
    p_imp.add_argument("--include-default-principals", action="store_true")
    p_imp.set_defaults(func=cmd_import)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
