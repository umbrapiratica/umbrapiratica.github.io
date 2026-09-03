"""
knowledge_base.py

Reference-data layer for the defensive agent. Mirrors the offensive
EngagementState/ToolRegistry pattern: instead of stuffing large datasets
into the LLM's context up front, the agent gets tools to query this data
on demand.

Three data sources:
  - ScriptLibrary: previously written/vetted PowerShell (or other) scripts
  - HostHistory: prior incidents/compromises per host
  - AttackGraph: BloodHound-style nodes/edges, reusing the same BFS
    shortest-path logic as the offensive find_attack_path tool

Load data once at session start (from files, a database, wherever you
keep it), then register the query tools below so the agent can pull
exactly what it needs per finding instead of receiving everything at once.
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class ScriptEntry:
    name: str
    description: str
    content: str
    tags: list[str] = field(default_factory=list)     # e.g. ["hardening", "LLMNR", "GPO"]
    last_used: str | None = None                        # ISO date, if tracked
    known_good: bool = True                              # False = needs re-vetting


@dataclass
class HostIncident:
    hostname: str
    date: str                    # ISO date
    description: str             # what happened
    resolved: bool
    resolution_note: str | None = None
    tags: list[str] = field(default_factory=list)       # e.g. ["kerberoast", "reimaged"]


@dataclass
class KnowledgeBase:
    scripts: dict[str, ScriptEntry] = field(default_factory=dict)
    host_history: dict[str, list[HostIncident]] = field(default_factory=dict)
    edges: list[dict] = field(default_factory=list)  # BloodHound-style {source, target, edge_type}
    edge_map: dict[str, str] = field(default_factory=dict)  # lowercase edge name -> catalog finding ID

    # -- loaders --------------------------------------------------------

    @classmethod
    def load(
        cls,
        scripts_path: str | Path | None = None,
        host_history_path: str | Path | None = None,
        edges_path: str | Path | None = None,
    ) -> "KnowledgeBase":
        """Load from JSON files. Any/all can be omitted if you don't have
        that data source yet -- the tools just report 'no data' cleanly."""
        kb = cls()

        if scripts_path and Path(scripts_path).exists():
            raw = json.loads(Path(scripts_path).read_text())
            for entry in raw:
                s = ScriptEntry(**entry)
                kb.scripts[s.name] = s

        if host_history_path and Path(host_history_path).exists():
            raw = json.loads(Path(host_history_path).read_text())
            for hostname, incidents in raw.items():
                kb.host_history[hostname] = [HostIncident(**i) for i in incidents]

        if edges_path and Path(edges_path).exists():
            kb.edges = json.loads(Path(edges_path).read_text())

        return kb

    def merge_edges(self, new_edges: list[dict]) -> None:
        """Add freshly collected BloodHound edges (e.g. from a new
        bloodhound_collect run) to what's already known."""
        self.edges.extend(new_edges)

    def load_adremedy_catalog(self, catalog_path: str | Path) -> int:
        """Import the ADRemedy remediation catalog (Data/RemediationCatalog.json)
        as vetted script-library entries. Each catalog entry becomes one
        ScriptEntry: its 'content' is the ordered remediation steps with the
        actual PowerShell commands attached, so lookup_script surfaces
        real, previously-vetted guidance instead of the agent writing a
        remediation script from scratch. The catalog's 'edges' field (exact
        BloodHound edge names, e.g. GenericAll, WriteDacl, DCSync) is folded
        into tags so a defensive agent handed a raw BloodHound edge name can
        look up the matching remediation directly. Returns the number of
        entries loaded.
        """
        entries = json.loads(Path(catalog_path).read_text())
        for entry in entries:
            steps = entry.get("remediation", [])
            lines = []
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {step.get('step', '')}")
                if step.get("command"):
                    lines.append(f"   PS> {step['command']}")
            content = "\n".join(lines)
            if entry.get("validation"):
                content += f"\n\nVerify: {entry['validation']}"

            tags = [entry.get("category", ""), entry.get("severity", ""), "ADRemedy"]
            tags.extend(entry.get("edges", []))  # exact BloodHound edge names

            self.scripts[entry["id"]] = ScriptEntry(
                name=entry["id"],
                description=entry.get("title", entry["id"]),
                content=content,
                tags=tags,
                known_good=True,
            )

            # Reverse index: exact edge name -> finding ID, ported from
            # ADRemedy's Get-ADRemedyEdgeMap so the two never drift apart.
            for edge_name in entry.get("edges", []):
                if edge_name:
                    self.edge_map[edge_name.lower()] = entry["id"]

        return len(entries)



# ---------------------------------------------------------------------------
# Tool functions -- register these with your ToolRegistry alongside the
# offensive tools, or with whatever tool-calling harness runs Fable 5.1
# for the defensive agent.
# ---------------------------------------------------------------------------

def lookup_script(tool_input: dict, kb: KnowledgeBase) -> dict:
    """Search the script library by tag or name fragment before writing a
    new remediation script from scratch."""
    query = tool_input.get("query", "").lower()

    if not kb.scripts:
        return {"found": False, "reason": "no script library loaded for this session"}

    matches = [
        {
            "name": s.name,
            "description": s.description,
            "tags": s.tags,
            "known_good": s.known_good,
            "last_used": s.last_used,
            "content": s.content,
        }
        for s in kb.scripts.values()
        if query in s.name.lower()
        or query in s.description.lower()
        or any(query in t.lower() for t in s.tags)
    ]

    return {
        "found": bool(matches),
        "query": query,
        "matches": matches,
        "match_count": len(matches),
    }


def check_host_history(tool_input: dict, kb: KnowledgeBase) -> dict:
    """Check whether a host has prior incident history before weighting a
    new finding or proposing a remediation that may have already failed."""
    hostname = tool_input.get("hostname", "").upper()

    incidents = kb.host_history.get(hostname) or kb.host_history.get(hostname.lower(), [])
    if not incidents:
        return {"hostname": hostname, "has_history": False}

    return {
        "hostname": hostname,
        "has_history": True,
        "incident_count": len(incidents),
        "incidents": [
            {
                "date": i.date,
                "description": i.description,
                "resolved": i.resolved,
                "resolution_note": i.resolution_note,
                "tags": i.tags,
            }
            for i in incidents
        ],
        "unresolved_count": sum(1 for i in incidents if not i.resolved),
    }


def query_attack_graph(tool_input: dict, kb: KnowledgeBase) -> dict:
    """Same BFS shortest-path logic as the offensive find_attack_path tool,
    run against whatever BloodHound edge data has been loaded/merged into
    this knowledge base -- lets the defensive agent see the same graph an
    attacker (or your own offensive prototype) would."""
    start = tool_input["start_node"].upper()
    target = tool_input["target_node"].upper()

    if not kb.edges:
        return {
            "found": False,
            "reason": "no attack-graph edge data loaded for this session "
                      "-- prioritization will be severity-only until edges "
                      "are provided",
        }

    adjacency: dict[str, list[tuple[str, str]]] = {}
    for edge in kb.edges:
        src = str(edge.get("source", "")).upper()
        dst = str(edge.get("target", "")).upper()
        if not src or not dst:
            continue
        adjacency.setdefault(src, []).append((dst, edge.get("edge_type", "?")))

    if start not in adjacency and start != target:
        return {
            "found": False,
            "reason": f"'{start}' has no outgoing edges in the loaded graph",
        }

    visited = {start}
    queue = deque([(start, [])])

    while queue:
        node, path = queue.popleft()
        if node == target:
            return {
                "found": True,
                "start": start,
                "target": target,
                "hops": len(path),
                "path": [{"from": a, "via": e, "to": b} for (a, e, b) in path],
            }
        for neighbor, edge_type in adjacency.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [(node, edge_type, neighbor)]))

    return {
        "found": False,
        "reason": f"no path found from '{start}' to '{target}' in the "
                  f"loaded graph ({len(kb.edges)} edges known)",
    }


def path_multiplicity(tool_input: dict, kb: KnowledgeBase) -> dict:
    """How many distinct paths from any node reach the target within a hop
    limit -- a cheap proxy for 'is this node a chokepoint' to support the
    prioritization method in the system prompt (path multiplicity)."""
    target = tool_input["target_node"].upper()
    node_of_interest = tool_input["node"].upper()
    max_hops = tool_input.get("max_hops", 6)
    max_paths = tool_input.get("max_paths", 20000)  # enumeration cap for large graphs

    if not kb.edges:
        return {"found": False, "reason": "no attack-graph edge data loaded"}

    # reverse adjacency: who points AT this node/edge, walked backward from target
    reverse_adj: dict[str, list[str]] = {}
    for edge in kb.edges:
        src = str(edge.get("source", "")).upper()
        dst = str(edge.get("target", "")).upper()
        if src and dst:
            reverse_adj.setdefault(dst, []).append(src)

    # Count distinct end-to-end attack paths (from any reachable starting
    # node, i.e. a "root" with no further predecessors) that pass through
    # node_of_interest on their way to target. This is the actual
    # chokepoint signal: how many separate attacker starting points would
    # all have to go through this one node/edge to reach the target.
    paths_through = 0
    paths_seen = 0
    truncated = False
    stack = [(target, [target], 0)]
    while stack:
        node, path, depth = stack.pop()
        if depth > max_hops:
            continue
        predecessors = [p for p in reverse_adj.get(node, []) if p not in path]
        if not predecessors:
            # dead end / root reached -- this is one complete path
            paths_seen += 1
            if node_of_interest in path:
                paths_through += 1
            if paths_seen >= max_paths:
                truncated = True
                break
            continue
        for prev in predecessors:
            stack.append((prev, path + [prev], depth + 1))

    return {
        "node": node_of_interest,
        "target": target,
        "paths_through_node": paths_through,
        "total_paths_enumerated": paths_seen,
        "truncated": truncated,
        "max_hops_considered": max_hops,
        "note": (
            "higher paths_through_node = more of a chokepoint = higher "
            "priority per the graph-based prioritization method, even at "
            "moderate severity"
        ),
    }


# ---------------------------------------------------------------------------
# Edge classification -- ported from ADRemedy's Private/EdgeHelpers.ps1 so the
# defensive agent applies the same "is this edge a real finding, and how bad
# is it given what it targets" logic the PowerShell module uses.
# ---------------------------------------------------------------------------

# Structural or benign edges that appear in every collection and are not
# findings on their own (containment, role membership, PKI plumbing, etc.).
IGNORED_EDGES = {
    "contains", "memberof", "hasrole", "trustedby", "container",
    "enroll", "enrollonbehalfof", "publishedto", "enterpriseca",
    "rootcafor", "ntauthstorefor", "trustedforntauth", "issuedsignedby",
    "extendedright", "localtocomputer", "memberoflocalgroup", "haslapspassword",
}

# SharpHound splits DCSync into its component replication rights. Either one
# alone is not the attack, but both together are, and reporting the pair is
# more useful than reporting neither.
_DCSYNC_COMPONENTS = {"getchanges", "getchangesall", "getchangesinfilteredset", "dcsync"}
_DCSYNC_FINDING_ID = "ADR-ACL-007"

# Principals that legitimately hold sweeping rights everywhere. Reporting
# them turns a useful finding into thousands of rows of expected config.
DEFAULT_PRINCIPAL_RIDS = ("-512", "-516", "-517", "-518", "-519", "-498", "-500", "-521")
DEFAULT_PRINCIPAL_SIDS = {
    "S-1-5-18", "S-1-5-9", "S-1-5-10", "S-1-3-0", "S-1-3-4", "S-1-5-32-544",
    "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-552",
}
_DEFAULT_PRINCIPAL_NAME_RE = re.compile(
    r"^(?:[^\\]+\\)?"  # optional NT AUTHORITY\, BUILTIN\, or DOMAIN\ prefix
    r"(SYSTEM|SELF|CREATOR OWNER|ENTERPRISE DOMAIN CONTROLLERS|Domain Admins|"
    r"Enterprise Admins|Schema Admins|Administrators|Domain Controllers|"
    r"Enterprise Read-only Domain Controllers|Key Admins|Enterprise Key Admins)",
    re.IGNORECASE,
)

_TIER0_TARGET_RE = re.compile(
    r"(?i)domain admins|enterprise admins|schema admins|administrators|"
    r"domain controllers|adminsdholder|krbtgt"
)


def is_default_principal(sid: str | None = None, name: str | None = None) -> bool:
    """True when a SID/name belongs to a built-in tier 0 principal whose
    broad rights are expected rather than a finding. Port of
    Test-ADRemedyDefaultPrincipal. Filters noise before it ever reaches
    the agent -- these principals are supposed to have these rights."""
    if not sid and not name:
        return False

    if sid:
        if sid in DEFAULT_PRINCIPAL_SIDS:
            return True
        if any(sid.endswith(rid) for rid in DEFAULT_PRINCIPAL_RIDS):
            return True

    if name and _DEFAULT_PRINCIPAL_NAME_RE.match(name):
        return True

    return False


def resolve_edge(tool_input: dict, kb: KnowledgeBase) -> dict:
    """Map a raw BloodHound/SharpHound edge name (e.g. from the offensive
    agent's find_attack_path output) to its ADRemedy catalog finding ID.
    Port of Resolve-ADRemedyEdge, including the DCSync special case where
    the component replication rights collapse onto one finding."""
    edge = tool_input["edge"]
    key = edge.lower()

    if key in IGNORED_EDGES:
        return {
            "edge": edge,
            "finding_id": None,
            "ignored": True,
            "reason": "structural/benign edge, not a finding on its own",
        }

    if key in kb.edge_map:
        return {"edge": edge, "finding_id": kb.edge_map[key], "ignored": False}

    if key in _DCSYNC_COMPONENTS:
        return {"edge": edge, "finding_id": _DCSYNC_FINDING_ID, "ignored": False}

    return {
        "edge": edge,
        "finding_id": None,
        "ignored": False,
        "reason": "no catalog entry maps to this edge name -- load_adremedy_catalog "
                  "first, or this edge type isn't in the catalog yet",
    }


def classify_principal(tool_input: dict, kb: KnowledgeBase) -> dict:
    """Check whether a principal (by SID and/or name) is a built-in tier 0
    account whose broad rights are expected -- so the agent doesn't flag
    SYSTEM having GenericAll on the domain object as a finding. Pass
    include_default_principals=true to skip the filter and see everything,
    matching ADRemedy's -IncludeDefaultPrincipals switch."""
    sid = tool_input.get("sid")
    name = tool_input.get("name")
    include_defaults = tool_input.get("include_default_principals", False)

    is_default = is_default_principal(sid=sid, name=name)
    return {
        "sid": sid,
        "name": name,
        "is_default_principal": is_default,
        "should_report": include_defaults or not is_default,
    }


def escalate_edge_severity(tool_input: dict, kb: KnowledgeBase) -> dict:
    """Raise severity to Critical when an edge's affected objects include a
    tier 0 target -- the same edge against a test group and against Domain
    Admins are not the same finding. Port of Get-ADRemedyEdgeSeverity.
    affected_objects: list of {"target": str, "target_type": str}."""
    base_severity = tool_input["base_severity"]
    affected_objects = tool_input.get("affected_objects", [])

    tier0_hits = [
        o for o in affected_objects
        if _TIER0_TARGET_RE.search(str(o.get("target", ""))) or o.get("target_type") == "Domain"
    ]

    escalated = bool(tier0_hits) and base_severity != "Critical"
    final_severity = "Critical" if (tier0_hits or base_severity == "Critical") else base_severity

    return {
        "base_severity": base_severity,
        "final_severity": final_severity,
        "escalated": escalated,
        "tier0_targets_hit": [o.get("target") for o in tier0_hits],
    }
