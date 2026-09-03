"""Graph-based prioritization.

Implements the ranking rule from the system prompt: severity and graph
criticality (hops-to-Domain-Admins and path multiplicity) are combined into
four ordered tiers rather than averaged into one number. Each ranked finding
carries a one-line reason so the operator can sanity-check it.

When no edge data is loaded the ranking is severity-only and says so.
"""

from __future__ import annotations

from collections import deque

from .findings import Finding, TIER0_TARGET
from .knowledge_base import KnowledgeBase, path_multiplicity

DEFAULT_TARGET_PATTERNS = ("DOMAIN ADMINS@", "DOMAIN ADMINS")
CHOKEPOINT_THRESHOLD = 3


def find_da_node(kb: KnowledgeBase, explicit: str | None = None) -> str | None:
    if explicit:
        return explicit.upper()
    nodes = {str(e.get("source", "")).upper() for e in kb.edges} | {str(e.get("target", "")).upper() for e in kb.edges}
    for n in sorted(nodes):
        if n.startswith("DOMAIN ADMINS@") or n == "DOMAIN ADMINS":
            return n
    return None


def _adjacency(kb: KnowledgeBase) -> dict[str, list[str]]:
    adj: dict[str, list[str]] = {}
    for e in kb.edges:
        s, t = str(e.get("source", "")).upper(), str(e.get("target", "")).upper()
        if s and t:
            adj.setdefault(s, []).append(t)
    return adj


def hops_to(adj: dict[str, list[str]], start: str, target: str) -> int | None:
    if start == target:
        return 0
    seen = {start}
    q = deque([(start, 0)])
    while q:
        node, d = q.popleft()
        for nxt in adj.get(node, []):
            if nxt == target:
                return d + 1
            if nxt not in seen:
                seen.add(nxt)
                q.append((nxt, d + 1))
    return None


def _is_tier0(node: str, f: Finding) -> bool:
    if TIER0_TARGET.search(node):
        return True
    return node.upper() in {str(t).upper() for t in (f.detail or {}).get("Tier0Targets", [])}


def _candidate_nodes(f: Finding) -> list[tuple[str, str | None]]:
    """(node, target-of-edge) pairs to evaluate for a finding."""
    out = []
    for o in f.affected_objects:
        if "Principal" in o:
            out.append((str(o["Principal"]).upper(), str(o.get("Target", "")).upper() or None))
        elif "Name" in o:
            out.append((str(o["Name"]).upper(), None))
    return out


def rank_findings(findings: list[Finding], kb: KnowledgeBase, da_node: str | None = None,
                  max_hops: int = 6) -> dict:
    da = find_da_node(kb, da_node)
    graph_available = bool(kb.edges) and da is not None
    adj = _adjacency(kb) if graph_available else {}
    ranked = []

    for f in findings:
        best_hops: int | None = None
        best_mult = 0
        best_node = None
        best_target = None
        if graph_available:
            for node, edge_target in _candidate_nodes(f)[:50]:
                if edge_target:
                    # an edge finding: the path goes principal -> target -> ... -> DA
                    tail = hops_to(adj, edge_target, da)
                    if tail is None and _is_tier0(edge_target, f):
                        tail = 0  # the target is itself Tier 0: domain object, DC, krbtgt, AdminSDHolder...
                    h = None if tail is None else tail + 1
                    mult_node = edge_target
                else:
                    h = hops_to(adj, node, da)
                    mult_node = node
                if h is not None and (best_hops is None or h < best_hops):
                    best_hops, best_node, best_target = h, node, (edge_target or da)
                m = path_multiplicity({"node": mult_node, "target_node": da, "max_hops": max_hops}, kb)
                best_mult = max(best_mult, m.get("paths_through_node", 0))

        high = f.severity in ("Critical", "High")
        near = best_hops is not None and best_hops <= 2
        choke = best_mult >= CHOKEPOINT_THRESHOLD
        on_path = best_hops is not None

        if not graph_available:
            tier, reason = f.severity_rank + 1, "severity-only: no attack-graph edge data loaded"
        elif high and (near or choke):
            tier = 1
            reason = (f"{f.severity} and {best_hops} hop(s) from Tier 0 ({best_node} -> {best_target})" if near
                      else f"{f.severity} and a chokepoint: {best_mult} paths to Domain Admins route through it")
        elif high:
            tier = 2
            reason = (f"{f.severity} but graph-isolated: no path to Domain Admins through it in the loaded edges"
                      if not on_path else f"{f.severity}; {best_hops} hops from Domain Admins, not a chokepoint")
        elif choke or near:
            tier = 3
            reason = (f"ranked above its {f.severity} severity because {best_mult} paths to Domain Admins route "
                      f"through it" if choke else f"ranked above its {f.severity} severity: {best_hops} hop(s) from Tier 0")
        else:
            tier = 4
            reason = f"{f.severity} and graph-isolated; batch or defer"

        ranked.append({
            "finding_id": f.finding_id, "title": f.title, "severity": f.severity, "source": f.source,
            "affected_count": f.affected_count, "tier": tier, "hops_to_da": best_hops,
            "path_multiplicity": best_mult, "closest_node": best_node, "reason": reason,
        })

    ranked.sort(key=lambda r: (r["tier"], r["hops_to_da"] if r["hops_to_da"] is not None else 99,
                               -r["path_multiplicity"], r["severity"] != "Critical", r["finding_id"]))
    for i, r in enumerate(ranked, 1):
        r["rank"] = i
    return {
        "graph_available": graph_available,
        "domain_admins_node": da,
        "edges_loaded": len(kb.edges),
        "note": ("ranking uses severity + graph criticality (hops-to-DA, path multiplicity)" if graph_available
                 else "severity-only ranking; load SharpHound edges for graph-informed prioritization"),
        "ranked": ranked,
    }
