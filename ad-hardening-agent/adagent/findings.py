"""Finding model and loaders.

Two sources of findings:

  1. ADRemedy audit export. On a domain-joined Windows host:
         Invoke-ADRemedyAudit | ConvertTo-Json -Depth 8 > findings.json
     (or Import-ADRemedyFindings for PingCastle / Purple Knight output).

  2. SharpHound collection JSON (a directory or individual files). This is a
     Python port of ADRemedy's ConvertFrom-ADRemedySharpHound: it reads the
     property flags, ACEs, local group membership, sessions and SID history
     SharpHound already collected and turns them into the same finding shape,
     plus BloodHound-style edges for the attack graph.

Findings never carry the full catalog writeup; the agent asks for it through
the get_guidance tool when it needs it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .catalog import Catalog, SEVERITY_RANK
from .knowledge_base import IGNORED_EDGES, is_default_principal

EOL_OS = re.compile(r"2003|2008|Windows 7|Windows XP|Windows 8|Windows Vista|2000", re.IGNORECASE)
TIER0_TARGET = re.compile(
    r"domain admins|enterprise admins|schema admins|administrators|domain controllers|adminsdholder|krbtgt",
    re.IGNORECASE,
)


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: str
    category: str
    source: str
    domain: str = ""
    evidence: str = ""
    affected_objects: list[dict] = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    has_guidance: bool = True

    @property
    def affected_count(self) -> int:
        return len(self.affected_objects)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 9)

    def summary(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "source": self.source,
            "domain": self.domain,
            "affected_count": self.affected_count,
            "evidence": self.evidence,
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d["affected_count"] = self.affected_count
        return d


# ---------------------------------------------------------------------------
# ADRemedy export loader
# ---------------------------------------------------------------------------

def _first(d: dict, *keys, default=None):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def load_adremedy_export(path: str | Path, catalog: Catalog) -> list[Finding]:
    """Load findings exported from ADRemedy (ConvertTo-Json) or from this
    tool's own `import` command."""
    raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(raw, dict):
        raw = raw.get("findings", [raw])
    findings = []
    for item in raw:
        fid = _first(item, "FindingId", "finding_id", default="UNKNOWN")
        entry = catalog.get(fid) or {}
        objs = _first(item, "AffectedObjects", "affected_objects", default=[]) or []
        if isinstance(objs, dict):
            objs = [objs]
        findings.append(Finding(
            finding_id=fid,
            title=_first(item, "Title", "title", default=entry.get("title", fid)),
            severity=_first(item, "Severity", "severity", default=entry.get("severity", "Medium")),
            category=_first(item, "Category", "category", default=entry.get("category", "Uncategorised")),
            source=_first(item, "Source", "source", default="Import"),
            domain=_first(item, "Domain", "domain", default="") or "",
            evidence=_first(item, "Evidence", "evidence", default="") or "",
            affected_objects=[o if isinstance(o, dict) else {"Name": str(o)} for o in objs],
            detail=_first(item, "Detail", "detail", default={}) or {},
            has_guidance=bool(entry),
        ))
    findings.sort(key=lambda f: (f.severity_rank, f.finding_id))
    return findings


# ---------------------------------------------------------------------------
# SharpHound import
# ---------------------------------------------------------------------------

_WELL_KNOWN = {
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
    "S-1-1-0": "Everyone",
}

_LOCAL_GROUPS = {
    "LocalAdmins": ("ADR-PATH-001", "AdminTo"),
    "RemoteDesktopUsers": ("ADR-PATH-003", "CanRDP"),
    "PSRemoteUsers": ("ADR-PATH-003", "CanPSRemote"),
    "DcomUsers": ("ADR-PATH-003", "ExecuteDCOM"),
}

_TYPE_OF = {
    "users": "User", "computers": "Computer", "groups": "Group", "domains": "Domain",
    "gpos": "GPO", "ous": "OU", "containers": "Container",
}

_DCSYNC_PARTS = {"getchanges", "getchangesall", "getchangesinfilteredset", "dcsync"}


def read_sharphound(path: str | Path) -> list[dict]:
    """Flatten one or more SharpHound JSON files into rows of
    {collection_type, object}. Accepts a file or a directory."""
    path = Path(path)
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    rows = []
    for f in files:
        try:
            doc = json.loads(f.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(doc, dict) or "data" not in doc:
            continue
        ctype = (doc.get("meta") or {}).get("type") or f.stem.split("_")[-1]
        for obj in doc["data"]:
            rows.append({"collection_type": str(ctype).lower(), "object": obj})
    return rows


def _props(row: dict) -> dict:
    return row["object"].get("Properties") or {}


def _sid(row: dict) -> str:
    return str(row["object"].get("ObjectIdentifier") or "")


class SharpHoundImport:
    """Result of a SharpHound import: findings plus graph edges."""

    def __init__(self, findings: list[Finding], edges: list[dict], names: dict[str, str]):
        self.findings = findings
        self.edges = edges
        self.names = names


def import_sharphound(path: str | Path, catalog: Catalog, include_default_principals: bool = False) -> SharpHoundImport:
    rows = read_sharphound(path)
    domain = next((_props(r).get("domain") for r in rows if _props(r).get("domain")), "") or ""

    index: dict[str, str] = {}
    for r in rows:
        sid = _sid(r)
        name = _props(r).get("name") or _props(r).get("distinguishedname")
        if sid and name:
            index[sid] = str(name).upper()

    def resolve(sid: str) -> str:
        return index.get(sid) or _WELL_KNOWN.get(sid) or sid

    findings: list[Finding] = []

    def add(fid: str, evidence: str, objects: list[dict], severity: str | None = None, detail: dict | None = None):
        entry = catalog.get(fid) or {}
        findings.append(Finding(
            finding_id=fid,
            title=entry.get("title", fid),
            severity=severity or entry.get("severity", "High"),
            category=entry.get("category", "Uncategorised"),
            source="SharpHound",
            domain=domain,
            evidence=evidence,
            affected_objects=objects,
            detail=detail or {},
            has_guidance=bool(entry),
        ))

    # --- property-flag findings (same checks as ADRemedy) -------------------
    uncon = [r for r in rows if _props(r).get("unconstraineddelegation") is True and r["collection_type"] != "domains"]
    if uncon:
        add("ADR-DELEG-001", f"{len(uncon)} object(s) trusted for unconstrained delegation.",
            [{"Name": resolve(_sid(r)), "OperatingSystem": _props(r).get("operatingsystem", ""),
              "Enabled": bool(_props(r).get("enabled"))} for r in uncon])

    asrep = [r for r in rows if _props(r).get("dontreqpreauth") is True]
    if asrep:
        add("ADR-KERB-002", f"{len(asrep)} account(s) do not require Kerberos pre-authentication.",
            [{"Name": resolve(_sid(r)), "Enabled": bool(_props(r).get("enabled")),
              "Privileged": bool(_props(r).get("admincount"))} for r in asrep])

    roast = [r for r in rows if _props(r).get("hasspn") is True and _props(r).get("admincount") is True]
    if roast:
        add("ADR-KERB-001", f"{len(roast)} privileged account(s) carry a service principal name.",
            [{"Name": resolve(_sid(r)),
              "ServicePrincipalNames": "; ".join(_props(r).get("serviceprincipalnames") or []),
              "PasswordLastSet": _props(r).get("pwdlastset")} for r in roast])

    never = [r for r in rows if _props(r).get("pwdneverexpires") is True and _props(r).get("enabled") is True]
    if never:
        add("ADR-ACCT-001", f"{len(never)} enabled account(s) have a password that never expires.",
            [{"Name": resolve(_sid(r)), "Privileged": bool(_props(r).get("admincount")),
              "HasSPN": bool(_props(r).get("hasspn"))} for r in never])

    notreq = [r for r in rows if _props(r).get("passwordnotreqd") is True]
    if notreq:
        add("ADR-ACCT-004", f"{len(notreq)} account(s) have the password-not-required flag.",
            [{"Name": resolve(_sid(r)), "Enabled": bool(_props(r).get("enabled"))} for r in notreq])

    eol = [r for r in rows if r["collection_type"] == "computers"
           and EOL_OS.search(str(_props(r).get("operatingsystem") or ""))]
    if eol:
        add("ADR-HOST-001", f"{len(eol)} computer(s) run an unsupported operating system.",
            [{"Name": resolve(_sid(r)), "OperatingSystem": _props(r).get("operatingsystem"),
              "Enabled": bool(_props(r).get("enabled"))} for r in eol])

    nolaps = [r for r in rows if r["collection_type"] == "computers" and _props(r).get("enabled") is True
              and _props(r).get("haslaps") is False]
    if nolaps:
        add("ADR-HOST-002", f"{len(nolaps)} enabled computer(s) have no LAPS-managed local administrator password.",
            [{"Name": resolve(_sid(r)), "OperatingSystem": _props(r).get("operatingsystem")} for r in nolaps])

    for d in (r for r in rows if r["collection_type"] == "domains"):
        quota = _props(d).get("machineaccountquota")
        if isinstance(quota, (int, float)) and quota > 0:
            add("ADR-DOM-001", f"ms-DS-MachineAccountQuota is {int(quota)}; any user can join {int(quota)} computers.",
                [{"Name": resolve(_sid(d)), "Setting": "MachineAccountQuota", "Value": int(quota), "Recommended": 0}])

    # --- edges: ACEs, local groups, sessions, SID history --------------------
    edge_rows: list[dict] = []    # rows that become findings
    graph_edges: list[dict] = []  # everything, for the attack graph

    def graph(src: str, dst: str, edge: str):
        if src and dst and src != dst:
            graph_edges.append({"source": src, "target": dst, "edge_type": edge})

    for r in rows:
        target = resolve(_sid(r))
        ttype = _TYPE_OF.get(r["collection_type"], "Object")

        for member in (r["object"].get("Members") or []):
            msid = str(member.get("ObjectIdentifier") or "")
            if msid:
                graph(resolve(msid), target, "MemberOf")

        for ace in (r["object"].get("Aces") or []):
            right = str(ace.get("RightName") or "")
            if not right:
                continue
            psid = str(ace.get("PrincipalSID") or "")
            pname = resolve(psid)
            default = is_default_principal(sid=psid, name=pname)
            if not default:
                graph(pname, target, right)
            if right.lower() in IGNORED_EDGES:
                continue
            if default and not include_default_principals:
                continue
            fid = catalog.edge_map.get(right.lower())
            if not fid and right.lower() in _DCSYNC_PARTS:
                fid = "ADR-ACL-007"
            if not fid:
                continue
            if ttype == "GPO" and right in {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns"}:
                fid = "ADR-ACL-013"
            edge_rows.append({"FindingId": fid, "Edge": right, "Principal": pname, "Target": target,
                              "TargetType": ttype, "Inherited": bool(ace.get("IsInherited"))})

    for r in (x for x in rows if x["collection_type"] == "computers"):
        computer = resolve(_sid(r))
        for prop, (fid, edge) in _LOCAL_GROUPS.items():
            coll = r["object"].get(prop) or {}
            for member in (coll.get("Results") or []):
                msid = str(member.get("ObjectIdentifier") or "")
                name = resolve(msid)
                default = is_default_principal(sid=msid, name=name)
                if not default:
                    graph(name, computer, edge)
                if default and not include_default_principals:
                    continue
                edge_rows.append({"FindingId": fid, "Edge": edge, "Principal": name, "Target": computer,
                                  "TargetType": "Computer", "Inherited": False})
        sessions = r["object"].get("Sessions") or {}
        for s in (sessions.get("Results") or []):
            user = resolve(str(s.get("UserSID") or ""))
            graph(computer, user, "HasSession")
            edge_rows.append({"FindingId": "ADR-PATH-002", "Edge": "HasSession", "Principal": user,
                              "Target": computer, "TargetType": "Computer", "Inherited": False})
        for tgt in (r["object"].get("AllowedToDelegate") or []):
            tsid = str(tgt.get("ObjectIdentifier") or "") if isinstance(tgt, dict) else str(tgt)
            graph(computer, resolve(tsid), "AllowedToDelegate")
        for p in (r["object"].get("AllowedToAct") or []):
            psid = str(p.get("ObjectIdentifier") or "") if isinstance(p, dict) else str(p)
            graph(resolve(psid), computer, "AllowedToAct")

    for r in rows:
        for sid in (_props(r).get("sidhistory") or []):
            src, dst = resolve(_sid(r)), resolve(str(sid))
            graph(src, dst, "HasSIDHistory")
            edge_rows.append({"FindingId": "ADR-PATH-005", "Edge": "HasSIDHistory", "Principal": src,
                              "Target": dst, "TargetType": "Historical SID", "Inherited": False})

    grouped: dict[str, list[dict]] = {}
    for row in edge_rows:
        grouped.setdefault(row["FindingId"], []).append(row)
    for fid, objs in grouped.items():
        unique = {(o["Edge"], o["Principal"], o["Target"]): o for o in objs}
        objs = sorted(unique.values(), key=lambda o: (o["Edge"], o["Principal"], o["Target"]))
        base = (catalog.get(fid) or {}).get("severity", "High")
        tier0 = [o for o in objs if TIER0_TARGET.search(o["Target"]) or o["TargetType"] == "Domain"]
        severity = "Critical" if tier0 else base
        edges = ", ".join(sorted({o["Edge"] for o in objs}))
        principals = len({o["Principal"] for o in objs})
        add(fid, f"{len(objs)} {edges} edge(s) held by {principals} distinct principal(s).", objs,
            severity=severity, detail={"Edges": edges, "PrincipalCount": principals,
                                       "Tier0Targets": sorted({o["Target"] for o in tier0})})

    findings.sort(key=lambda f: (f.severity_rank, f.finding_id))
    return SharpHoundImport(findings, graph_edges, index)


def save_findings(findings: list[Finding], path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps({"findings": [f.to_dict() for f in findings]}, indent=2), encoding="utf-8")
    return path
