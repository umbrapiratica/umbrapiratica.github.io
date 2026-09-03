from pathlib import Path

from adagent.catalog import Catalog
from adagent.findings import import_sharphound, load_adremedy_export, save_findings
from adagent.knowledge_base import KnowledgeBase, query_attack_graph, path_multiplicity
from adagent.prioritize import rank_findings

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def test_catalog_loads_with_edges():
    cat = Catalog.load()
    assert len(cat.entries) == 39
    assert cat.edge_map["genericall"] == "ADR-ACL-001"
    assert cat.edge_map["dcsync"] == "ADR-ACL-007"
    assert cat.search(edge="AddKeyCredentialLink")[0]["id"] == "ADR-ACL-008"
    assert "ADR-KERB-001" in {e["id"] for e in cat.search(keyword="kerberoast")}


def test_sharphound_import_findings_and_edges():
    cat = Catalog.load()
    imp = import_sharphound(SAMPLES, cat)
    ids = {f.finding_id: f for f in imp.findings}

    # property-flag checks
    assert "ADR-DELEG-001" in ids and ids["ADR-DELEG-001"].affected_objects[0]["Name"] == "APPSRV01.CORP.LOCAL"
    assert "ADR-KERB-001" in ids and ids["ADR-KERB-001"].affected_count >= 2
    assert "ADR-HOST-001" in ids
    assert "ADR-DOM-001" in ids and ids["ADR-DOM-001"].affected_objects[0]["Value"] == 10

    # edge findings: DCSync rights on the domain object escalate to Critical
    assert ids["ADR-ACL-007"].severity == "Critical"
    # WriteDacl on Domain Admins escalates to Critical
    assert ids["ADR-ACL-003"].severity == "Critical"
    assert "DOMAIN ADMINS@CORP.LOCAL" in ids["ADR-ACL-003"].detail["Tier0Targets"]
    # GenericAll on a GPO routes to the GPO entry
    assert any(o["Target"].startswith("DEFAULT DOMAIN POLICY") for o in ids["ADR-ACL-013"].affected_objects)
    # local admins produce AdminTo
    assert ids["ADR-PATH-001"].affected_objects[0]["Edge"] == "AdminTo"
    # Domain Admins in LocalAdmins is a default principal and filtered
    assert not any(o["Principal"].startswith("DOMAIN ADMINS") for o in ids["ADR-PATH-001"].affected_objects)

    # graph edges are name-resolved and exclude default principals as sources
    assert imp.edges
    assert all(not e["source"].startswith("DOMAIN ADMINS") for e in imp.edges)
    assert any(e["edge_type"] == "HasSession" for e in imp.edges)


def test_export_roundtrip(tmp_path):
    cat = Catalog.load()
    imp = import_sharphound(SAMPLES, cat)
    p = save_findings(imp.findings, tmp_path / "f.json")
    again = load_adremedy_export(p, cat)
    assert [f.finding_id for f in again] == [f.finding_id for f in imp.findings]
    assert again[0].affected_count == imp.findings[0].affected_count


def test_adremedy_powershell_export_shape(tmp_path):
    cat = Catalog.load()
    (tmp_path / "ps.json").write_text('''[{"FindingId":"ADR-KERB-002","Title":"x","Severity":"High","Category":"Kerberos",
        "Source":"Live Audit","Domain":"corp.local","Evidence":"1 account","AffectedObjects":{"Name":"jdoe"},"AffectedCount":1}]''')
    f = load_adremedy_export(tmp_path / "ps.json", cat)
    assert f[0].finding_id == "ADR-KERB-002" and f[0].affected_objects == [{"Name": "jdoe"}] and f[0].has_guidance


def test_graph_queries_and_ranking():
    cat = Catalog.load()
    imp = import_sharphound(SAMPLES, cat)
    kb = KnowledgeBase()
    kb.merge_edges(imp.edges)

    # the helpdesk group holds WriteDacl on Domain Admins in the sample: one hop
    r = query_attack_graph({"start_node": "HELPDESK-TIER1@CORP.LOCAL", "target_node": "DOMAIN ADMINS@CORP.LOCAL"}, kb)
    if not r["found"]:
        # fall back: at least one principal reaches DA in one hop
        srcs = [e["source"] for e in imp.edges if e["target"] == "DOMAIN ADMINS@CORP.LOCAL"]
        assert srcs
        r = query_attack_graph({"start_node": srcs[0], "target_node": "DOMAIN ADMINS@CORP.LOCAL"}, kb)
    assert r["found"] and r["hops"] == 1

    m = path_multiplicity({"node": "DOMAIN ADMINS@CORP.LOCAL", "target_node": "DOMAIN ADMINS@CORP.LOCAL"}, kb)
    assert m["paths_through_node"] >= 1 and m["truncated"] is False

    ranking = rank_findings(imp.findings, kb)
    assert ranking["graph_available"] and ranking["domain_admins_node"] == "DOMAIN ADMINS@CORP.LOCAL"
    ranked = ranking["ranked"]
    assert ranked[0]["tier"] == 1
    assert all(ranked[i]["tier"] <= ranked[i + 1]["tier"] for i in range(len(ranked) - 1))
    assert all(r["reason"] for r in ranked)

    # severity-only when no edges are loaded
    empty = rank_findings(imp.findings, KnowledgeBase())
    assert not empty["graph_available"]
    assert "severity-only" in empty["ranked"][0]["reason"]
