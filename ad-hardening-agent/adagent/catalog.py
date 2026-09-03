"""ADRemedy remediation catalog access.

The catalog (data/RemediationCatalog.json) is the vetted library of
findings: what each weakness is, how it is abused, the exact commands to
fix it, a validation query, and what could break. The agent reads it via
tools instead of receiving the whole file in its context.
"""

from __future__ import annotations

import json
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CATALOG_PATH = PACKAGE_ROOT / "data" / "RemediationCatalog.json"

SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


class Catalog:
    def __init__(self, entries: list[dict]):
        self.entries: dict[str, dict] = {e["id"]: e for e in entries}
        self.edge_map: dict[str, str] = {}
        for entry in entries:
            for edge in entry.get("edges", []) or []:
                self.edge_map[edge.lower()] = entry["id"]

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Catalog":
        path = Path(path) if path else DEFAULT_CATALOG_PATH
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def get(self, finding_id: str) -> dict | None:
        return self.entries.get(finding_id)

    def search(
        self,
        keyword: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        edge: str | None = None,
    ) -> list[dict]:
        results = list(self.entries.values())
        if edge:
            fid = self.edge_map.get(edge.lower())
            results = [self.entries[fid]] if fid else []
        if keyword:
            k = keyword.lower()
            results = [
                e for e in results
                if k in e.get("title", "").lower()
                or k in e.get("summary", "").lower()
                or k in e.get("howItWorks", "").lower()
                or k in e["id"].lower()
            ]
        if category:
            results = [e for e in results if e.get("category", "").lower() == category.lower()]
        if severity:
            results = [e for e in results if e.get("severity", "").lower() == severity.lower()]
        return sorted(results, key=lambda e: (SEVERITY_RANK.get(e.get("severity"), 9), e["id"]))

    def summary(self, entry: dict) -> dict:
        return {
            "id": entry["id"],
            "title": entry.get("title"),
            "category": entry.get("category"),
            "severity": entry.get("severity"),
            "edges": entry.get("edges", []),
            "summary": entry.get("summary"),
        }
