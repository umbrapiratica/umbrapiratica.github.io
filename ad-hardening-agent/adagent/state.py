"""Engagement state: scope, authorization, approvals, executions, verification.

This is the audit trail. Every approval checkpoint, every command the
executor ran (or would have run in dry-run), and every verification result
lands here and is written to disk at the end of the session.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class EngagementState:
    scope: list[str] = field(default_factory=list)          # OUs / hosts / domain in scope
    authorized_by: str = ""                                  # who granted authorization
    authorized: bool = False
    output_dir: Path = field(default_factory=lambda: Path("./adagent-output"))
    ask_operator: Callable[[str], str] = input               # injectable for tests
    approvals: list[dict] = field(default_factory=list)
    executions: list[dict] = field(default_factory=list)
    verifications: list[dict] = field(default_factory=list)
    reports: list[str] = field(default_factory=list)
    stopped: bool = False
    started_at: str = field(default_factory=_now)

    def record_approval(self, **kwargs) -> dict:
        entry = {"at": _now(), **kwargs}
        self.approvals.append(entry)
        return entry

    def record_execution(self, **kwargs) -> dict:
        entry = {"at": _now(), **kwargs}
        self.executions.append(entry)
        return entry

    def record_verification(self, **kwargs) -> dict:
        entry = {"at": _now(), **kwargs}
        self.verifications.append(entry)
        return entry

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("ask_operator", None)
        d["output_dir"] = str(self.output_dir)
        return d

    def save(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / "session-log.json"
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path
