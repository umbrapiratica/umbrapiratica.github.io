"""Command executors.

Two modes:
  DryRunExecutor    - default. Never runs anything; records what *would* run.
  PowerShellExecutor - runs commands through pwsh/powershell on the operator's
                       machine. Only selected with an explicit --execute flag.

Both go through the same interface so the tool layer does not care which one
is active, and both log to the engagement state.

The read-only guard is a verb denylist, not a sandbox. It catches the obvious
state-changing cmdlets so a "validation" query cannot quietly mutate the
directory, but the operator remains responsible for reviewing anything that
runs live.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

STATE_CHANGING = re.compile(
    r"\b(Set|Remove|Add|New|Reset|Disable|Enable|Move|Install|Uninstall|Update|Clear|"
    r"Invoke|Start|Stop|Restart|Rename|Grant|Revoke|Unlock|Import|Export|Write|Out|Copy|Register|Unregister)-\w+"
    r"|\bnetdom\b|\bdsacls\b.*\s/(G|D|R|I|P|S)\b|\bcertutil\b.*-(set|dCA|delTemplate)|\bReset-\w+|\bntdsutil\b|\breg\s+(add|delete)\b",
    re.IGNORECASE,
)


def is_read_only(command: str) -> tuple[bool, str | None]:
    """Return (ok, offending_match). A best-effort guard, not a sandbox."""
    m = STATE_CHANGING.search(command)
    if m:
        return False, m.group(0)
    return True, None


@dataclass
class ExecResult:
    executed: bool
    dry_run: bool
    command: str
    stdout: str = ""
    stderr: str = ""
    return_code: int | None = None
    note: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class DryRunExecutor:
    name = "dry-run"

    def run(self, command: str, timeout: int = 120) -> ExecResult:
        return ExecResult(
            executed=False, dry_run=True, command=command,
            note="dry-run mode: command recorded, not executed. Start the CLI with --execute to run live.",
        )


class PowerShellExecutor:
    name = "powershell"

    def __init__(self, binary: str | None = None):
        self.binary = binary or shutil.which("pwsh") or shutil.which("powershell")
        if not self.binary:
            raise RuntimeError("No pwsh/powershell binary found on PATH; cannot use --execute.")

    def run(self, command: str, timeout: int = 120) -> ExecResult:
        try:
            proc = subprocess.run(
                [self.binary, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return ExecResult(executed=True, dry_run=False, command=command,
                              note=f"timed out after {timeout}s", return_code=None)
        return ExecResult(
            executed=True, dry_run=False, command=command,
            stdout=proc.stdout[-20000:], stderr=proc.stderr[-5000:], return_code=proc.returncode,
        )
