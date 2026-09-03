# AD Hardening Agent

A human-in-the-loop **defensive** security agent for Active Directory endpoint and host
hardening, built on the Claude API. It thinks like the attacker to find the gap, then acts
like a careful sysadmin to close it, and it never changes anything without an explicit
operator approval.

The agent runs the operating procedure in
[`prompts/ad_endpoint_hardening_system_prompt.md`](prompts/ad_endpoint_hardening_system_prompt.md):
discovery, graph-based risk assessment, a mitigation plan, an approval checkpoint per
change, remediation, verification, and a summary report that says which fixes shortened the
attacker's path to Domain Admins.

## What is in the box

| Piece | Purpose |
|---|---|
| `adagent/agent.py` | Streaming tool-use loop over the Messages API. Append-only history, refusal handling, server-side fallbacks. |
| `adagent/tools.py` | The tools the model can call and the gating around them. The approval checkpoint is enforced here in code, not just in the prompt. |
| `adagent/knowledge_base.py` | Reference-data layer: script library, host incident history, BloodHound-style attack graph (BFS shortest path, path multiplicity), edge classification ported from ADRemedy. |
| `adagent/findings.py` | Finding model. Loads ADRemedy audit exports, and imports raw SharpHound JSON into findings plus graph edges (a port of `ConvertFrom-ADRemedySharpHound`). |
| `adagent/prioritize.py` | The four-tier ranking from the procedure: severity combined with hops-to-Tier-0 and path multiplicity, with a one-line reason per finding. |
| `adagent/executor.py` | Dry-run executor (default) and a PowerShell executor (only with `--execute`). Read-only verb guard for validation queries. |
| `data/RemediationCatalog.json` | The ADRemedy catalog: 39 entries covering 42 BloodHound edges, each with attack chain, MITRE mapping, fix commands, validation query and break risk. |
| `ADRemedy/` | The read-only PowerShell audit module that produces findings from a live domain, PingCastle, SharpHound or CSV. |
| `data/samples/` | A mock domain (CORP.LOCAL) so the whole thing can be exercised with no domain and no API key. |

## Quick start

```bash
cd ad-hardening-agent
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                                            # offline tests, no API key needed

# Offline: graph-based prioritization of the sample domain
adagent triage --demo

# Interactive session against the sample domain (needs an Anthropic credential)
export ANTHROPIC_API_KEY=sk-ant-...               # or `ant auth login`
adagent chat --demo --scope "DC=corp,DC=local" --authorized-by "Jane Doe, IT Director"
```

Inside the session type what you would say to an analyst (`walk me through the top three`,
`propose the fix for ADR-ACL-003`, `yes`, `skip`, `stop`), `report` to get the summary
report, `exit` to end. Every approval, command and verification is written to
`adagent-output/session-log.json`.

## Feeding it real data

**1. Audit the domain with ADRemedy** (Windows, any domain user, LDAP reads only):

```powershell
Import-Module .\ADRemedy\ADRemedy.psd1
Invoke-ADRemedyAudit | ConvertTo-Json -Depth 8 | Set-Content findings.json
```

**2. Add the attack graph** from a SharpHound collection (unzip it first, or point at the
directory of JSON files). This gives the agent hops-to-Domain-Admins and path multiplicity;
without it, prioritization is severity-only and the agent says so.

**3. Optional reference data**, both plain JSON (see `data/samples/` for the shape):

- `--scripts scripts.json`: your vetted script library. The agent checks it before writing
  anything new and flags first-run scripts as unvetted at the checkpoint.
- `--host-history history.json`: prior incidents per host. Findings on repeat offenders are
  weighted up, and fixes that history shows did not hold are flagged instead of re-proposed.

```bash
adagent chat --findings findings.json --sharphound ./sharphound-out \
             --scripts scripts.json --host-history history.json \
             --scope "OU=Servers,DC=corp,DC=local,OU=Workstations,DC=corp,DC=local" \
             --authorized-by "change ticket CHG-4821"
```

## How remediation is controlled

1. **Dry-run by default.** Approved commands are printed and logged, never executed. Pass
   `--execute` (and confirm the prompt) to run approved commands through `pwsh`/`powershell`
   on the host you launched from.
2. **The checkpoint is a tool the model must call.** `request_remediation_approval` prints
   the ready-to-fix / risk-if-not / risk-if-breaks / rollback block and waits for `yes`,
   `skip` or `stop`. Nothing in the loop can execute a command by any other route.
3. **Tier 0 changes** (DCs, Domain Admins, Enterprise Admins, krbtgt, AdminSDHolder, the
   domain object) must be flagged `tier0` and are approved only by typing `yes tier0`.
4. **`stop` is final for the session.** Further approval requests are refused without asking.
5. **No authorization, no remediation.** Without `--authorized-by`, the agent can assess but
   every checkpoint is refused.
6. **Validation queries are read-only.** A verb denylist rejects `Set-`, `Remove-`, `Reset-`,
   `netdom`, `dsacls /G` and friends. It is a guard, not a sandbox: review anything that runs live.

## Model settings

The procedure was written for Claude Fable 5.1, so that is the default model. Fable's safety
classifiers can decline cybersecurity-adjacent requests, so every request opts into
server-side refusal fallbacks (`fallbacks="default"` with the `server-side-fallback-2026-07-01`
beta), which reruns a declined turn on an Opus-tier model. Use `--no-fallbacks` to turn that
off, or `--model claude-opus-5` to skip Fable entirely. Thinking is adaptive; effort defaults
to `high` (`--effort xhigh` for a long autonomous assessment, `low` for quick questions).

## Adding a check or a script

- New finding class: add an entry to `data/RemediationCatalog.json` (and the matching check
  in `ADRemedy/Private/Checks/` if you want the live audit to detect it). The agent picks it
  up through `get_guidance` with no code change.
- New vetted script: add it to your `scripts.json` with tags. Mark `known_good: false` until
  it has run successfully once; the agent surfaces that flag at the checkpoint.

## Safety

This tool is for environments you own or are explicitly authorized to secure. It contains no
exploitation capability: discovery reads data you already collected, the attack graph is used
only to decide what to fix first, and the only way anything changes is an operator typing
`yes` at a checkpoint whose commands they can read.
