# ADRemedy

A read-only Active Directory review tool that explains how to fix what it finds.

It does two things. It runs its own LDAP checks against a domain, and it ingests
output from PingCastle, SharpHound, and CSV exports like Purple Knight. Either way
you get the same finding objects, each carrying a remediation writeup: how the
weakness is actually abused, the commands to fix it, a query to prove the fix
landed, and what might break when you apply it.

It also maps BloodHound edges to their remediation. BloodHound shows you the path;
this tells you which permission to change to cut it, and what breaks if you do.

Built for people learning AD security, so every finding explains the mechanism
rather than just naming it, and includes a lab exercise to reproduce it safely.

## Requirements

| Component | Requirement |
|---|---|
| Live audit | Windows, PowerShell 5.1 or 7.x, line of sight to a domain controller |
| Import and reporting | Any platform, PowerShell 5.1 or 7.x |
| RSAT ActiveDirectory module | Not required. Checks use `System.DirectoryServices` directly |
| Privileges | A standard domain user account is enough for nearly every check |

That last row is the point of the design. Everything the collector reads is
already readable by any authenticated user, which is exactly why these
misconfigurations matter.

## Install

```powershell
Import-Module .\ADRemedy\ADRemedy.psd1

# or install for the current user
Copy-Item .\ADRemedy -Destination "$HOME\Documents\PowerShell\Modules\" -Recurse
Import-Module ADRemedy
```

## Commands

| Command | Purpose |
|---|---|
| `Invoke-ADRemedyAudit` | Runs the read-only checks against a live domain |
| `Import-ADRemedyFindings` | Converts PingCastle, SharpHound, or CSV output into findings |
| `Get-ADRemedyGuidance` | Looks up remediation guidance without running a scan |
| `New-ADRemedyReport` | Renders findings as a self-contained HTML file |

## Usage

Audit a domain and produce a report:

```powershell
Invoke-ADRemedyAudit | New-ADRemedyReport -Path .\corp-review.html
```

Run a subset of checks:

```powershell
Invoke-ADRemedyAudit -IncludeCheck '*Delegation*','*Kerb*' -SkipSysvol |
    Format-Table Severity, Title, AffectedCount
```

Audit a domain you are not joined to:

```powershell
Invoke-ADRemedyAudit -Server dc01.corp.local -Credential (Get-Credential)
```

Import existing scan output, merging findings that several tools both reported:

```powershell
Import-ADRemedyFindings -Path .\scans\ -Merge | New-ADRemedyReport -Path .\review.html
```

Study a topic with no scan at all:

```powershell
Get-ADRemedyGuidance -Keyword delegation | Select-Object id, severity, title
Get-ADRemedyGuidance -FindingId ADR-KERB-001 -Detailed
Get-ADRemedyGuidance -Severity Critical -Detailed
```

Export the raw findings for a ticket queue or spreadsheet:

```powershell
Invoke-ADRemedyAudit |
    Select-Object Severity, FindingId, Title, AffectedCount, Evidence |
    Export-Csv .\findings.csv -NoTypeInformation
```

## Try it without a domain

`Samples\` contains mock SharpHound JSON, a PingCastle XML report, and a Purple
Knight style CSV. This works on macOS and Linux too:

```powershell
Import-ADRemedyFindings -Path .\ADRemedy\Samples -Merge |
    New-ADRemedyReport -Path .\sample-report.html
```

## BloodHound edges

42 edge names map to 18 remediation entries. Feed it a SharpHound collection and
every abusable ACE, local admin grant, session, and SID history entry comes back
as a finding with the fix attached.

```powershell
# from a collection
Import-ADRemedyFindings -Path .\20260901_bloodhound.zip | Where-Object Category -eq 'ACL Edges'

# or just look up an edge you saw in the UI
Get-ADRemedyGuidance -Edge AddKeyCredentialLink -Detailed
Get-ADRemedyGuidance -Category 'ACL Edges' | Select-Object id, severity, edges
```

| Entry | Edges covered |
|---|---|
| ADR-ACL-001 | GenericAll, AllExtendedRights |
| ADR-ACL-002 | GenericWrite, WriteProperty |
| ADR-ACL-003 | WriteDacl |
| ADR-ACL-004 | WriteOwner, Owns, WriteOwnerLimitedRights |
| ADR-ACL-005 | ForceChangePassword |
| ADR-ACL-006 | AddMember, AddSelf, WriteMember |
| ADR-ACL-007 | DCSync, GetChanges, GetChangesAll, GetChangesInFilteredSet |
| ADR-ACL-008 | AddKeyCredentialLink |
| ADR-ACL-009 | WriteSPN, AddSPN |
| ADR-ACL-010 | AddAllowedToAct, WriteAccountRestrictions |
| ADR-ACL-011 | ReadLAPSPassword, SyncLAPSPassword |
| ADR-ACL-012 | ReadGMSAPassword, DumpSMSAPassword |
| ADR-ACL-013 | WriteGPLink, GPO control edges |
| ADR-PATH-001 | AdminTo |
| ADR-PATH-002 | HasSession |
| ADR-PATH-003 | CanRDP, CanPSRemote, ExecuteDCOM |
| ADR-PATH-004 | SQLAdmin |
| ADR-PATH-005 | HasSIDHistory |
| ADR-DELEG-002 / 003 | AllowedToDelegate, AllowedToAct |

Three behaviours worth knowing:

**Built-in tier 0 principals are filtered by default.** Domain Admins holding
GenericAll on everything is the design, not a finding, and including it buries the
real edges in thousands of expected rows. Use `-IncludeDefaultPrincipals` to see
them.

**Severity is raised when the target is tier 0.** The same GenericAll edge against
a test group and against Domain Admins are not the same finding, so an edge
pointing at a privileged group, a domain controller, krbtgt, or the domain object
is escalated to Critical.

**Object-control edges on a GPO route to the GPO entry.** GenericAll over a GPO is
code execution on everything in that policy's scope, and the fix is GPO
permissions, not an object ACE.

## Checks

22 checks across 10 categories. Each maps to a catalog entry with the same ID.

| ID | Check | Severity |
|---|---|---|
| ADR-DELEG-001 | Unconstrained delegation outside the Domain Controllers OU | Critical |
| ADR-DELEG-002 | Constrained delegation with protocol transition | High |
| ADR-DELEG-003 | Resource-based constrained delegation configured | Medium |
| ADR-KERB-001 | Privileged account with an SPN (kerberoastable) | Critical |
| ADR-KERB-002 | Kerberos pre-authentication disabled (AS-REP roastable) | High |
| ADR-KERB-003 | krbtgt password older than 180 days | High |
| ADR-PRIV-001 | Excessive privileged group membership | High |
| ADR-PRIV-002 | Privileged account delegatable and not in Protected Users | High |
| ADR-PRIV-003 | Orphaned adminCount with broken inheritance | Medium |
| ADR-ACCT-001 | Password set to never expire | Medium |
| ADR-ACCT-002 | Stale account still enabled | Medium |
| ADR-ACCT-003 | Reversible password encryption | High |
| ADR-ACCT-004 | Password-not-required flag | High |
| ADR-DOM-001 | Machine account quota greater than zero | High |
| ADR-DOM-002 | Weak password or lockout policy | Medium |
| ADR-DOM-003 | Pre-Windows 2000 Compatible Access contains a broad identity | Medium |
| ADR-HOST-001 | Unsupported operating system on an enabled computer | High |
| ADR-HOST-002 | No managed local administrator password (LAPS gap) | High |
| ADR-CERT-001 | Certificate template allows enrollee-supplied subject | Critical |
| ADR-TRUST-001 | Trust without SID filtering | High |
| ADR-GPO-001 | cpassword in SYSVOL | Critical |
| ADR-ACL-* | Dangerous ACEs on tier 0 objects, including DCSync rights | Critical |

## Finding object

```
FindingId       ADR-KERB-001
Title           Privileged account with a service principal name (kerberoastable)
Severity        Critical
SeverityRank    0            # sort key, worst first
Category        Kerberos
Source          Live Audit | PingCastle | SharpHound | CSV Import
Domain          corp.local
Evidence        What was actually observed
AffectedObjects Array of objects, shape varies by check
AffectedCount   Count of the above
Guidance        The catalog entry: summary, howItWorks, attackChain, remediation,
                validation, breakRisk, lab, mitre, references
HasGuidance     False for imported findings with no catalog entry yet
```

## Adding a check

Two files. Add the catalog entry, then the check function.

1. Add an entry to `Data\RemediationCatalog.json` with a new ID. Use an existing
   entry as the template; every field is optional except `id`, `title`,
   `severity`, and `category`.

2. Add a function named `Invoke-ADRCheck<Something>` to a file in
   `Private\Checks\`. It is discovered automatically by name, so there is nothing
   to register. It takes `$Context` and returns findings:

```powershell
function Invoke-ADRCheckMyThing {
    [CmdletBinding()]
    param($Context)

    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context `
        -Filter '(&(objectClass=user)(someAttribute=*))' `
        -Property @('distinguishedName','samAccountName','someAttribute'))
    if (-not $rows) { return }

    New-ADRemedyFinding -FindingId 'ADR-XXXX-001' -Source 'Live Audit' `
        -Domain $Context.DomainFQDN `
        -Evidence "$($rows.Count) object(s) matched." `
        -AffectedObjects ($rows | ForEach-Object {
            [pscustomobject]@{ Name = ConvertTo-ADRemedyName $_ }
        })
}
```

If the check needs a tunable threshold, add it as a parameter named `InactiveDays`
or `SkipSysvol` and `Invoke-ADRemedyAudit` will pass the user's value through.
Other parameter names are left at their defaults.

To map a new external tool rule onto your entry, add it to the table in
`Get-ADRemedySourceMap` inside `Public\Import-ADRemedyFindings.ps1`.

## Notes on accuracy

Some things worth knowing before you take a finding to a client.

**PingCastle rule IDs drift between versions.** The mapping table covers the
common ones. Anything unmapped still comes through with the source tool's own
description, tagged `HasGuidance = False`, so nothing is silently dropped. Check
the report for those and extend the map as you meet them.

**SharpHound import reads collected data, not computed paths.** It reads the
properties, ACEs, local group memberships, sessions, and SID history that
SharpHound already gathered, and reports each abusable edge with its remediation.
It does not run the graph queries, so it will not tell you that five edges chain
together into a path to Domain Admins. Use BloodHound for the path, then use this
for what to change at each hop.

**Session data is a snapshot.** `HasSession` reflects who was logged on at
collection time. An empty result means nobody was logged on during that
collection, not that privileged accounts never touch the host. Collect more than
once before concluding anything.

**The live ACL check is scoped to tier 0 objects.** `Invoke-ADRCheckTier0Acl`
reads the DACL on the domain object, AdminSDHolder, privileged groups, domain
controllers, and krbtgt. A full-domain ACL walk would take far longer and produce
mostly noise, so edges pointing at ordinary objects will only appear via a
SharpHound import.

**`lastLogonTimestamp` replicates lazily.** It can be up to 14 days behind, so the
stale account check errs toward reporting an account as stale. Confirm against
`lastLogon` on each DC before disabling anything.

**The certificate template check is an indicator, not a verdict.** It flags
templates whose flags combine enrollee-supplied subject, client authentication,
and no approval step. Whether that is exploitable depends on the enrolment rights
in the template's DACL, which you should review before escalating.

**Trust findings include intra-forest trusts.** Parent-child trusts inside a
forest legitimately lack the quarantine flag, because the forest is the security
boundary. Expect them in the output and read the guidance for why.

## Safety

The collector only performs LDAP reads and one optional read of the SYSVOL share.
It never writes to the directory. The remediation commands in the report are
generated text for you to review and run deliberately; nothing in this module
executes them. Every catalog entry has a "What could break" note, and several of
these changes will cause an outage if applied without checking who depends on the
current configuration.

Get written authorization before running this against an environment that is not
yours.
