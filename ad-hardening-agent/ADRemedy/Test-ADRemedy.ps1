<#
.SYNOPSIS
    Smoke test for ADRemedy. Runs without a domain, so it works anywhere.

.DESCRIPTION
    Validates that every file parses, the module loads, the catalog is well formed,
    all three import parsers work against the sample data, and the HTML report
    renders. Run it after editing the catalog or adding a check.

.EXAMPLE
    pwsh -NoProfile -File .\Test-ADRemedy.ps1
#>
[CmdletBinding()]
param([switch]$KeepReport)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$pass = 0
$fail = 0

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        $result = & $Body
        if ($result -eq $false) { throw 'Assertion returned false.' }
        Write-Host "  PASS  $Name" -ForegroundColor Green
        $script:pass++
    } catch {
        Write-Host "  FAIL  $Name" -ForegroundColor Red
        Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkGray
        $script:fail++
    }
}

Write-Host "`nADRemedy smoke test`n" -ForegroundColor Cyan

Test-Case 'All PowerShell files parse' {
    $errors = @()
    Get-ChildItem -Path $root -Filter '*.ps1' -Recurse | ForEach-Object {
        $tokens = $null; $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
        if ($parseErrors) { $errors += "$($_.Name): $($parseErrors[0].Message)" }
    }
    if ($errors) { throw ($errors -join '; ') }
    $true
}

Test-Case 'Module imports and exports four commands' {
    Import-Module (Join-Path $root 'ADRemedy.psd1') -Force
    $commands = @(Get-Command -Module ADRemedy)
    if ($commands.Count -ne 4) { throw "Expected 4 exported commands, got $($commands.Count)." }
    $true
}

Test-Case 'Catalog is valid JSON with unique IDs and required fields' {
    $catalog = Get-Content (Join-Path $root 'Data/RemediationCatalog.json') -Raw | ConvertFrom-Json
    $ids = @($catalog.id)
    if ($ids.Count -ne ($ids | Select-Object -Unique).Count) { throw 'Duplicate catalog IDs.' }
    foreach ($entry in $catalog) {
        foreach ($field in 'id', 'title', 'severity', 'category', 'summary', 'remediation') {
            if (-not $entry.$field) { throw "$($entry.id) is missing '$field'." }
        }
        if ($entry.severity -notin 'Critical', 'High', 'Medium', 'Low') {
            throw "$($entry.id) has an unrecognised severity '$($entry.severity)'."
        }
    }
    Write-Host "        $($ids.Count) catalog entries" -ForegroundColor DarkGray
    $true
}

Test-Case 'Every check function has a matching catalog entry' {
    Import-Module (Join-Path $root 'ADRemedy.psd1') -Force
    $checkFiles = Get-ChildItem (Join-Path $root 'Private/Checks') -Filter '*.ps1'
    $referenced = foreach ($file in $checkFiles) {
        [regex]::Matches((Get-Content $file.FullName -Raw), "FindingId '(ADR-[A-Z]+-\d+)'") |
            ForEach-Object { $_.Groups[1].Value }
    }
    $catalogIds = @((Get-Content (Join-Path $root 'Data/RemediationCatalog.json') -Raw | ConvertFrom-Json).id)
    $orphans = @($referenced | Select-Object -Unique | Where-Object { $_ -notin $catalogIds })
    if ($orphans) { throw "Checks reference missing catalog entries: $($orphans -join ', ')" }
    Write-Host "        $(@($referenced | Select-Object -Unique).Count) IDs referenced by checks" -ForegroundColor DarkGray
    $true
}

Test-Case 'PingCastle XML imports' {
    $findings = @(Import-ADRemedyFindings -Path (Join-Path $root 'Samples/sample-pingcastle.xml'))
    if ($findings.Count -lt 5) { throw "Expected at least 5 findings, got $($findings.Count)." }
    if (-not ($findings | Where-Object HasGuidance)) { throw 'No PingCastle rule mapped to a catalog entry.' }
    $true
}

Test-Case 'SharpHound JSON imports' {
    $findings = @(Import-ADRemedyFindings -Path (Join-Path $root 'Samples') -Format SharpHound)
    if (-not ($findings | Where-Object FindingId -eq 'ADR-DELEG-001')) { throw 'Unconstrained delegation not detected.' }
    if (-not ($findings | Where-Object FindingId -eq 'ADR-KERB-002')) { throw 'AS-REP roastable not detected.' }
    $true
}

Test-Case 'Every catalog edge name is unique across entries' {
    $catalog = Get-Content (Join-Path $root 'Data/RemediationCatalog.json') -Raw | ConvertFrom-Json
    $owner = @{}
    foreach ($entry in $catalog) {
        foreach ($edge in @($entry.edges)) {
            if (-not $edge) { continue }
            if ($owner.ContainsKey($edge)) { throw "Edge '$edge' is claimed by both $($owner[$edge]) and $($entry.id)." }
            $owner[$edge] = $entry.id
        }
    }
    Write-Host "        $($owner.Count) BloodHound edges mapped" -ForegroundColor DarkGray
    $true
}

Test-Case 'BloodHound edges extract from SharpHound data' {
    $findings = @(Import-ADRemedyFindings -Path (Join-Path $root 'Samples') -Format SharpHound)
    $edgeFindings = @($findings | Where-Object { $_.Category -in 'ACL Edges', 'Attack Paths' })
    if ($edgeFindings.Count -lt 10) { throw "Expected at least 10 edge findings, got $($edgeFindings.Count)." }

    foreach ($id in 'ADR-ACL-007', 'ADR-ACL-008', 'ADR-PATH-001', 'ADR-PATH-002') {
        if (-not ($findings | Where-Object FindingId -eq $id)) { throw "Expected finding $id was not produced." }
    }

    # SIDs must resolve to names, otherwise the report is unreadable
    $dcsync = $findings | Where-Object FindingId -eq 'ADR-ACL-007'
    if ($dcsync.AffectedObjects[0].Principal -match '^S-1-5-') { throw 'Principal SID was not resolved to a name.' }

    # both replication rights must survive deduplication
    if (@($dcsync.AffectedObjects.Edge | Select-Object -Unique).Count -lt 2) {
        throw 'GetChanges and GetChangesAll collapsed into one row.'
    }

    Write-Host "        $($edgeFindings.Count) edge findings extracted" -ForegroundColor DarkGray
    $true
}

Test-Case 'Built-in tier 0 principals are filtered unless requested' {
    $default = @(Import-ADRemedyFindings -Path (Join-Path $root 'Samples') -Format SharpHound)
    $all = @(Import-ADRemedyFindings -Path (Join-Path $root 'Samples') -Format SharpHound -IncludeDefaultPrincipals)

    $defaultRows = ($default | Where-Object { $_.Category -eq 'ACL Edges' }).AffectedObjects.Count
    $allRows = ($all | Where-Object { $_.Category -eq 'ACL Edges' }).AffectedObjects.Count
    if ($allRows -le $defaultRows) { throw 'IncludeDefaultPrincipals did not surface additional edges.' }

    if (($default | Where-Object { $_.Category -eq 'ACL Edges' }).AffectedObjects.Principal -match 'DOMAIN ADMINS') {
        throw 'Domain Admins edges were not filtered by default.'
    }
    $true
}

Test-Case 'Edge lookup resolves both catalog names and component rights' {
    if ((Get-ADRemedyGuidance -Edge GenericAll).id -ne 'ADR-ACL-001') { throw 'GenericAll did not resolve.' }
    if ((Get-ADRemedyGuidance -Edge GetChangesAll).id -ne 'ADR-ACL-007') { throw 'GetChangesAll did not resolve to the DCSync entry.' }
    if ((Get-ADRemedyGuidance -Edge readlapspassword).id -ne 'ADR-ACL-011') { throw 'Edge matching is not case-insensitive.' }
    $true
}

Test-Case 'CSV imports' {
    $findings = @(Import-ADRemedyFindings -Path (Join-Path $root 'Samples/sample-purpleknight.csv'))
    if ($findings.Count -lt 6) { throw "Expected at least 6 rows, got $($findings.Count)." }
    $true
}

Test-Case 'Merge collapses duplicates across tools' {
    $raw = @(Import-ADRemedyFindings -Path (Join-Path $root 'Samples'))
    $merged = @(Import-ADRemedyFindings -Path (Join-Path $root 'Samples') -Merge)
    if ($merged.Count -ge $raw.Count) { throw 'Merge did not reduce the finding count.' }
    $ids = @($merged.FindingId)
    if ($ids.Count -ne ($ids | Select-Object -Unique).Count) { throw 'Merged output still has duplicate IDs.' }
    Write-Host "        $($raw.Count) raw findings collapsed to $($merged.Count)" -ForegroundColor DarkGray
    $true
}

Test-Case 'Guidance lookup works by ID, keyword, and severity' {
    if (-not (Get-ADRemedyGuidance -FindingId 'ADR-KERB-001')) { throw 'Lookup by ID failed.' }
    if (-not (Get-ADRemedyGuidance -Keyword 'delegation')) { throw 'Lookup by keyword failed.' }
    if (-not (Get-ADRemedyGuidance -Severity Critical)) { throw 'Lookup by severity failed.' }
    $true
}

Test-Case 'HTML report renders and is self-contained' {
    $out = Join-Path ([System.IO.Path]::GetTempPath()) 'adremedy-smoketest.html'
    Import-ADRemedyFindings -Path (Join-Path $root 'Samples') -Merge |
        New-ADRemedyReport -Path $out -Title 'Smoke test' | Out-Null

    $html = Get-Content $out -Raw
    if ($html -notmatch '</html>') { throw 'Report is truncated.' }
    if ($html -match '<(script|link|img)[^>]+src="http') { throw 'Report references an external asset.' }
    if ($html -notmatch 'ADR-DELEG-001') { throw 'Expected finding missing from the report.' }
    if ($html -notmatch 'BloodHound edges') { throw 'Edge names are missing from the report.' }

    Write-Host "        $([math]::Round((Get-Item $out).Length / 1KB)) KB written" -ForegroundColor DarkGray
    if ($KeepReport) { Write-Host "        kept at $out" -ForegroundColor DarkGray }
    else { Remove-Item $out -Force }
    $true
}

Test-Case 'Live audit refuses to run on a non-Windows host' {
    if ($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
        Write-Host '        skipped, running on Windows' -ForegroundColor DarkGray
        return $true
    }
    try {
        Invoke-ADRemedyAudit -ErrorAction Stop | Out-Null
        throw 'Audit should have thrown on this platform.'
    } catch {
        if ($_.Exception.Message -notmatch 'requires Windows') { throw "Unexpected error: $($_.Exception.Message)" }
    }
    $true
}

Write-Host ''
$color = if ($fail -gt 0) { 'Red' } else { 'Green' }
Write-Host "$pass passed, $fail failed" -ForegroundColor $color
Write-Host ''
if ($fail -gt 0) { exit 1 }
