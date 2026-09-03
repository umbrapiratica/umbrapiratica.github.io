function Invoke-ADRemedyAudit {
    <#
    .SYNOPSIS
        Runs read-only checks against an Active Directory domain and returns findings
        with remediation guidance attached.

    .DESCRIPTION
        Uses LDAP searches through System.DirectoryServices, so no RSAT module is
        required and no writes are ever made. Every check reads directory attributes
        that any authenticated domain user can already read; the point of the tool is
        to show you what an attacker sees, and what to do about each item.

        Run it from a domain-joined Windows host, or supply -Server and -Credential.

    .PARAMETER Server
        Domain controller to query. Defaults to the host's own domain.

    .PARAMETER Credential
        Credentials for the LDAP bind. Defaults to the current user.

    .PARAMETER IncludeCheck
        Only run checks whose name matches one of these wildcards, e.g. '*Delegation*'.

    .PARAMETER ExcludeCheck
        Skip checks whose name matches one of these wildcards.

    .PARAMETER InactiveDays
        Threshold in days for the stale account check. Default 90.

    .PARAMETER SkipSysvol
        Skip the SYSVOL scan for Group Policy Preferences passwords, which walks a
        file share and can be slow on large policy sets.

    .EXAMPLE
        Invoke-ADRemedyAudit | New-ADRemedyReport -Path .\ad-report.html

    .EXAMPLE
        Invoke-ADRemedyAudit -IncludeCheck '*Delegation*','*Kerb*' | Format-Table Severity,Title,AffectedCount

    .EXAMPLE
        Invoke-ADRemedyAudit -Server dc01.corp.local -Credential (Get-Credential)
    #>
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential,
        [string[]]$IncludeCheck,
        [string[]]$ExcludeCheck,
        [int]$InactiveDays = 90,
        [switch]$SkipSysvol
    )

    if (-not (Test-ADRemedyWindows)) {
        throw 'Invoke-ADRemedyAudit requires Windows. On macOS or Linux, use Import-ADRemedyFindings with exported scan data instead.'
    }

    Write-Verbose 'Resolving directory context.'
    $context = Get-ADRemedyContext -Server $Server -Credential $Credential
    Write-Host "Auditing $($context.DomainFQDN)" -ForegroundColor Cyan

    $checks = Get-Command -CommandType Function -Name 'Invoke-ADRCheck*' -ErrorAction SilentlyContinue |
        Sort-Object Name

    if ($IncludeCheck) {
        $checks = $checks | Where-Object { $name = $_.Name; @($IncludeCheck | Where-Object { $name -like $_ }).Count -gt 0 }
    }
    if ($ExcludeCheck) {
        $checks = $checks | Where-Object { $name = $_.Name; @($ExcludeCheck | Where-Object { $name -like $_ }).Count -eq 0 }
    }

    $checks = @($checks)
    if (-not $checks) {
        Write-Warning 'No checks matched the include/exclude filters.'
        return
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    $i = 0

    foreach ($check in $checks) {
        $i++
        $label = $check.Name -replace '^Invoke-ADRCheck', ''
        Write-Progress -Activity "ADRemedy audit of $($context.DomainFQDN)" -Status $label `
            -PercentComplete (($i / $checks.Count) * 100)

        $splat = @{ Context = $context }
        if ($check.Parameters.ContainsKey('InactiveDays')) { $splat['InactiveDays'] = $InactiveDays }
        if ($check.Parameters.ContainsKey('SkipSysvol'))   { $splat['SkipSysvol'] = $SkipSysvol }

        try {
            $result = & $check @splat
            foreach ($item in @($result)) {
                if ($item) {
                    $findings.Add($item)
                    Write-Verbose "$label -> $($item.FindingId) ($($item.Severity), $($item.AffectedCount) object(s))"
                }
            }
        } catch {
            Write-Warning "Check '$label' failed: $($_.Exception.Message)"
        }
    }

    Write-Progress -Activity "ADRemedy audit of $($context.DomainFQDN)" -Completed

    $sorted = $findings | Sort-Object SeverityRank, Category, Title
    Write-Host "$($sorted.Count) finding(s) across $($checks.Count) check(s)." -ForegroundColor Cyan
    $sorted
}
