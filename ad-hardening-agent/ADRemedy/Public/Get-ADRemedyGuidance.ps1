function Get-ADRemedyGuidance {
    <#
    .SYNOPSIS
        Looks up remediation guidance from the catalog, by finding ID, keyword, or category.

    .DESCRIPTION
        Use this to study a topic without running a scan. -Detailed prints the full
        writeup to the console: how the weakness is abused, the remediation steps with
        commands, what could break, and a lab exercise to see it work.

    .PARAMETER FindingId
        Exact catalog ID, e.g. ADR-KERB-001. Wildcards accepted.

    .PARAMETER Edge
        BloodHound edge name, e.g. GenericAll, DCSync, AddKeyCredentialLink.
        Matching is exact but case-insensitive.

    .PARAMETER Keyword
        Free text matched against title, summary, and the abuse explanation.

    .PARAMETER Category
        Filter to one category, e.g. Delegation, Kerberos, Certificate Services.

    .PARAMETER Severity
        Filter to one severity level.

    .PARAMETER Detailed
        Print the full writeup instead of returning the object.

    .EXAMPLE
        Get-ADRemedyGuidance -FindingId ADR-KERB-001 -Detailed

    .EXAMPLE
        Get-ADRemedyGuidance -Keyword delegation | Select-Object id, severity, title

    .EXAMPLE
        Get-ADRemedyGuidance -Edge DCSync -Detailed

    .EXAMPLE
        Get-ADRemedyGuidance -Category 'ACL Edges' | Select-Object id, severity, edges

    .EXAMPLE
        Get-ADRemedyGuidance -Severity Critical
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param(
        [Parameter(ParameterSetName = 'ById', Position = 0)]
        [SupportsWildcards()]
        [string]$FindingId,

        [Parameter(ParameterSetName = 'ByKeyword')]
        [string]$Keyword,

        [Parameter(ParameterSetName = 'ByEdge')]
        [string]$Edge,

        [string]$Category,

        [ValidateSet('Critical', 'High', 'Medium', 'Low')]
        [string]$Severity,

        [switch]$Detailed
    )

    $catalog = Get-ADRemedyCatalog
    $entries = @($catalog.Values)

    if ($FindingId) {
        $entries = @($entries | Where-Object { $_.id -like $FindingId })
    }
    if ($Edge) {
        $matched = @($entries | Where-Object { @($_.edges) -contains $Edge -or (@($_.edges) | Where-Object { $_ -and $_.ToLowerInvariant() -eq $Edge.ToLowerInvariant() }) })
        if (-not $matched) {
            # Fall back to the same resolver the importer uses, so component edges
            # like GetChangesAll still land on the right entry.
            $resolved = Resolve-ADRemedyEdge -Edge $Edge
            if ($resolved) { $matched = @($entries | Where-Object { $_.id -eq $resolved }) }
        }
        $entries = $matched
    }
    if ($Keyword) {
        $entries = @($entries | Where-Object {
            $_.title -match [regex]::Escape($Keyword) -or
            $_.summary -match [regex]::Escape($Keyword) -or
            $_.howItWorks -match [regex]::Escape($Keyword) -or
            $_.category -match [regex]::Escape($Keyword) -or
            (@($_.edges) -join ' ') -match [regex]::Escape($Keyword)
        })
    }
    if ($Category) { $entries = @($entries | Where-Object { $_.category -like "*$Category*" }) }
    if ($Severity) { $entries = @($entries | Where-Object { $_.severity -eq $Severity }) }

    if (-not $entries) {
        Write-Warning 'No catalog entries matched. Try Get-ADRemedyGuidance with no parameters to list everything.'
        return
    }

    $entries = $entries | Sort-Object { Get-ADRemedySeverityRank -Severity $_.severity }, id

    if (-not $Detailed) { return $entries }

    foreach ($entry in $entries) {
        $color = switch ($entry.severity) {
            'Critical' { 'Red' }
            'High'     { 'DarkYellow' }
            'Medium'   { 'Yellow' }
            default    { 'Gray' }
        }

        Write-Host ''
        Write-Host ("=" * 78) -ForegroundColor DarkGray
        Write-Host "$($entry.id)  [$($entry.severity)]  $($entry.category)" -ForegroundColor $color
        Write-Host $entry.title -ForegroundColor White
        Write-Host ("=" * 78) -ForegroundColor DarkGray

        Write-Host "`nWHAT IT IS" -ForegroundColor Cyan
        Write-Host $entry.summary

        Write-Host "`nHOW IT IS ABUSED" -ForegroundColor Cyan
        Write-Host $entry.howItWorks

        if ($entry.attackChain) {
            Write-Host "`nTYPICAL CHAIN" -ForegroundColor Cyan
            $i = 0
            foreach ($step in $entry.attackChain) { $i++; Write-Host "  $i. $step" }
        }

        Write-Host "`nREMEDIATION" -ForegroundColor Green
        $i = 0
        foreach ($step in $entry.remediation) {
            $i++
            Write-Host "  $i. $($step.step)"
            if ($step.command) { Write-Host "     $($step.command)" -ForegroundColor DarkCyan }
        }

        Write-Host "`nVERIFY THE FIX" -ForegroundColor Green
        Write-Host "  $($entry.validation)" -ForegroundColor DarkCyan

        Write-Host "`nWHAT COULD BREAK" -ForegroundColor Yellow
        Write-Host $entry.breakRisk

        if ($entry.lab) {
            Write-Host "`nLAB EXERCISE" -ForegroundColor Magenta
            Write-Host $entry.lab
        }

        if ($entry.edges) {
            Write-Host "`\nBLOODHOUND EDGES: $($entry.edges -join ', ')" -ForegroundColor Blue
        }
        if ($entry.mitre) {
            Write-Host "`nMITRE ATT&CK: $($entry.mitre -join ', ')" -ForegroundColor DarkGray
        }
        if ($entry.references) {
            Write-Host 'REFERENCES' -ForegroundColor DarkGray
            foreach ($ref in $entry.references) {
                $line = "  $($ref.title)"
                if ($ref.url) { $line += " - $($ref.url)" }
                Write-Host $line -ForegroundColor DarkGray
            }
        }
        Write-Host ''
    }
}
