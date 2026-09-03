# Edge handling shared by the SharpHound importer and the live ACL check.

function Get-ADRemedyEdgeMap {
    <#
    .SYNOPSIS
        Reverse index of BloodHound edge name to catalog finding ID, built from the
        'edges' field on each catalog entry so the two never drift apart.
    #>
    [CmdletBinding()]
    param([switch]$Force)

    if ($script:ADRemedyEdgeMap -and -not $Force) { return $script:ADRemedyEdgeMap }

    $map = @{}
    foreach ($entry in (Get-ADRemedyCatalog).Values) {
        foreach ($edge in @($entry.edges)) {
            if ($edge) { $map[$edge.ToLowerInvariant()] = $entry.id }
        }
    }

    $script:ADRemedyEdgeMap = $map
    return $script:ADRemedyEdgeMap
}

function Resolve-ADRemedyEdge {
    <#
    .SYNOPSIS
        Maps a SharpHound RightName or edge label onto a catalog finding ID.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Edge)

    $map = Get-ADRemedyEdgeMap
    $key = $Edge.ToLowerInvariant()
    if ($map.ContainsKey($key)) { return $map[$key] }

    # SharpHound splits DCSync into its component replication rights. Either one
    # alone is not the attack, but both together are, and reporting the pair is
    # more useful than reporting neither.
    if ($key -in 'getchanges', 'getchangesall', 'getchangesinfilteredset', 'dcsync') { return 'ADR-ACL-007' }
    return $null
}

# Structural or benign edges that appear in every collection and are not findings.
$script:ADRemedyIgnoredEdges = @(
    'contains', 'memberof', 'hasrole', 'trustedby', 'container',
    'enroll', 'enrollonbehalfof', 'publishedto', 'enterpriseca',
    'rootcafor', 'ntauthstorefor', 'trustedforntauth', 'issuedsignedby',
    'extendedright', 'localtocomputer', 'memberoflocalgroup', 'haslapspassword'
)

# Principals that legitimately hold sweeping rights everywhere. Reporting them
# turns a useful finding into thousands of rows of expected configuration.
$script:ADRemedyDefaultPrincipalRids = @('-512', '-516', '-517', '-518', '-519', '-498', '-500', '-521')
$script:ADRemedyDefaultPrincipalSids = @(
    'S-1-5-18', 'S-1-5-9', 'S-1-5-10', 'S-1-3-0', 'S-1-3-4', 'S-1-5-32-544',
    'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551', 'S-1-5-32-552'
)

function Test-ADRemedyDefaultPrincipal {
    <#
    .SYNOPSIS
        True when a SID belongs to a built-in tier 0 principal whose broad rights
        are expected rather than a finding.
    #>
    [CmdletBinding()]
    param([string]$Sid, [string]$Name)

    if (-not $Sid -and -not $Name) { return $false }

    if ($Sid) {
        if ($Sid -in $script:ADRemedyDefaultPrincipalSids) { return $true }
        foreach ($rid in $script:ADRemedyDefaultPrincipalRids) {
            if ($Sid.EndsWith($rid)) { return $true }
        }
    }

    if ($Name -and $Name -match '^(NT AUTHORITY\\|BUILTIN\\)?(SYSTEM|SELF|CREATOR OWNER|ENTERPRISE DOMAIN CONTROLLERS|Domain Admins|Enterprise Admins|Schema Admins|Administrators|Domain Controllers|Enterprise Read-only Domain Controllers|Key Admins|Enterprise Key Admins)') {
        return $true
    }

    return $false
}

function Get-ADRemedyEdgeSeverity {
    <#
    .SYNOPSIS
        Raises severity when an edge points at a tier 0 target, since the same edge
        against a test group and against Domain Admins are not the same finding.
    #>
    [CmdletBinding()]
    param([string]$BaseSeverity, [object[]]$AffectedObject)

    $tier0 = @($AffectedObject | Where-Object {
        "$($_.Target)" -match '(?i)domain admins|enterprise admins|schema admins|administrators|domain controllers|adminsdholder|krbtgt' -or
        "$($_.TargetType)" -eq 'Domain'
    })

    if ($tier0.Count -and $BaseSeverity -ne 'Critical') { return 'Critical' }
    return $BaseSeverity
}
