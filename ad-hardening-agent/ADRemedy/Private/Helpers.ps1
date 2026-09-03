function Get-ADRemedyCatalog {
    <#
    .SYNOPSIS
        Loads and caches the remediation catalog from Data\RemediationCatalog.json.
    #>
    [CmdletBinding()]
    param([switch]$Force)

    if ($script:ADRemedyCatalog -and -not $Force) { return $script:ADRemedyCatalog }

    $path = Join-Path -Path $script:ADRemedyModuleRoot -ChildPath 'Data/RemediationCatalog.json'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Remediation catalog not found at '$path'."
    }

    $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    $entries = $raw | ConvertFrom-Json

    $index = [ordered]@{}
    foreach ($entry in $entries) { $index[$entry.id] = $entry }

    $script:ADRemedyCatalog = $index
    return $script:ADRemedyCatalog
}

function Get-ADRemedySeverityRank {
    <#
    .SYNOPSIS
        Numeric rank for a severity label so findings sort worst-first.
    #>
    param([string]$Severity)

    switch ($Severity) {
        'Critical' { 0; break }
        'High'     { 1; break }
        'Medium'   { 2; break }
        'Low'      { 3; break }
        default    { 4 }
    }
}

function New-ADRemedyFinding {
    <#
    .SYNOPSIS
        Builds a normalized finding object. Every source (live audit, PingCastle,
        SharpHound, CSV) funnels through here so the report only handles one shape.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FindingId,
        [string]$Title,
        [string]$Severity,
        [string]$Category,
        [string]$Source = 'Unknown',
        [string]$Domain,
        [string]$Evidence,
        [object[]]$AffectedObjects = @(),
        [hashtable]$Detail = @{}
    )

    $catalog = Get-ADRemedyCatalog
    $guidance = $null
    if ($catalog.Contains($FindingId)) { $guidance = $catalog[$FindingId] }

    if (-not $Title)    { $Title    = if ($guidance) { $guidance.title }    else { $FindingId } }
    if (-not $Severity) { $Severity = if ($guidance) { $guidance.severity } else { 'Medium' } }
    if (-not $Category) { $Category = if ($guidance) { $guidance.category } else { 'Other' } }

    [pscustomobject]@{
        PSTypeName      = 'ADRemedy.Finding'
        FindingId       = $FindingId
        Title           = $Title
        Severity        = $Severity
        SeverityRank    = Get-ADRemedySeverityRank -Severity $Severity
        Category        = $Category
        Source          = $Source
        Domain          = $Domain
        Evidence        = $Evidence
        AffectedObjects = @($AffectedObjects)
        AffectedCount   = @($AffectedObjects).Count
        Detail          = $Detail
        HasGuidance     = [bool]$guidance
        Guidance        = $guidance
        DetectedOn      = Get-Date
    }
}

function Test-ADRemedyWindows {
    <#
    .SYNOPSIS
        Live collection needs System.DirectoryServices, which is Windows only.
    #>
    return ($IsWindows -or ($PSVersionTable.PSEdition -eq 'Desktop'))
}

function Get-ADRemedyContext {
    <#
    .SYNOPSIS
        Resolves naming contexts and domain metadata over LDAP via ADSI.
    .DESCRIPTION
        Deliberately avoids the RSAT ActiveDirectory module so the collector runs on
        any domain-joined host. All operations are read-only LDAP searches.
    #>
    [CmdletBinding()]
    param(
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    if (-not (Test-ADRemedyWindows)) {
        throw 'Live collection requires Windows. On other platforms, use Import-ADRemedyFindings with exported scan data.'
    }

    $rootPath = if ($Server) { "LDAP://$Server/RootDSE" } else { 'LDAP://RootDSE' }
    $rootDse = if ($Credential) {
        New-Object System.DirectoryServices.DirectoryEntry(
            $rootPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        New-Object System.DirectoryServices.DirectoryEntry($rootPath)
    }

    $defaultNc = [string]$rootDse.Properties['defaultNamingContext'].Value
    if (-not $defaultNc) { throw 'Could not read defaultNamingContext. Confirm this host can reach a domain controller.' }

    $prefix = if ($Server) { "LDAP://$Server/" } else { 'LDAP://' }

    [pscustomobject]@{
        Server            = $Server
        Credential        = $Credential
        Prefix            = $prefix
        DefaultNC         = $defaultNc
        ConfigurationNC   = [string]$rootDse.Properties['configurationNamingContext'].Value
        SchemaNC          = [string]$rootDse.Properties['schemaNamingContext'].Value
        DnsHostName       = [string]$rootDse.Properties['dnsHostName'].Value
        DomainFQDN        = ($defaultNc -replace 'DC=', '' -replace ',', '.')
        DomainFunctional  = [int]($rootDse.Properties['domainFunctionality'].Value)
        ForestFunctional  = [int]($rootDse.Properties['forestFunctionality'].Value)
    }
}

function New-ADRemedyDirectoryEntry {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$DistinguishedName
    )

    $path = "$($Context.Prefix)$DistinguishedName"
    if ($Context.Credential) {
        New-Object System.DirectoryServices.DirectoryEntry(
            $path, $Context.Credential.UserName, $Context.Credential.GetNetworkCredential().Password)
    } else {
        New-Object System.DirectoryServices.DirectoryEntry($path)
    }
}

function Invoke-ADRemedyLdapQuery {
    <#
    .SYNOPSIS
        Runs a paged, read-only LDAP search and returns flattened property hashtables.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Filter,
        [string]$SearchBase,
        [string[]]$Property = @('distinguishedName', 'samAccountName', 'name'),
        [int]$SizeLimit = 0
    )

    if (-not $SearchBase) { $SearchBase = $Context.DefaultNC }
    $entry = New-ADRemedyDirectoryEntry -Context $Context -DistinguishedName $SearchBase

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = $Filter
    $searcher.PageSize = 1000
    $searcher.SizeLimit = $SizeLimit
    $searcher.SearchScope = 'Subtree'
    foreach ($p in $Property) { [void]$searcher.PropertiesToLoad.Add($p) }

    try {
        $results = $searcher.FindAll()
        foreach ($result in $results) {
            $row = [ordered]@{}
            foreach ($key in $result.Properties.PropertyNames) {
                $values = @($result.Properties[$key])
                $row[$key] = if ($values.Count -eq 1) { $values[0] } else { $values }
            }
            [pscustomobject]$row
        }
    } finally {
        if ($results) { $results.Dispose() }
        $searcher.Dispose()
        $entry.Dispose()
    }
}

function ConvertFrom-ADRemedyFileTime {
    param($Value)
    if (-not $Value) { return $null }
    try {
        $ticks = [int64]$Value
        if ($ticks -le 0 -or $ticks -ge 9223372036854775807) { return $null }
        return [datetime]::FromFileTimeUtc($ticks).ToLocalTime()
    } catch { return $null }
}

function ConvertTo-ADRemedyName {
    <#
    .SYNOPSIS
        Best-effort friendly name for an LDAP result row.
    #>
    param($Row)
    if ($Row.samaccountname) { return [string]$Row.samaccountname }
    if ($Row.name)           { return [string]$Row.name }
    if ($Row.cn)             { return [string]$Row.cn }
    return [string]$Row.distinguishedname
}

function Write-ADRemedyLog {
    param([string]$Message, [ValidateSet('Info', 'Warn', 'Detail')][string]$Level = 'Info')
    switch ($Level) {
        'Warn'   { Write-Warning $Message }
        'Detail' { Write-Verbose $Message }
        default  { Write-Host "  $Message" }
    }
}
