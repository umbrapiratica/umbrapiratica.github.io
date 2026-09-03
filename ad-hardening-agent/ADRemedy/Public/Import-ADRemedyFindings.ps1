function Import-ADRemedyFindings {
    <#
    .SYNOPSIS
        Converts output from other AD assessment tools into ADRemedy findings with
        remediation guidance attached.

    .DESCRIPTION
        Supported inputs:
          PingCastle  - ad_hc_<domain>.xml health check report
          SharpHound  - BloodHound collection .json files or the .zip they ship in
          CSV         - any severity/finding style export, including Purple Knight

        Findings that map to a known catalog entry get the full remediation writeup.
        Anything unmapped is still returned, carrying whatever description the source
        tool provided, so nothing is silently dropped.

    .PARAMETER Path
        One or more files or directories to import.

    .PARAMETER Format
        Force a parser instead of detecting from the file contents.

    .EXAMPLE
        Import-ADRemedyFindings -Path .\ad_hc_corp.local.xml | New-ADRemedyReport -Path .\report.html

    .EXAMPLE
        Import-ADRemedyFindings -Path .\20260901_bloodhound.zip | Where-Object Severity -eq 'Critical'

    .EXAMPLE
        Get-ChildItem .\scans\ | Import-ADRemedyFindings | Sort-Object SeverityRank
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)]
        [Alias('FullName')]
        [string[]]$Path,

        [ValidateSet('Auto', 'PingCastle', 'SharpHound', 'Csv')]
        [string]$Format = 'Auto',

        [switch]$Merge,

        # BloodHound edges held by built-in tier 0 principals are expected
        # configuration, so they are filtered out unless this is set.
        [switch]$IncludeDefaultPrincipals
    )

    begin {
        $files = [System.Collections.Generic.List[string]]::new()
        $temps = [System.Collections.Generic.List[string]]::new()
    }

    process {
        foreach ($p in $Path) {
            if (-not (Test-Path -LiteralPath $p)) {
                Write-Warning "Path not found: $p"
                continue
            }
            $item = Get-Item -LiteralPath $p
            if ($item.PSIsContainer) {
                Get-ChildItem -LiteralPath $item.FullName -File -Include '*.xml', '*.json', '*.csv', '*.zip' -Recurse |
                    ForEach-Object { $files.Add($_.FullName) }
            } else {
                $files.Add($item.FullName)
            }
        }
    }

    end {
        $expanded = [System.Collections.Generic.List[string]]::new()
        foreach ($file in $files) {
            if ([System.IO.Path]::GetExtension($file) -eq '.zip') {
                $dest = Join-Path ([System.IO.Path]::GetTempPath()) ("adremedy_" + [guid]::NewGuid().ToString('N'))
                Write-Verbose "Expanding archive $file"
                try {
                    Expand-Archive -LiteralPath $file -DestinationPath $dest -Force
                    $temps.Add($dest)
                    Get-ChildItem -LiteralPath $dest -File -Recurse | ForEach-Object { $expanded.Add($_.FullName) }
                } catch {
                    Write-Warning "Could not expand '$file': $($_.Exception.Message)"
                }
            } else {
                $expanded.Add($file)
            }
        }

        $findings = [System.Collections.Generic.List[object]]::new()
        $sharpHoundRows = [System.Collections.Generic.List[object]]::new()

        foreach ($file in $expanded) {
            $ext = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
            $detected = if ($Format -ne 'Auto') {
                # A forced format only applies to files that could hold it, so pointing
                # -Format at a mixed directory does not warn about every other file.
                $expected = switch ($Format) {
                    'PingCastle' { '.xml' }
                    'SharpHound' { '.json' }
                    'Csv'        { '.csv' }
                }
                if ($ext -eq $expected) { $Format } else { 'Skip' }
            } else {
                Get-ADRemedyFileFormat -Path $file
            }
            if ($detected -eq 'Skip') { continue }

            Write-Verbose "$([System.IO.Path]::GetFileName($file)) detected as $detected"

            switch ($detected) {
                'PingCastle' {
                    foreach ($f in (ConvertFrom-ADRemedyPingCastle -Path $file)) { $findings.Add($f) }
                }
                'SharpHound' {
                    foreach ($r in (Read-ADRemedySharpHound -Path $file)) { $sharpHoundRows.Add($r) }
                }
                'Csv' {
                    foreach ($f in (ConvertFrom-ADRemedyCsv -Path $file)) { $findings.Add($f) }
                }
                default { Write-Verbose "Skipping unrecognised file: $file" }
            }
        }

        if ($sharpHoundRows.Count) {
            $shSplat = @{ Row = $sharpHoundRows; IncludeDefaultPrincipals = $IncludeDefaultPrincipals }
            foreach ($f in (ConvertFrom-ADRemedySharpHound @shSplat)) { $findings.Add($f) }
        }

        foreach ($temp in $temps) {
            Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
        }

        $output = if ($Merge) { Merge-ADRemedyFinding -Finding $findings } else { $findings }
        $output | Sort-Object SeverityRank, Category, Title
    }
}

function Merge-ADRemedyFinding {
    <#
    .SYNOPSIS
        Consolidates findings that share a finding ID, as happens when two tools
        report the same weakness. Keeps the worst severity, unions the affected
        objects by name, and records every contributing source.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    foreach ($group in ($Finding | Group-Object FindingId)) {
        if ($group.Count -eq 1) { $group.Group[0]; continue }

        $items = @($group.Group | Sort-Object SeverityRank)
        $best = $items[0]

        # One tool reports APPSRV01, another APPSRV01.CORP.LOCAL. Key on the short
        # name so they collapse, and keep whichever record carries more detail.
        $byKey = [ordered]@{}
        $fieldCount = {
            param($o)
            if ($o -isnot [psobject]) { return 0 }
            @($o.PSObject.Properties | Where-Object { $null -ne $_.Value -and "$($_.Value)".Trim() }).Count
        }

        foreach ($item in $items) {
            foreach ($o in @($item.AffectedObjects)) {
                if (-not $o) { continue }
                $name = if ($o -is [psobject] -and $o.PSObject.Properties['Name']) { [string]$o.Name } else { [string]$o }
                $key = if ($name) { (($name -split '\.')[0]).ToLowerInvariant() } else { [guid]::NewGuid().ToString() }

                if (-not $byKey.Contains($key)) {
                    $byKey[$key] = $o
                } elseif ((& $fieldCount $o) -gt (& $fieldCount $byKey[$key])) {
                    $byKey[$key] = $o
                }
            }
        }
        $objects = [System.Collections.Generic.List[object]]::new()
        foreach ($v in $byKey.Values) { $objects.Add($v) }

        $sources = @($items.Source | Where-Object { $_ } | Select-Object -Unique)
        $evidence = (@($items | Where-Object { $_.Evidence } | ForEach-Object { "$($_.Source): $($_.Evidence)" }) -join '  |  ')

        $merged = $best.PSObject.Copy()
        $merged.Source = ($sources -join ' + ')
        $merged.Evidence = $evidence
        $merged.AffectedObjects = $objects.ToArray()
        $merged.AffectedCount = $objects.Count
        $merged
    }
}

function Get-ADRemedyFileFormat {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $head = ''
    try { $head = (Get-Content -LiteralPath $Path -TotalCount 40 -ErrorAction Stop) -join "`n" } catch { return 'Unknown' }

    switch ($ext) {
        '.xml'  { if ($head -match 'HealthcheckData|PingCastle') { return 'PingCastle' } else { return 'Unknown' } }
        '.json' { if ($head -match '"meta"|"data"|ObjectIdentifier|Properties') { return 'SharpHound' } else { return 'Unknown' } }
        '.csv'  { return 'Csv' }
        default { return 'Unknown' }
    }
}

function ConvertFrom-ADRemedyPingCastle {
    <#
    .SYNOPSIS
        Maps PingCastle risk rules onto catalog entries where they overlap.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try {
        [xml]$xml = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    } catch {
        Write-Warning "Could not parse '$Path' as XML: $($_.Exception.Message)"
        return
    }

    $domain = [string]$xml.HealthcheckData.DomainFQDN
    $rules = @($xml.HealthcheckData.RiskRules.HealthcheckRiskRule)
    if (-not $rules) {
        Write-Warning "No risk rules found in '$Path'."
        return
    }

    $map = Get-ADRemedySourceMap -Source 'PingCastle'

    foreach ($rule in $rules) {
        $riskId = [string]$rule.RiskId
        $rationale = [string]$rule.Rationale
        $points = [int]$rule.Points

        $findingId = $null
        foreach ($pattern in $map.Keys) {
            if ($riskId -like $pattern) { $findingId = $map[$pattern]; break }
        }

        if ($findingId) {
            New-ADRemedyFinding -FindingId $findingId -Source 'PingCastle' -Domain $domain `
                -Evidence "PingCastle rule $riskId ($points points): $rationale" `
                -Detail @{ SourceRuleId = $riskId; Points = $points }
        } else {
            $severity = if ($points -ge 30) { 'High' } elseif ($points -ge 10) { 'Medium' } else { 'Low' }
            New-ADRemedyFinding -FindingId $riskId -Source 'PingCastle' -Domain $domain `
                -Title $riskId -Severity $severity -Category ([string]$rule.Category) `
                -Evidence $rationale -Detail @{ SourceRuleId = $riskId; Points = $points }
        }
    }
}

function Read-ADRemedySharpHound {
    <#
    .SYNOPSIS
        Reads a SharpHound collection file and flattens the objects it contains.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try {
        $json = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        Write-Warning "Could not parse '$Path' as JSON: $($_.Exception.Message)"
        return
    }

    $type = if ($json.meta -and $json.meta.type) { [string]$json.meta.type } else { 'unknown' }
    foreach ($obj in @($json.data)) {
        [pscustomobject]@{
            CollectionType = $type
            Object         = $obj
        }
    }
}

function ConvertFrom-ADRemedySharpHound {
    <#
    .SYNOPSIS
        Turns SharpHound object properties into the same findings the live audit produces.
    .DESCRIPTION
        Reads only the property flags SharpHound already collected. It does not compute
        attack paths; use BloodHound itself for that, then bring the finding types here
        for remediation guidance.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Row,
        [switch]$IncludeDefaultPrincipals
    )

    $domain = ($Row | ForEach-Object { $_.Object.Properties.domain } | Where-Object { $_ } | Select-Object -First 1)
    $prop = { param($o) $o.Object.Properties }

    $named = {
        param($o)
        $p = $o.Object.Properties
        if ($p.name) { [string]$p.name } elseif ($p.distinguishedname) { [string]$p.distinguishedname } else { [string]$o.Object.ObjectIdentifier }
    }

    # Unconstrained delegation
    $unconstrained = @($Row | Where-Object {
        $_.Object.Properties.unconstraineddelegation -eq $true -and $_.CollectionType -ne 'domains'
    })
    if ($unconstrained) {
        New-ADRemedyFinding -FindingId 'ADR-DELEG-001' -Source 'SharpHound' -Domain $domain `
            -Evidence "$($unconstrained.Count) object(s) in the collection have unconstraineddelegation set to true." `
            -AffectedObjects ($unconstrained | ForEach-Object {
                [pscustomobject]@{
                    Name = & $named $_
                    Type = $_.CollectionType
                    OperatingSystem = [string]$_.Object.Properties.operatingsystem
                }
            })
    }

    # AS-REP roastable
    $asrep = @($Row | Where-Object { $_.Object.Properties.dontreqpreauth -eq $true })
    if ($asrep) {
        New-ADRemedyFinding -FindingId 'ADR-KERB-002' -Source 'SharpHound' -Domain $domain `
            -Evidence "$($asrep.Count) account(s) have dontreqpreauth set to true." `
            -AffectedObjects ($asrep | ForEach-Object {
                [pscustomobject]@{
                    Name       = & $named $_
                    Enabled    = [bool]$_.Object.Properties.enabled
                    Privileged = [bool]$_.Object.Properties.admincount
                }
            })
    }

    # Kerberoastable privileged accounts
    $roastable = @($Row | Where-Object {
        $_.Object.Properties.hasspn -eq $true -and $_.Object.Properties.admincount -eq $true
    })
    if ($roastable) {
        New-ADRemedyFinding -FindingId 'ADR-KERB-001' -Source 'SharpHound' -Domain $domain `
            -Evidence "$($roastable.Count) privileged account(s) have an SPN registered." `
            -AffectedObjects ($roastable | ForEach-Object {
                [pscustomobject]@{
                    Name           = & $named $_
                    ServicePrincipalNames = (@($_.Object.Properties.serviceprincipalnames) -join '; ')
                }
            })
    }

    # Password never expires
    $neverExpires = @($Row | Where-Object {
        $_.Object.Properties.pwdneverexpires -eq $true -and $_.Object.Properties.enabled -eq $true
    })
    if ($neverExpires) {
        New-ADRemedyFinding -FindingId 'ADR-ACCT-001' -Source 'SharpHound' -Domain $domain `
            -Evidence "$($neverExpires.Count) enabled account(s) have pwdneverexpires set to true." `
            -AffectedObjects ($neverExpires | Select-Object -First 200 | ForEach-Object {
                [pscustomobject]@{
                    Name       = & $named $_
                    Privileged = [bool]$_.Object.Properties.admincount
                    HasSPN     = [bool]$_.Object.Properties.hasspn
                }
            })
    }

    # Password not required
    $notRequired = @($Row | Where-Object { $_.Object.Properties.passwordnotreqd -eq $true })
    if ($notRequired) {
        New-ADRemedyFinding -FindingId 'ADR-ACCT-004' -Source 'SharpHound' -Domain $domain `
            -Evidence "$($notRequired.Count) account(s) have passwordnotreqd set to true." `
            -AffectedObjects ($notRequired | ForEach-Object { [pscustomobject]@{ Name = & $named $_ } })
    }

    # Unsupported operating systems
    $eolPattern = 'Windows XP|Windows Vista|Windows 7|Windows Server 2000|Windows Server 2003|Windows Server 2008|Windows Server 2012'
    $eol = @($Row | Where-Object {
        $_.CollectionType -eq 'computers' -and [string]$_.Object.Properties.operatingsystem -match $eolPattern
    })
    if ($eol) {
        New-ADRemedyFinding -FindingId 'ADR-HOST-001' -Source 'SharpHound' -Domain $domain `
            -Evidence "$($eol.Count) computer(s) report an end-of-life operating system." `
            -AffectedObjects ($eol | ForEach-Object {
                [pscustomobject]@{
                    Name            = & $named $_
                    OperatingSystem = [string]$_.Object.Properties.operatingsystem
                    Enabled         = [bool]$_.Object.Properties.enabled
                }
            })
    }

    # Machine account quota from the domain object
    $domainObjects = @($Row | Where-Object { $_.CollectionType -eq 'domains' })
    foreach ($d in $domainObjects) {
        $quota = $d.Object.Properties.machineaccountquota
        if ($null -ne $quota -and [int]$quota -gt 0) {
            New-ADRemedyFinding -FindingId 'ADR-DOM-001' -Source 'SharpHound' -Domain ([string]$d.Object.Properties.name) `
                -Evidence "machineaccountquota is $quota in the collected domain object." `
                -AffectedObjects @([pscustomobject]@{
                    Name = [string]$d.Object.Properties.name; Setting = 'MachineAccountQuota'; Value = $quota; Recommended = 0 })
        }
    }

    # Edges: ACEs, local group membership, sessions, SID history
    ConvertFrom-ADRemedySharpHoundEdge -Row $Row -Domain $domain -IncludeDefaultPrincipals:$IncludeDefaultPrincipals
}

function ConvertFrom-ADRemedySharpHoundEdge {
    <#
    .SYNOPSIS
        Turns the ACE, local group, session, and SID history data in a SharpHound
        collection into findings, grouped by BloodHound edge type.
    .DESCRIPTION
        BloodHound shows you the path. This maps each edge on that path to the
        remediation for it, which is the part the graph does not give you.

        Edges held by built-in tier 0 principals are filtered out by default,
        because Domain Admins holding GenericAll everywhere is the design, not a
        finding. Use -IncludeDefaultPrincipals to see them anyway.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Row,
        [string]$Domain,
        [switch]$IncludeDefaultPrincipals
    )

    # SID to name index, so edges read as names rather than raw identifiers.
    $index = @{}
    foreach ($item in $Row) {
        $sid = [string]$item.Object.ObjectIdentifier
        if (-not $sid) { continue }
        $name = [string]$item.Object.Properties.name
        if (-not $name) { $name = [string]$item.Object.Properties.distinguishedname }
        if ($name) { $index[$sid] = $name }
    }

    $resolve = {
        param([string]$Sid)
        if ($Sid -and $index.ContainsKey($Sid)) { return $index[$Sid] }
        if ($Sid -eq 'S-1-5-32-544') { return 'BUILTIN\Administrators' }
        if ($Sid -eq 'S-1-5-18') { return 'NT AUTHORITY\SYSTEM' }
        return $Sid
    }

    $typeOf = {
        param($Item)
        switch ($Item.CollectionType) {
            'users'     { 'User' }
            'computers' { 'Computer' }
            'groups'    { 'Group' }
            'domains'   { 'Domain' }
            'gpos'      { 'GPO' }
            'ous'       { 'OU' }
            'containers' { 'Container' }
            default     { 'Object' }
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()

    # --- ACE derived edges ---------------------------------------------
    foreach ($item in $Row) {
        $targetName = & $resolve ([string]$item.Object.ObjectIdentifier)
        if (-not $targetName) { $targetName = [string]$item.Object.Properties.name }
        $targetType = & $typeOf $item

        foreach ($ace in @($item.Object.Aces)) {
            if (-not $ace) { continue }
            $right = [string]$ace.RightName
            if (-not $right) { continue }
            if ($right.ToLowerInvariant() -in $script:ADRemedyIgnoredEdges) { continue }

            $principalSid = [string]$ace.PrincipalSID
            $principalName = & $resolve $principalSid

            if (-not $IncludeDefaultPrincipals -and (Test-ADRemedyDefaultPrincipal -Sid $principalSid -Name $principalName)) { continue }

            $findingId = Resolve-ADRemedyEdge -Edge $right
            if (-not $findingId) {
                Write-Verbose "No catalog entry for edge '$right', skipping."
                continue
            }

            # Full control over a GPO is a GPO problem, not a generic object one:
            # the abuse is code execution on everything in the policy's scope, and
            # the fix is GPO permissions rather than an object ACE.
            if ($targetType -eq 'GPO' -and $right -in 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns') {
                $findingId = 'ADR-ACL-013'
            }

            $rows.Add([pscustomobject]@{
                FindingId = $findingId
                Edge      = $right
                Principal = $principalName
                Target    = $targetName
                TargetType = $targetType
                Inherited = [bool]$ace.IsInherited
            })
        }
    }

    # --- computer collection edges -------------------------------------
    $localGroups = @{
        'LocalAdmins'         = @{ Id = 'ADR-PATH-001'; Edge = 'AdminTo' }
        'RemoteDesktopUsers'  = @{ Id = 'ADR-PATH-003'; Edge = 'CanRDP' }
        'PSRemoteUsers'       = @{ Id = 'ADR-PATH-003'; Edge = 'CanPSRemote' }
        'DcomUsers'           = @{ Id = 'ADR-PATH-003'; Edge = 'ExecuteDCOM' }
    }

    foreach ($item in ($Row | Where-Object { $_.CollectionType -eq 'computers' })) {
        $computer = & $resolve ([string]$item.Object.ObjectIdentifier)

        foreach ($property in $localGroups.Keys) {
            $collection = $item.Object.$property
            if (-not $collection) { continue }
            foreach ($member in @($collection.Results)) {
                if (-not $member) { continue }
                $sid = [string]$member.ObjectIdentifier
                $name = & $resolve $sid
                if (-not $IncludeDefaultPrincipals -and (Test-ADRemedyDefaultPrincipal -Sid $sid -Name $name)) { continue }

                $rows.Add([pscustomobject]@{
                    FindingId  = $localGroups[$property].Id
                    Edge       = $localGroups[$property].Edge
                    Principal  = $name
                    Target     = $computer
                    TargetType = 'Computer'
                    Inherited  = $false
                })
            }
        }

        foreach ($session in @($item.Object.Sessions.Results)) {
            if (-not $session) { continue }
            $userSid = [string]$session.UserSID
            $userName = & $resolve $userSid
            $rows.Add([pscustomobject]@{
                FindingId  = 'ADR-PATH-002'
                Edge       = 'HasSession'
                Principal  = $userName
                Target     = $computer
                TargetType = 'Computer'
                Inherited  = $false
            })
        }
    }

    # --- SID history ----------------------------------------------------
    foreach ($item in $Row) {
        foreach ($sid in @($item.Object.Properties.sidhistory)) {
            if (-not $sid) { continue }
            $rows.Add([pscustomobject]@{
                FindingId  = 'ADR-PATH-005'
                Edge       = 'HasSIDHistory'
                Principal  = (& $resolve ([string]$item.Object.ObjectIdentifier))
                Target     = (& $resolve ([string]$sid))
                TargetType = 'Historical SID'
                Inherited  = $false
            })
        }
    }

    if (-not $rows.Count) { return }

    foreach ($group in ($rows | Group-Object FindingId)) {
        $objects = @($group.Group | Select-Object Edge, Principal, Target, TargetType, Inherited |
            Sort-Object Edge, Principal, Target -Unique)

        $catalog = Get-ADRemedyCatalog
        $base = if ($catalog.Contains($group.Name)) { $catalog[$group.Name].severity } else { 'High' }
        $severity = Get-ADRemedyEdgeSeverity -BaseSeverity $base -AffectedObject $objects

        $edgeNames = @($objects.Edge | Select-Object -Unique | Sort-Object) -join ', '
        $principals = @($objects.Principal | Select-Object -Unique).Count

        New-ADRemedyFinding -FindingId $group.Name -Source 'SharpHound' -Domain $Domain -Severity $severity `
            -Evidence "$($objects.Count) $edgeNames edge(s) held by $principals distinct principal(s)." `
            -Detail @{ Edges = $edgeNames; PrincipalCount = $principals } `
            -AffectedObjects $objects
    }
}

function ConvertFrom-ADRemedyCsv {
    <#
    .SYNOPSIS
        Imports a generic finding CSV, such as a Purple Knight indicator export.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try {
        $rows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
    } catch {
        Write-Warning "Could not parse '$Path' as CSV: $($_.Exception.Message)"
        return
    }
    if (-not $rows) { return }

    $columns = $rows[0].PSObject.Properties.Name
    $pick = {
        param($row, [string[]]$candidates)
        foreach ($c in $candidates) {
            $match = $columns | Where-Object { $_ -replace '[^a-z]', '' -eq ($c -replace '[^a-z]', '') } | Select-Object -First 1
            if ($match -and $row.$match) { return [string]$row.$match }
        }
        return $null
    }

    $map = Get-ADRemedySourceMap -Source 'Keyword'

    foreach ($row in $rows) {
        $title = & $pick $row @('indicatorname', 'indicator', 'finding', 'title', 'name', 'rule')
        if (-not $title) { continue }

        $severity = & $pick $row @('severity', 'risklevel', 'criticality', 'priority')
        $desc = & $pick $row @('description', 'details', 'rationale', 'summary')
        $objects = & $pick $row @('affectedobjects', 'objects', 'entities', 'impacted')
        $domain = & $pick $row @('domain', 'forest', 'target')

        $normalizedSeverity = switch -Regex ([string]$severity) {
            '(?i)crit'          { 'Critical'; break }
            '(?i)high'          { 'High'; break }
            '(?i)med|moderate'  { 'Medium'; break }
            '(?i)low|info'      { 'Low'; break }
            default             { 'Medium' }
        }

        $findingId = $null
        foreach ($keyword in $map.Keys) {
            if ($title -match $keyword) { $findingId = $map[$keyword]; break }
        }

        $affected = if ($objects) {
            @($objects -split '[;,|]' | Where-Object { $_.Trim() } | ForEach-Object { [pscustomobject]@{ Name = $_.Trim() } })
        } else { @() }

        if ($findingId) {
            New-ADRemedyFinding -FindingId $findingId -Source 'CSV Import' -Domain $domain `
                -Evidence "Imported finding '$title': $desc" -AffectedObjects $affected
        } else {
            New-ADRemedyFinding -FindingId ("IMPORT-" + ($title -replace '[^A-Za-z0-9]', '').Substring(0, [Math]::Min(24, ($title -replace '[^A-Za-z0-9]', '').Length))) `
                -Source 'CSV Import' -Domain $domain -Title $title -Severity $normalizedSeverity `
                -Category 'Imported' -Evidence $desc -AffectedObjects $affected
        }
    }
}

function Get-ADRemedySourceMap {
    <#
    .SYNOPSIS
        Maps external tool rule identifiers and keywords onto catalog finding IDs.
    #>
    [CmdletBinding()]
    param([ValidateSet('PingCastle', 'Keyword')][string]$Source)

    switch ($Source) {
        'PingCastle' {
            [ordered]@{
                'A-Krbtgt*'                = 'ADR-KERB-003'
                'A-PreWin2000*'            = 'ADR-DOM-003'
                'S-DsHeuristics*'          = 'ADR-DOM-003'
                'A-DsHeuristics*'          = 'ADR-DOM-003'
                'S-PwdNeverExpires*'       = 'ADR-ACCT-001'
                'S-Inactive*'              = 'ADR-ACCT-002'
                'S-DC-Inactive*'           = 'ADR-ACCT-002'
                'A-MinPwdLen*'             = 'ADR-DOM-002'
                'A-LockoutThreshold*'      = 'ADR-DOM-002'
                'A-DCLdapSign*'            = 'ADR-DOM-003'
                'A-UnconstrainedDelegation*' = 'ADR-DELEG-001'
                'A-Delegation*'            = 'ADR-DELEG-002'
                'A-SmartCardPwdRotation*'  = 'ADR-ACCT-001'
                'A-NoServicePolicy*'       = 'ADR-ACCT-001'
                'A-ReversiblePwd*'         = 'ADR-ACCT-003'
                'P-Delegated*'             = 'ADR-PRIV-002'
                'P-AdminNum*'              = 'ADR-PRIV-001'
                'P-ServiceDomainAdmin*'    = 'ADR-KERB-001'
                'P-Kerberoasting*'         = 'ADR-KERB-001'
                'P-ProtectedUsers*'        = 'ADR-PRIV-002'
                'P-AdminLogin*'            = 'ADR-PRIV-001'
                'P-RecycleBin*'            = $null
                'S-PwdNotRequired*'        = 'ADR-ACCT-004'
                'S-DesEnabled*'            = 'ADR-KERB-001'
                'S-OS-*'                   = 'ADR-HOST-001'
                'S-ADRegistration*'        = 'ADR-DOM-001'
                'S-C-PrimaryGroup*'        = 'ADR-PRIV-003'
                'A-LAPS*'                  = 'ADR-HOST-002'
                'A-CertTempCustomSubject*' = 'ADR-CERT-001'
                'A-CertTempAnyone*'        = 'ADR-CERT-001'
                'A-CertTempAgent*'         = 'ADR-CERT-001'
                'T-SIDFiltering*'          = 'ADR-TRUST-001'
                'T-SIDHistory*'            = 'ADR-TRUST-001'
                'A-SysvolPassword*'        = 'ADR-GPO-001'
                'A-PwdGPO*'                = 'ADR-GPO-001'
            }
        }
        'Keyword' {
            [ordered]@{
                '(?i)unconstrained.*delegation'      = 'ADR-DELEG-001'
                '(?i)protocol transition|constrained delegation' = 'ADR-DELEG-002'
                '(?i)resource.based.*delegation'     = 'ADR-DELEG-003'
                '(?i)kerberoast|spn.*privileged|privileged.*spn' = 'ADR-KERB-001'
                '(?i)as.?rep|pre.?authentication'    = 'ADR-KERB-002'
                '(?i)krbtgt'                         = 'ADR-KERB-003'
                '(?i)privileged group|domain admin'  = 'ADR-PRIV-001'
                '(?i)protected users|not delegated'  = 'ADR-PRIV-002'
                '(?i)admincount|adminsdholder'       = 'ADR-PRIV-003'
                '(?i)password.*never expire'         = 'ADR-ACCT-001'
                '(?i)stale|inactive|dormant'         = 'ADR-ACCT-002'
                '(?i)reversible'                     = 'ADR-ACCT-003'
                '(?i)password not required|passwd_notreqd' = 'ADR-ACCT-004'
                '(?i)machine ?account ?quota'        = 'ADR-DOM-001'
                '(?i)password polic|lockout|password length|minimum password' = 'ADR-DOM-002'
                '(?i)pre.?windows ?2000|anonymous'   = 'ADR-DOM-003'
                '(?i)unsupported|end.of.life|obsolete os' = 'ADR-HOST-001'
                '(?i)laps|local admin.*password'     = 'ADR-HOST-002'
                '(?i)certificate template|esc1|adcs' = 'ADR-CERT-001'
                '(?i)sid ?filter|sid ?history|trust' = 'ADR-TRUST-001'
                '(?i)cpassword|group policy preference|sysvol' = 'ADR-GPO-001'
            }
        }
    }
}
