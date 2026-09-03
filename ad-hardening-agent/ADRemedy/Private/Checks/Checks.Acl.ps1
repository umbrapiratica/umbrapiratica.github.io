# Live DACL review. Scoped deliberately to tier 0 objects rather than the whole
# directory: a full domain ACL walk is slow, and the findings that matter are the
# ones pointing at objects that already confer privilege.

$script:ADRemedyRightGuids = @{
    'DS-Replication-Get-Changes'               = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-All'           = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
    'User-Force-Change-Password'               = '00299570-246d-11d0-a768-00aa006e0529'
    'Member'                                   = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    'msDS-KeyCredentialLink'                   = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
    'servicePrincipalName'                     = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
    'msDS-AllowedToActOnBehalfOfOtherIdentity' = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
    'GP-Link'                                  = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
}

function Get-ADRemedyAceEdge {
    <#
    .SYNOPSIS
        Names the BloodHound edge an access rule corresponds to, or nothing if the
        rule is not one of the abusable ones.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Rule)

    if ($Rule.AccessControlType -ne 'Allow') { return }

    $rights = [string]$Rule.ActiveDirectoryRights
    $objectType = [string]$Rule.ObjectType

    if ($rights -match 'GenericAll')  { return 'GenericAll' }
    if ($rights -match 'WriteDacl')   { return 'WriteDacl' }
    if ($rights -match 'WriteOwner')  { return 'WriteOwner' }

    if ($rights -match 'ExtendedRight') {
        switch ($objectType) {
            $script:ADRemedyRightGuids['DS-Replication-Get-Changes']     { return 'GetChanges' }
            $script:ADRemedyRightGuids['DS-Replication-Get-Changes-All'] { return 'GetChangesAll' }
            $script:ADRemedyRightGuids['DS-Replication-Get-Changes-In-Filtered-Set'] { return 'GetChangesInFilteredSet' }
            $script:ADRemedyRightGuids['User-Force-Change-Password']     { return 'ForceChangePassword' }
            '00000000-0000-0000-0000-000000000000'                       { return 'AllExtendedRights' }
        }
        return
    }

    if ($rights -match 'WriteProperty|GenericWrite') {
        switch ($objectType) {
            $script:ADRemedyRightGuids['Member']                   { return 'AddMember' }
            $script:ADRemedyRightGuids['msDS-KeyCredentialLink']   { return 'AddKeyCredentialLink' }
            $script:ADRemedyRightGuids['servicePrincipalName']     { return 'WriteSPN' }
            $script:ADRemedyRightGuids['msDS-AllowedToActOnBehalfOfOtherIdentity'] { return 'AddAllowedToAct' }
            $script:ADRemedyRightGuids['GP-Link']                  { return 'WriteGPLink' }
            '00000000-0000-0000-0000-000000000000'                 { return 'GenericWrite' }
        }
        return
    }

    if ($rights -match 'Self' -and $objectType -eq $script:ADRemedyRightGuids['Member']) { return 'AddSelf' }
    return
}

function Invoke-ADRCheckTier0Acl {
    <#
    .SYNOPSIS
        Reviews the DACL on tier 0 objects for rights held by principals that are
        not themselves tier 0. These are the same edges BloodHound draws.
    #>
    [CmdletBinding()]
    param($Context, [switch]$IncludeDefaultPrincipals)

    $targets = [System.Collections.Generic.List[object]]::new()

    $targets.Add([pscustomobject]@{ Name = $Context.DomainFQDN; DN = $Context.DefaultNC; Type = 'Domain' })
    $targets.Add([pscustomobject]@{
        Name = 'AdminSDHolder'; DN = "CN=AdminSDHolder,CN=System,$($Context.DefaultNC)"; Type = 'Container' })

    $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Account Operators', 'Backup Operators', 'Server Operators', 'DnsAdmins', 'Key Admins')
    foreach ($group in $privilegedGroups) {
        foreach ($row in (Invoke-ADRemedyLdapQuery -Context $Context -Filter "(&(objectClass=group)(cn=$group))" -Property @('distinguishedName', 'cn'))) {
            $targets.Add([pscustomobject]@{ Name = [string]$row.cn; DN = [string]$row.distinguishedname; Type = 'Group' })
        }
    }

    foreach ($row in (Invoke-ADRemedyLdapQuery -Context $Context -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' -Property @('distinguishedName', 'name'))) {
        $targets.Add([pscustomobject]@{ Name = [string]$row.name; DN = [string]$row.distinguishedname; Type = 'Domain Controller' })
    }

    foreach ($row in (Invoke-ADRemedyLdapQuery -Context $Context -Filter '(&(objectClass=user)(samAccountName=krbtgt))' -Property @('distinguishedName', 'samAccountName'))) {
        $targets.Add([pscustomobject]@{ Name = 'krbtgt'; DN = [string]$row.distinguishedname; Type = 'User' })
    }

    $rows = [System.Collections.Generic.List[object]]::new()

    foreach ($target in $targets) {
        $entry = $null
        try {
            $entry = New-ADRemedyDirectoryEntry -Context $Context -DistinguishedName $target.DN
            $security = $entry.ObjectSecurity
            if (-not $security) { continue }

            foreach ($rule in $security.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
                $edge = Get-ADRemedyAceEdge -Rule $rule
                if (-not $edge) { continue }

                $principal = [string]$rule.IdentityReference
                if (-not $IncludeDefaultPrincipals -and (Test-ADRemedyDefaultPrincipal -Name $principal)) { continue }

                $findingId = Resolve-ADRemedyEdge -Edge $edge
                if (-not $findingId) { continue }

                $rows.Add([pscustomobject]@{
                    FindingId  = $findingId
                    Edge       = $edge
                    Principal  = $principal
                    Target     = $target.Name
                    TargetType = $target.Type
                    Inherited  = [bool]$rule.IsInherited
                })
            }
        } catch {
            Write-Verbose "Could not read the security descriptor on '$($target.DN)': $($_.Exception.Message)"
        } finally {
            if ($entry) { $entry.Dispose() }
        }
    }

    if (-not $rows.Count) { return }

    foreach ($group in ($rows | Group-Object FindingId)) {
        $objects = @($group.Group | Select-Object Edge, Principal, Target, TargetType, Inherited |
            Sort-Object Edge, Principal, Target -Unique)
        $principals = @($objects.Principal | Select-Object -Unique).Count
        $edges = @($objects.Edge | Select-Object -Unique | Sort-Object) -join ', '

        New-ADRemedyFinding -FindingId $group.Name -Source 'Live Audit' -Domain $Context.DomainFQDN -Severity 'Critical' `
            -Evidence "$($objects.Count) $edges right(s) over tier 0 objects held by $principals principal(s) outside the built-in administrative groups." `
            -Detail @{ Edges = $edges; PrincipalCount = $principals } `
            -AffectedObjects $objects
    }
}
