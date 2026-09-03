# Every function named Invoke-ADRCheck* is auto-discovered by Invoke-ADRemedyAudit.
# All of them perform read-only LDAP searches and return ADRemedy.Finding objects.

function Invoke-ADRCheckUnconstrainedDelegation {
    [CmdletBinding()]
    param($Context)

    # TRUSTED_FOR_DELEGATION (0x80000) on anything that is not a domain controller.
    # SERVER_TRUST_ACCOUNT (0x2000) identifies DCs, which are expected to carry the flag.
    $filter = '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))'
    $rows = Invoke-ADRemedyLdapQuery -Context $Context -Filter $filter -Property @(
        'distinguishedName', 'samAccountName', 'name', 'objectClass', 'operatingSystem', 'lastLogonTimestamp')

    $hits = @($rows | Where-Object { $_.distinguishedname -notmatch 'OU=Domain Controllers' })
    if (-not $hits) { return }

    New-ADRemedyFinding -FindingId 'ADR-DELEG-001' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($hits.Count) object(s) carry TRUSTED_FOR_DELEGATION outside the Domain Controllers OU." `
        -AffectedObjects ($hits | ForEach-Object {
            [pscustomobject]@{
                Name             = ConvertTo-ADRemedyName $_
                Type             = if ($_.objectclass -contains 'computer') { 'Computer' } else { 'User' }
                OperatingSystem  = [string]$_.operatingsystem
                LastLogon        = ConvertFrom-ADRemedyFileTime $_.lastlogontimestamp
                DistinguishedName = [string]$_.distinguishedname
            }
        })
}

function Invoke-ADRCheckProtocolTransition {
    [CmdletBinding()]
    param($Context)

    # TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000) = constrained delegation with protocol transition.
    $filter = '(userAccountControl:1.2.840.113556.1.4.803:=16777216)'
    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter $filter -Property @(
        'distinguishedName', 'samAccountName', 'name', 'objectClass', 'msDS-AllowedToDelegateTo'))
    if (-not $rows) { return }

    New-ADRemedyFinding -FindingId 'ADR-DELEG-002' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($rows.Count) account(s) can impersonate any user to their allowed services without that user authenticating." `
        -AffectedObjects ($rows | ForEach-Object {
            [pscustomobject]@{
                Name        = ConvertTo-ADRemedyName $_
                Type        = if ($_.objectclass -contains 'computer') { 'Computer' } else { 'User' }
                DelegatesTo = (@($_.'msds-allowedtodelegateto') -join '; ')
            }
        })
}

function Invoke-ADRCheckResourceBasedDelegation {
    [CmdletBinding()]
    param($Context)

    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Property @(
        'distinguishedName', 'samAccountName', 'name', 'objectClass'))
    if (-not $rows) { return }

    New-ADRemedyFinding -FindingId 'ADR-DELEG-003' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($rows.Count) object(s) have resource-based constrained delegation configured. Confirm each one is intentional and owned." `
        -AffectedObjects ($rows | ForEach-Object {
            [pscustomobject]@{
                Name = ConvertTo-ADRemedyName $_
                Type = if ($_.objectclass -contains 'computer') { 'Computer' } else { 'User' }
                DistinguishedName = [string]$_.distinguishedname
            }
        })
}

function Invoke-ADRCheckKerberoastablePrivileged {
    [CmdletBinding()]
    param($Context)

    $filter = '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(samAccountName=krbtgt)))'
    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter $filter -Property @(
        'distinguishedName', 'samAccountName', 'name', 'servicePrincipalName', 'adminCount',
        'pwdLastSet', 'userAccountControl', 'memberOf'))
    if (-not $rows) { return }

    $privileged = @($rows | Where-Object { [int]$_.admincount -eq 1 })
    if (-not $privileged) { return }

    New-ADRemedyFinding -FindingId 'ADR-KERB-001' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($privileged.Count) privileged account(s) have an SPN and can be roasted by any domain user. $($rows.Count) service account(s) with SPNs exist in total." `
        -Detail @{ TotalSpnAccounts = $rows.Count } `
        -AffectedObjects ($privileged | ForEach-Object {
            $pwdSet = ConvertFrom-ADRemedyFileTime $_.pwdlastset
            [pscustomobject]@{
                Name            = ConvertTo-ADRemedyName $_
                PasswordLastSet = $pwdSet
                PasswordAgeDays = if ($pwdSet) { [int]((Get-Date) - $pwdSet).TotalDays } else { $null }
                SPNs            = (@($_.serviceprincipalname) -join '; ')
            }
        })
}

function Invoke-ADRCheckAsRepRoastable {
    [CmdletBinding()]
    param($Context)

    # DONT_REQ_PREAUTH (0x400000)
    $filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter $filter -Property @(
        'distinguishedName', 'samAccountName', 'name', 'userAccountControl', 'lastLogonTimestamp', 'adminCount'))
    if (-not $rows) { return }

    New-ADRemedyFinding -FindingId 'ADR-KERB-002' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($rows.Count) account(s) do not require Kerberos pre-authentication, so crackable material can be requested without credentials." `
        -AffectedObjects ($rows | ForEach-Object {
            [pscustomobject]@{
                Name       = ConvertTo-ADRemedyName $_
                Enabled    = -not ([int]$_.useraccountcontrol -band 2)
                Privileged = ([int]$_.admincount -eq 1)
                LastLogon  = ConvertFrom-ADRemedyFileTime $_.lastlogontimestamp
            }
        })
}

function Invoke-ADRCheckKrbtgtAge {
    [CmdletBinding()]
    param($Context, [int]$MaxAgeDays = 180)

    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter '(&(objectClass=user)(samAccountName=krbtgt*))' -Property @(
        'distinguishedName', 'samAccountName', 'pwdLastSet'))
    if (-not $rows) { return }

    $stale = foreach ($row in $rows) {
        $set = ConvertFrom-ADRemedyFileTime $row.pwdlastset
        $age = if ($set) { [int]((Get-Date) - $set).TotalDays } else { $null }
        if ($null -eq $age -or $age -gt $MaxAgeDays) {
            [pscustomobject]@{
                Name            = [string]$row.samaccountname
                PasswordLastSet = $set
                AgeDays         = $age
            }
        }
    }

    $stale = @($stale)
    if (-not $stale) { return }

    New-ADRemedyFinding -FindingId 'ADR-KERB-003' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "krbtgt password age exceeds the $MaxAgeDays day threshold. Any previously stolen hash still forges valid tickets." `
        -AffectedObjects $stale
}

function Invoke-ADRCheckPrivilegedGroupSprawl {
    [CmdletBinding()]
    param(
        $Context,
        [string[]]$Groups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
            'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'DnsAdmins'),
        [int]$Threshold = 5
    )

    $members = foreach ($group in $Groups) {
        $g = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter "(&(objectClass=group)(cn=$group))" -Property @(
            'distinguishedName', 'member', 'cn'))
        foreach ($row in $g) {
            foreach ($dn in @($row.member)) {
                if (-not $dn) { continue }
                [pscustomobject]@{
                    Group             = [string]$row.cn
                    Name              = ([string]$dn -split ',')[0] -replace '^CN=', ''
                    DistinguishedName = [string]$dn
                }
            }
        }
    }

    $members = @($members)
    if (-not $members) { return }

    $sensitive = @($members | Where-Object {
        $_.Group -in @('Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators', 'DnsAdmins') })
    $tier0 = @($members | Where-Object { $_.Group -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins') })

    if ($tier0.Count -le $Threshold -and $sensitive.Count -eq 0) { return }

    $evidence = "$($tier0.Count) member(s) across Domain/Enterprise/Schema Admins"
    if ($sensitive.Count) {
        $evidence += ", plus $($sensitive.Count) member(s) in operator groups that Microsoft recommends leaving empty"
    }
    $evidence += '.'

    New-ADRemedyFinding -FindingId 'ADR-PRIV-001' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence $evidence `
        -Detail @{ Tier0Count = $tier0.Count; OperatorCount = $sensitive.Count } `
        -AffectedObjects ($members | Sort-Object Group, Name)
}

function Invoke-ADRCheckDelegatablePrivilegedAccounts {
    [CmdletBinding()]
    param($Context)

    # adminCount=1 users missing NOT_DELEGATED (0x100000)
    $filter = '(&(objectCategory=person)(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=1048576)))'
    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter $filter -Property @(
        'distinguishedName', 'samAccountName', 'memberOf', 'userAccountControl'))
    if (-not $rows) { return }

    $protectedUsers = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter '(&(objectClass=group)(cn=Protected Users))' -Property @('member'))
    $protectedDns = @()
    foreach ($g in $protectedUsers) { $protectedDns += @($g.member) }

    $exposed = @($rows | Where-Object { [string]$_.distinguishedname -notin $protectedDns })
    if (-not $exposed) { return }

    New-ADRemedyFinding -FindingId 'ADR-PRIV-002' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($exposed.Count) privileged account(s) are delegatable and not in Protected Users." `
        -AffectedObjects ($exposed | ForEach-Object {
            [pscustomobject]@{
                Name              = ConvertTo-ADRemedyName $_
                Enabled           = -not ([int]$_.useraccountcontrol -band 2)
                InProtectedUsers  = $false
                DistinguishedName = [string]$_.distinguishedname
            }
        })
}

function Invoke-ADRCheckOrphanedAdminCount {
    [CmdletBinding()]
    param($Context)

    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter '(&(adminCount=1)(objectCategory=person))' -Property @(
        'distinguishedName', 'samAccountName', 'memberOf'))
    if (-not $rows) { return }

    $protectedPattern = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators|Server Operators|Print Operators|Replicator|Key Admins|Enterprise Key Admins'

    $orphans = @($rows | Where-Object {
        $groups = (@($_.memberof) -join ';')
        $groups -notmatch $protectedPattern
    })
    if (-not $orphans) { return }

    New-ADRemedyFinding -FindingId 'ADR-PRIV-003' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($orphans.Count) account(s) still carry adminCount=1 with broken inheritance but are no longer in a protected group." `
        -AffectedObjects ($orphans | ForEach-Object {
            [pscustomobject]@{
                Name              = ConvertTo-ADRemedyName $_
                DistinguishedName = [string]$_.distinguishedname
            }
        })
}

function Invoke-ADRCheckPasswordNeverExpires {
    [CmdletBinding()]
    param($Context)

    # DONT_EXPIRE_PASSWORD (0x10000) and not ACCOUNTDISABLE (0x2)
    $filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter $filter -Property @(
        'distinguishedName', 'samAccountName', 'adminCount', 'servicePrincipalName', 'pwdLastSet'))
    if (-not $rows) { return }

    $risky = @($rows | Where-Object { [int]$_.admincount -eq 1 -or $_.serviceprincipalname })

    New-ADRemedyFinding -FindingId 'ADR-ACCT-001' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Severity $(if ($risky.Count) { 'High' } else { 'Medium' }) `
        -Evidence "$($rows.Count) enabled account(s) never expire their password; $($risky.Count) of those are privileged or carry an SPN." `
        -Detail @{ TotalCount = $rows.Count; RiskyCount = $risky.Count } `
        -AffectedObjects (($risky + ($rows | Where-Object { $_ -notin $risky })) | Select-Object -First 200 | ForEach-Object {
            $set = ConvertFrom-ADRemedyFileTime $_.pwdlastset
            [pscustomobject]@{
                Name            = ConvertTo-ADRemedyName $_
                Privileged      = ([int]$_.admincount -eq 1)
                HasSPN          = [bool]$_.serviceprincipalname
                PasswordLastSet = $set
                PasswordAgeDays = if ($set) { [int]((Get-Date) - $set).TotalDays } else { $null }
            }
        })
}

function Invoke-ADRCheckStaleAccounts {
    [CmdletBinding()]
    param($Context, [int]$InactiveDays = 90)

    $cutoff = (Get-Date).AddDays(-$InactiveDays).ToFileTimeUtc()
    $filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$cutoff))"
    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter $filter -Property @(
        'distinguishedName', 'samAccountName', 'lastLogonTimestamp', 'whenCreated', 'adminCount'))
    if (-not $rows) { return }

    New-ADRemedyFinding -FindingId 'ADR-ACCT-002' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($rows.Count) enabled account(s) have not authenticated in $InactiveDays days." `
        -Detail @{ InactiveDays = $InactiveDays } `
        -AffectedObjects ($rows | Select-Object -First 200 | ForEach-Object {
            [pscustomobject]@{
                Name       = ConvertTo-ADRemedyName $_
                LastLogon  = ConvertFrom-ADRemedyFileTime $_.lastlogontimestamp
                Privileged = ([int]$_.admincount -eq 1)
            }
        })
}

function Invoke-ADRCheckReversibleEncryption {
    [CmdletBinding()]
    param($Context)

    # ENCRYPTED_TEXT_PWD_ALLOWED (0x80)
    $filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))'
    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter $filter -Property @(
        'distinguishedName', 'samAccountName', 'userAccountControl'))
    if (-not $rows) { return }

    New-ADRemedyFinding -FindingId 'ADR-ACCT-003' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($rows.Count) account(s) store a recoverable form of their password in the directory." `
        -AffectedObjects ($rows | ForEach-Object {
            [pscustomobject]@{
                Name    = ConvertTo-ADRemedyName $_
                Enabled = -not ([int]$_.useraccountcontrol -band 2)
            }
        })
}

function Invoke-ADRCheckPasswordNotRequired {
    [CmdletBinding()]
    param($Context)

    # PASSWD_NOTREQD (0x20) on enabled accounts
    $filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter $filter -Property @(
        'distinguishedName', 'samAccountName', 'pwdLastSet'))
    if (-not $rows) { return }

    New-ADRemedyFinding -FindingId 'ADR-ACCT-004' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($rows.Count) enabled account(s) are exempt from the domain minimum password length." `
        -AffectedObjects ($rows | Select-Object -First 200 | ForEach-Object {
            [pscustomobject]@{
                Name            = ConvertTo-ADRemedyName $_
                PasswordLastSet = ConvertFrom-ADRemedyFileTime $_.pwdlastset
            }
        })
}
