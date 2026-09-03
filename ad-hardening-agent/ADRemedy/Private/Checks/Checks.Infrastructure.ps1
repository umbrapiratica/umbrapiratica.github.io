function Invoke-ADRCheckMachineAccountQuota {
    [CmdletBinding()]
    param($Context)

    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -SearchBase $Context.DefaultNC `
        -Filter '(objectClass=domain)' -Property @('distinguishedName', 'ms-DS-MachineAccountQuota'))
    $row = $rows | Where-Object { $_.distinguishedname -eq $Context.DefaultNC } | Select-Object -First 1
    if (-not $row) { return }

    $quota = [int]$row.'ms-ds-machineaccountquota'
    if ($quota -le 0) { return }

    New-ADRemedyFinding -FindingId 'ADR-DOM-001' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "ms-DS-MachineAccountQuota is $quota, so every authenticated user can create up to $quota computer accounts." `
        -Detail @{ Quota = $quota } `
        -AffectedObjects @([pscustomobject]@{ Name = $Context.DomainFQDN; Setting = 'ms-DS-MachineAccountQuota'; Value = $quota; Recommended = 0 })
}

function Invoke-ADRCheckPasswordPolicy {
    [CmdletBinding()]
    param($Context, [int]$MinimumLength = 14)

    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -SearchBase $Context.DefaultNC `
        -Filter '(objectClass=domain)' -Property @('distinguishedName', 'minPwdLength', 'lockoutThreshold', 'pwdProperties', 'maxPwdAge'))
    $row = $rows | Where-Object { $_.distinguishedname -eq $Context.DefaultNC } | Select-Object -First 1
    if (-not $row) { return }

    $minLen = [int]$row.minpwdlength
    $lockout = [int]$row.lockoutthreshold
    $complexity = [bool]([int]$row.pwdproperties -band 1)

    $issues = @()
    if ($minLen -lt $MinimumLength) { $issues += "minimum password length is $minLen (recommended $MinimumLength or more)" }
    if ($lockout -eq 0)             { $issues += 'no account lockout threshold is set, so online password spraying is unlimited' }
    if (-not $complexity)           { $issues += 'password complexity is disabled' }
    if (-not $issues) { return }

    New-ADRemedyFinding -FindingId 'ADR-DOM-002' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence ("Default domain policy: " + ($issues -join '; ') + '.') `
        -AffectedObjects @(
            [pscustomobject]@{ Setting = 'MinPasswordLength'; Value = $minLen;  Recommended = "$MinimumLength+" }
            [pscustomobject]@{ Setting = 'LockoutThreshold';  Value = $lockout; Recommended = '10 with a 15 minute window' }
            [pscustomobject]@{ Setting = 'ComplexityEnabled'; Value = $complexity; Recommended = 'True, plus a banned-password list' }
        )
}

function Invoke-ADRCheckPreWindows2000Access {
    [CmdletBinding()]
    param($Context)

    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context `
        -Filter '(&(objectClass=group)(cn=Pre-Windows 2000 Compatible Access))' -Property @('distinguishedName', 'member', 'cn'))
    if (-not $rows) { return }

    $broad = @()
    foreach ($row in $rows) {
        foreach ($dn in @($row.member)) {
            $name = ([string]$dn -split ',')[0] -replace '^CN=', ''
            if ($name -match '^(Everyone|Anonymous Logon|ANONYMOUS LOGON|NT AUTHORITY\\ANONYMOUS LOGON)$') {
                $broad += [pscustomobject]@{ Name = $name; DistinguishedName = [string]$dn }
            }
        }
    }
    if (-not $broad) { return }

    New-ADRemedyFinding -FindingId 'ADR-DOM-003' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "Pre-Windows 2000 Compatible Access contains $($broad.Count) broad identity/identities, allowing unauthenticated directory enumeration." `
        -AffectedObjects $broad
}

function Invoke-ADRCheckUnsupportedOperatingSystems {
    [CmdletBinding()]
    param($Context)

    $filter = '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter $filter -Property @(
        'distinguishedName', 'name', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp'))
    if (-not $rows) { return }

    $eolPattern = 'Windows XP|Windows Vista|Windows 7|Windows 8(?!\.1)|Windows Server 2000|Windows Server 2003|Windows Server 2008|Windows Server 2012'
    $eol = @($rows | Where-Object { [string]$_.operatingsystem -match $eolPattern })
    if (-not $eol) { return }

    New-ADRemedyFinding -FindingId 'ADR-HOST-001' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($eol.Count) enabled computer object(s) run an operating system that no longer receives security updates." `
        -AffectedObjects ($eol | Select-Object -First 200 | ForEach-Object {
            [pscustomobject]@{
                Name            = [string]$_.name
                OperatingSystem = [string]$_.operatingsystem
                Version         = [string]$_.operatingsystemversion
                LastLogon       = ConvertFrom-ADRemedyFileTime $_.lastlogontimestamp
            }
        })
}

function Invoke-ADRCheckLapsCoverage {
    [CmdletBinding()]
    param($Context, [int]$InactiveDays = 60)

    $cutoff = (Get-Date).AddDays(-$InactiveDays).ToFileTimeUtc()
    $filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp>=$cutoff))"
    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter $filter -Property @(
        'distinguishedName', 'name', 'operatingSystem', 'msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime'))
    if (-not $rows) { return }

    $missing = @($rows | Where-Object {
        -not $_.'mslaps-passwordexpirationtime' -and -not $_.'ms-mcs-admpwdexpirationtime'
    })
    if (-not $missing) { return }

    $pct = [math]::Round(($missing.Count / $rows.Count) * 100, 1)

    New-ADRemedyFinding -FindingId 'ADR-HOST-002' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($missing.Count) of $($rows.Count) active computer(s), $pct percent, have no managed local administrator password." `
        -Detail @{ MissingCount = $missing.Count; TotalCount = $rows.Count; PercentMissing = $pct } `
        -AffectedObjects ($missing | Select-Object -First 200 | ForEach-Object {
            [pscustomobject]@{
                Name            = [string]$_.name
                OperatingSystem = [string]$_.operatingsystem
            }
        })
}

function Invoke-ADRCheckCertificateTemplates {
    [CmdletBinding()]
    param($Context)

    if (-not $Context.ConfigurationNC) { return }
    $base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($Context.ConfigurationNC)"

    $rows = @(
        try {
            Invoke-ADRemedyLdapQuery -Context $Context -SearchBase $base -Filter '(objectClass=pKICertificateTemplate)' -Property @(
                'distinguishedName', 'cn', 'displayName', 'msPKI-Certificate-Name-Flag',
                'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'pKIExtendedKeyUsage')
        } catch {
            Write-Verbose "AD CS templates container not readable: $($_.Exception.Message)"
            @()
        }
    )
    if (-not $rows) { return }

    # 0x1 = ENROLLEE_SUPPLIES_SUBJECT, 0x2 (enrollment flag) = PEND_ALL_REQUESTS (manager approval)
    $clientAuthOids = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0')

    $risky = foreach ($row in $rows) {
        $nameFlag = [int64]($row.'mspki-certificate-name-flag')
        $enrollFlag = [int64]($row.'mspki-enrollment-flag')
        $raSig = [int]($row.'mspki-ra-signature')
        $ekus = @($row.'pkiextendedkeyusage')

        $suppliesSubject = ($nameFlag -band 1) -ne 0
        $managerApproval = ($enrollFlag -band 2) -ne 0
        $clientAuth = ($ekus | Where-Object { $_ -in $clientAuthOids }).Count -gt 0

        if ($suppliesSubject -and $clientAuth -and -not $managerApproval -and $raSig -le 0) {
            [pscustomobject]@{
                Name                    = [string]$row.cn
                DisplayName             = [string]$row.displayname
                EnrolleeSuppliesSubject = $true
                ManagerApproval         = $false
                ClientAuthentication    = $true
                AuthorizedSignatures    = $raSig
            }
        }
    }

    $risky = @($risky)
    if (-not $risky) { return }

    New-ADRemedyFinding -FindingId 'ADR-CERT-001' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($risky.Count) certificate template(s) allow an enrollee-supplied subject with client authentication and no approval step. Review enrolment rights on each before assuming exploitability." `
        -AffectedObjects $risky
}

function Invoke-ADRCheckTrusts {
    [CmdletBinding()]
    param($Context)

    $rows = @(Invoke-ADRemedyLdapQuery -Context $Context -Filter '(objectClass=trustedDomain)' -Property @(
        'distinguishedName', 'name', 'trustDirection', 'trustType', 'trustAttributes', 'flatName'))
    if (-not $rows) { return }

    # 0x4 QUARANTINED_DOMAIN (SID filtering on), 0x8 FOREST_TRANSITIVE, 0x40 TREAT_AS_EXTERNAL
    $weak = foreach ($row in $rows) {
        $attr = [int]$row.trustattributes
        $quarantined = ($attr -band 4) -ne 0
        $forest = ($attr -band 8) -ne 0
        $treatAsExternal = ($attr -band 64) -ne 0

        if (-not $quarantined) {
            [pscustomobject]@{
                Name            = [string]$row.name
                Direction       = switch ([int]$row.trustdirection) { 1 { 'Inbound' } 2 { 'Outbound' } 3 { 'Bidirectional' } default { 'Unknown' } }
                Type            = if ($forest) { 'Forest' } else { 'External or Parent/Child' }
                SIDFiltering    = 'Not quarantined'
                TreatAsExternal = $treatAsExternal
            }
        }
    }

    $weak = @($weak)
    if (-not $weak) { return }

    New-ADRemedyFinding -FindingId 'ADR-TRUST-001' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($weak.Count) trust(s) do not have the quarantine (SID filtering) attribute set. Intra-forest trusts are expected to appear here, since the forest is the security boundary." `
        -AffectedObjects $weak
}

function Invoke-ADRCheckSysvolPasswords {
    [CmdletBinding()]
    param($Context, [switch]$SkipSysvol)

    if ($SkipSysvol) { return }

    $domain = $Context.DomainFQDN
    $path = "\\$domain\SYSVOL\$domain\Policies"
    if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) {
        Write-Verbose "SYSVOL path '$path' not reachable, skipping GPP check."
        return
    }

    $hits = @(
        Get-ChildItem -Path $path -Recurse -Include '*.xml' -ErrorAction SilentlyContinue |
            Select-String -Pattern 'cpassword' -SimpleMatch -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Path -Unique
    )
    if (-not $hits) { return }

    New-ADRemedyFinding -FindingId 'ADR-GPO-001' -Source 'Live Audit' -Domain $Context.DomainFQDN `
        -Evidence "$($hits.Count) Group Policy Preferences file(s) in SYSVOL contain a cpassword value readable by every domain user." `
        -AffectedObjects ($hits | ForEach-Object { [pscustomobject]@{ Name = Split-Path $_ -Leaf; Path = $_ } })
}
