<#
.SYNOPSIS
    Automated Microsoft-365 Business Email Compromise (BEC) incident-response runbook.
    Multi-tenant aware: you specify the target TenantId at connect time.

.DESCRIPTION
    Automates the Microsoft-only portions of the "Email Compromised - Steps to take" KB.
    Non-Microsoft steps (ProZone, MyPortal, Modus, KACE, SFTP) are intentionally out of scope.

    The script runs in two phases:
       INVESTIGATE  (default, read-only)  -> collects evidence for the CS-#### case folder
                                             and prints a TRIAGE SUMMARY (also TRIAGE_SUMMARY.txt)
       REMEDIATE    (-Remediate switch)   -> resets the password twice (final password
                                             printed to the terminal) and revokes all
                                             sessions / signs the user out everywhere.
                                             Forwarding and inbox rules are NOT changed;
                                             they are reported in the triage summary.

    Every containment action honors -WhatIf / -Confirm (SupportsShouldProcess).
    Evidence collection and packaging deliberately opt OUT of -WhatIf so that a
    -WhatIf dry run still produces a full evidence set.

    CONNECTION IS FAIL-CLOSED. Both Graph and Exchange must connect and report a
    usable context, or the script aborts before touching any evidence. After
    connecting, BOTH resolved identities are displayed and confirmed.

    THREE OUTCOMES ARE KEPT DISTINCT for every collector:
       COLLECTED     - data was returned and saved
       EMPTY         - the query succeeded and there was genuinely nothing
       NOT COLLECTED - the query FAILED (permissions, licence, service error)
    A NOT COLLECTED result is never reported as "no data". See NOT_COLLECTED.txt.

.REQUIREMENTS
    PowerShell 5.1+ or 7.x
    Modules:  Microsoft.Graph  (Users, Identity.SignIns, Reports, DirectoryManagement, Applications)
              ExchangeOnlineManagement 3.x
    App/Delegated permissions (Graph):
              User.ReadWrite.All, Directory.Read.All, AuditLog.Read.All,
              Device.Read.All, Application.Read.All, Policy.Read.All,
              UserAuthenticationMethod.Read.All, Reports.Read.All
    Licensing: Entra ID P1 or P2 is required for sign-in log retrieval.
    Purview:   Search-UnifiedAuditLog requires the "Audit Logs" or
               "View-Only Audit Logs" role IN THE TARGET TENANT.

    AUTHENTICATION - PARAMETER NAMES ARE DETECTED AT RUNTIME (round 10):
      Auth switch names differ across module builds and have caused repeated
      hard failures in this script's history (-Device, -LoginHint, and
      -UseDeviceAuthentication were all wrong for the installed versions).
      Nothing auth-related is hardcoded any more: the script inspects
      (Get-Command X).Parameters.Keys and adapts, warning instead of dying
      when a capability is absent.

      Confirmed absent on the reference build (Graph SDK / EXO 3.10.0):
        Connect-MgGraph          : NO login-hint parameter of any name.
                                   Device code switch is -UseDeviceCode.
        Connect-ExchangeOnline   : NO device-code parameter of any name.
                                   WAM opt-out switch is -DisableWAM.

      Graph and Exchange auth are INDEPENDENT:
        - WAM crashes on EXO           -> add -DisableWam
        - WebView2 dialog fails on EXO -> install the WebView2 Evergreen Runtime
        - Graph browser inconvenient   -> add -UseDeviceCode (no EXO effect)

    EXO TENANT CHECK (round 12):
      Get-ConnectionInformation only populates .Organization for app-only or
      GDAP connections; on an interactive admin sign-in it is empty. The
      fail-closed check now keys on .TenantID (always populated), resolves a
      friendly name via Get-OrganizationConfig, and cross-checks the EXO
      tenant against the Graph tenant before evidence collection.

    MSAL ASSEMBLY CONFLICT (round 11):
      ExchangeOnlineManagement and the Graph SDK each ship their own
      Microsoft.Identity.Client. Under .NET Framework (Windows PowerShell 5.1)
      only ONE version loads per process, so whichever module initialises MSAL
      second can throw NullReferenceException from RuntimeBroker..ctor (or
      MissingMethodException). msgraph-sdk-powershell issue #3576.
      Handled here by: explicit Import-Module ordering, a -GraphFirst switch to
      flip the connect order, and a one-shot non-broker retry per leg.

.PARAMETER TenantId
    GUID or *.onmicrosoft.com of the tenant to connect to (multi-tenant selector).
    NOTE: -PartnerDelegated (GDAP/CSP) requires the DOMAIN form, not the GUID.

.PARAMETER UserPrincipalName
    The affected/compromised mailbox UPN.

.PARAMETER AdminUpn
    The operator account you intend to authenticate as. Applied as a login hint
    ONLY where the installed module exposes one - on the reference build that
    means the Exchange leg only, since Connect-MgGraph has no hint parameter.
    Never a guarantee: the identity banner after connect is the real safeguard.

.PARAMETER IssueId
    Ticket / case ID (e.g. CS-1234). Used to name the evidence folder + zip.

.PARAMETER CompromiseStart / CompromiseEnd
    Suspected compromise window (used for message trace + audit filtering).

.PARAMETER OutputPath
    Root folder where the CS-#### evidence folder + zip are written.

.PARAMETER UseDeviceCode
    Device-code auth for GRAPH ONLY. No effect on Exchange, which has no
    device-code path. The actual parameter name is resolved at runtime.

.PARAMETER DisableWam
    Move EXO's sign-in off the WAM broker onto the WebView2 dialog. Independent
    of -UseDeviceCode. Only set this if WAM specifically is crashing.

.PARAMETER GraphFirst
    Connect Graph BEFORE Exchange (default is Exchange first). ExchangeOnline-
    Management and the Graph SDK each bundle their own Microsoft.Identity.Client;
    under .NET Framework only one version loads per process, so whichever module
    initialises MSAL second can fail in RuntimeBroker..ctor. Which leg survives
    depends on the installed version pairing - if the default order fails on a
    given machine, try this switch. See msgraph-sdk-powershell issue #3576.

.PARAMETER PartnerDelegated
    Connect Exchange Online via GDAP/CSP delegation (-DelegatedOrganization).

.PARAMETER MaxGraphPages
    Safety cap on @odata.nextLink following. Default 50 (~50,000 records).

.PARAMETER ForceFreshAuth
    Clear the cached MSAL token before connecting.

.PARAMETER SkipTenantConfirm
    Suppress the post-connect identity confirmation. Unattended runs only.

.PARAMETER KeepConnected
    Skip the Disconnect calls so follow-up cmdlets still work in your session.

.PARAMETER ShowAuthCapabilities
    Print which auth parameters each module actually exposes, then continue.
    Use this first on any new machine to see what the build supports.

.PARAMETER Remediate / BlockSignIn / EmitTempPasswordFile
    Containment switches. See the REMEDIATE phase. -Remediate resets the
    password TWICE (throwaway, then the hand-over credential printed to the
    terminal) and revokes all sign-in sessions twice (signs the user out
    everywhere). It does NOT clear forwarding or disable inbox rules - those
    are listed in the triage summary for manual handling.

.EXAMPLE
    .\Invoke-CompromisedMailboxIR.ps1 -TenantId 'clienttenant.onmicrosoft.com' `
        -UserPrincipalName 'user@clientdomain.com' -AdminUpn 'you@yourmsp.com' `
        -IssueId 'CS-1234' -CompromiseStart '2026-09-01 00:00' `
        -CompromiseEnd '2026-09-02 23:59' -KeepConnected
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)] [string]   $TenantId,
    [Parameter(Mandatory)] [string]   $UserPrincipalName,
    [Parameter(Mandatory)] [string]   $IssueId,

    [string]   $AdminUpn,

    [datetime] $CompromiseStart = (Get-Date).AddDays(-7),
    [datetime] $CompromiseEnd   = (Get-Date),

    [string]   $OutputPath = (Join-Path $env:USERPROFILE 'Desktop\IR'),

    [int]      $MaxGraphPages = 50,

    [switch]   $UseDeviceCode,
    [switch]   $DisableWam,
    [switch]   $GraphFirst,
    [switch]   $ForceFreshAuth,
    [switch]   $SkipTenantConfirm,
    [switch]   $KeepConnected,
    [switch]   $ShowAuthCapabilities,
    [switch]   $PartnerDelegated,
    [switch]   $Remediate,
    [switch]   $BlockSignIn,
    [switch]   $EmitTempPasswordFile
)

# ---------------------------------------------------------------------------
#  0.  Setup
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Continue'

$caseFolder = Join-Path $OutputPath $IssueId
$null = New-Item -ItemType Directory -Path $caseFolder -Force -WhatIf:$false -Confirm:$false

$transcript = Join-Path $caseFolder ("{0}_transcript_{1:yyyyMMdd-HHmmss}.log" -f $IssueId, (Get-Date))

function Start-IRTranscript {
    try { Start-Transcript -Path $script:transcript -Append -WhatIf:$false | Out-Null }
    catch { Write-Host "  (transcript could not start: $($_.Exception.Message))" -ForegroundColor DarkGray }
}
function Stop-IRTranscript { try { Stop-Transcript | Out-Null } catch { } }

Start-IRTranscript

function Write-Step { param($msg) Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

function Write-EmptyDiag {
    param([string]$Name, [string]$Reason)
    Write-Host "  (no data) $Name" -ForegroundColor DarkGray
    if ($Reason) { Write-Host "     -> $Reason" -ForegroundColor DarkYellow }
}

function Save-Evidence {
    param($Object, [string]$Name, [string]$EmptyReason)
    if (-not $Object) { Write-EmptyDiag $Name $EmptyReason; return }
    $csv  = Join-Path $caseFolder "$Name.csv"
    $json = Join-Path $caseFolder "$Name.json"
    $Object | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    $Object | ConvertTo-Json -Depth 6 | Out-File $json -Encoding UTF8 -WhatIf:$false
    Write-Host ("  saved -> {0} ({1} row(s), .csv/.json)" -f $Name, @($Object).Count) -ForegroundColor Green
}

$script:findings = [System.Collections.Generic.List[string]]::new()
function Add-Finding {
    param([string]$Text, [string]$Severity = 'HIGH')
    $script:findings.Add("[$Severity] $Text")
    $color = if ($Severity -eq 'HIGH') { 'Red' } else { 'DarkYellow' }
    Write-Host "  !! $Text" -ForegroundColor $color
}

$script:notCollected = [System.Collections.Generic.List[string]]::new()
function Add-NotCollected {
    param([string]$Source, [string]$Why)
    $script:notCollected.Add("$Source :: $Why")
    Write-Host "  [NOT COLLECTED] $Source" -ForegroundColor Red
    Write-Host "     -> $Why" -ForegroundColor Red
}

function Invoke-Collect {
    param([string]$Label, [scriptblock]$Script)
    try   { & $Script }
    catch {
        Write-Host ("  [SKIP] {0}: {1}" -f $Label, $_.Exception.Message) -ForegroundColor DarkYellow
        Add-NotCollected $Label ("Collector threw: " + $_.Exception.Message)
    }
}

# ADDED (round 10): resolve a capability to whichever parameter name the
# installed module actually uses. Auth switch names have moved across builds
# and every hardcoded guess in this script's history (-Device, -LoginHint,
# -UseDeviceAuthentication) was wrong for the version in use, killing the run
# at connect time. Absent capability now degrades to a warning, never a throw.
function Resolve-ParamName {
    param(
        [Parameter(Mandatory)][string]$CommandName,
        [Parameter(Mandatory)][string[]]$Candidates
    )
    $cmd = Get-Command $CommandName -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    $keys = $cmd.Parameters.Keys
    foreach ($c in $Candidates) { if ($keys -contains $c) { return $c } }
    return $null
}

function Get-GraphOnce {
    param([Parameter(Mandatory)][string]$Uri)
    return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
}

function Get-GraphPaged {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$MaxPages = $script:MaxGraphPages,
        [string]$Label = 'query'
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri; $page = 0
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        if ($resp.value) { $results.AddRange(@($resp.value)) }
        $next = $resp.'@odata.nextLink'
        $page++
        if ($page -ge $MaxPages) {
            Write-Host ("  [WARN] {0}: hit page cap ({1} pages, {2} rows) - may be TRUNCATED." -f $Label, $MaxPages, $results.Count) -ForegroundColor DarkYellow
            break
        }
    } while ($next)
    return $results
}

Write-Step "Verifying required modules"
$required = @('Microsoft.Graph.Users','Microsoft.Graph.Identity.SignIns',
              'Microsoft.Graph.Reports','Microsoft.Graph.Identity.DirectoryManagement',
              'Microsoft.Graph.Applications','ExchangeOnlineManagement')
foreach ($m in $required) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Stop-IRTranscript
        throw "Missing module '$m'. Install:  Install-Module $m -Scope CurrentUser"
    }
}

$exoVer = (Get-Module ExchangeOnlineManagement -ListAvailable |
           Sort-Object Version -Descending | Select-Object -First 1).Version
$mgVer  = (Get-Module Microsoft.Graph.Authentication -ListAvailable |
           Sort-Object Version -Descending | Select-Object -First 1).Version
Write-Host ("  ExchangeOnlineManagement : {0}" -f $exoVer) -ForegroundColor DarkGray
Write-Host ("  Microsoft.Graph.Auth     : {0}" -f $mgVer)  -ForegroundColor DarkGray

# ADDED (round 10): resolve every auth capability up front, once.
$mgDeviceParam  = Resolve-ParamName 'Connect-MgGraph'        @('UseDeviceCode','UseDeviceAuthentication','DeviceCode')
$mgHintParam    = Resolve-ParamName 'Connect-MgGraph'        @('LoginHint','Account','UserId')
$exoWamParam    = Resolve-ParamName 'Connect-ExchangeOnline' @('DisableWAM','DisableWam')
$exoHintParam   = Resolve-ParamName 'Connect-ExchangeOnline' @('UserPrincipalName')
$exoDeviceParam = Resolve-ParamName 'Connect-ExchangeOnline' @('Device','DeviceCode','UseDeviceAuthentication')

if ($ShowAuthCapabilities) {
    Write-Step "Auth capabilities detected on this machine"
    @(
        [pscustomobject]@{ Command='Connect-MgGraph';        Capability='device code'; Parameter=$(if($mgDeviceParam){"-$mgDeviceParam"}else{'NOT SUPPORTED'}) }
        [pscustomobject]@{ Command='Connect-MgGraph';        Capability='login hint';  Parameter=$(if($mgHintParam){"-$mgHintParam"}else{'NOT SUPPORTED'}) }
        [pscustomobject]@{ Command='Connect-ExchangeOnline'; Capability='device code'; Parameter=$(if($exoDeviceParam){"-$exoDeviceParam"}else{'NOT SUPPORTED'}) }
        [pscustomobject]@{ Command='Connect-ExchangeOnline'; Capability='disable WAM'; Parameter=$(if($exoWamParam){"-$exoWamParam"}else{'NOT SUPPORTED'}) }
        [pscustomobject]@{ Command='Connect-ExchangeOnline'; Capability='login hint';  Parameter=$(if($exoHintParam){"-$exoHintParam"}else{'NOT SUPPORTED'}) }
    ) | Format-Table -AutoSize | Out-String | Write-Host
}

# ---------------------------------------------------------------------------
#  1.  Connect  (FAIL-CLOSED)
# ---------------------------------------------------------------------------
Write-Step "Connecting to tenant $TenantId"

$placeholders = '^(contoso|fabrikam|adventure-works|northwind|tailspintoys|woodgrovebank)\.onmicrosoft\.com$'
if ($TenantId -match $placeholders) {
    Stop-IRTranscript
    throw "TenantId '$TenantId' is a documentation placeholder that resolves to a real, unrelated tenant. Supply the actual client tenant."
}

$graphScopes = @('User.ReadWrite.All','Directory.Read.All','AuditLog.Read.All',
                 'Device.Read.All','Application.Read.All','Policy.Read.All',
                 'UserAuthenticationMethod.Read.All','Reports.Read.All')

if ($ForceFreshAuth) {
    Write-Host "  Clearing cached MSAL token (-ForceFreshAuth)..." -ForegroundColor DarkYellow
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    $graphCache = Join-Path $env:USERPROFILE '.graph'
    if (Test-Path $graphCache) { Remove-Item $graphCache -Recurse -Force -WhatIf:$false -ErrorAction SilentlyContinue }
}

Write-Host "  Graph auth : $(if ($UseDeviceCode -and $mgDeviceParam) {"DEVICE CODE (-$mgDeviceParam)"} else {'interactive browser (WAM)'})" -ForegroundColor Yellow
Write-Host "  EXO auth   : $(if ($DisableWam -and $exoWamParam) {"WebView2 dialog (-$exoWamParam)"} else {'WAM broker (default)'})" -ForegroundColor Yellow
if ($UseDeviceCode -and -not $mgDeviceParam) {
    Write-Host "  [WARN] This Graph SDK build ($mgVer) exposes no device-code switch - using interactive browser." -ForegroundColor Red
}
if ($DisableWam -and -not $exoWamParam) {
    Write-Host "  [WARN] This EXO build ($exoVer) exposes no WAM opt-out switch - ignoring -DisableWam." -ForegroundColor Red
}
if ($UseDeviceCode -and -not $DisableWam) {
    Write-Host "  (EXO stays on WAM - -UseDeviceCode only changes Graph.)" -ForegroundColor DarkGray
}

# FIX (round 10): -LoginHint does not exist on Connect-MgGraph in this SDK
# (confirmed against the live parameter list - there is NO hint parameter of
# any name). Passing it killed the run. -AdminUpn is now applied only where a
# hint parameter actually exists, per-command.
if ($AdminUpn) {
    $hintTargets = @()
    if ($mgHintParam)  { $hintTargets += "Graph (-$mgHintParam)" }
    if ($exoHintParam) { $hintTargets += "EXO (-$exoHintParam)" }
    if ($hintTargets) {
        Write-Host ("  Login hint: {0} -> applied to {1}" -f $AdminUpn, ($hintTargets -join ', ')) -ForegroundColor Yellow
    } else {
        Write-Host "  Login hint: NOT SUPPORTED by either module on this machine." -ForegroundColor DarkYellow
    }
    Write-Host "  The browser may still offer other cached accounts - check before clicking through." -ForegroundColor Yellow
} else {
    Write-Host "  No -AdminUpn given. If a sign-in prompt appears with an unexpected account" -ForegroundColor DarkGray
    Write-Host "  already selected, click 'Use another account' - do not click through it." -ForegroundColor DarkGray
}

$resolvedTenantId    = $null
$script:exoUpn       = $null
$script:exoOrg       = $null
$script:exoTenantId  = $null
$script:mgCtx        = $null
$script:connectStage = 'INIT'

# FIX (round 11): ExchangeOnlineManagement and the Graph SDK each ship their own
# copy of Microsoft.Identity.Client. Under .NET Framework (Windows PowerShell
# 5.1) only ONE version can be loaded per process, so whichever module
# initialises MSAL second can die inside RuntimeBroker..ctor with a
# NullReferenceException (or MissingMethodException on other pairings).
# Reference: msgraph-sdk-powershell issue #3576.
#
# Three mitigations, all here:
#   1. Load order is now EXPLICIT (Import-Module) instead of an accident of
#      which Connect-* cmdlet happens to auto-import first.
#   2. Connect order defaults to EXO-then-Graph; -GraphFirst flips it, because
#      which leg survives depends on the installed version pairing.
#   3. Each leg retries ONCE on a broker failure using a non-broker auth path
#      (EXO -> -DisableWAM, Graph -> device code).
$connectExoLeg = {
    $script:connectStage = 'EXO'
    $exoArgs = @{ ShowBanner = $false; ErrorAction = 'Stop' }
    if ($DisableWam -and $exoWamParam)  { $exoArgs[$exoWamParam]  = $true }
    if ($AdminUpn   -and $exoHintParam) { $exoArgs[$exoHintParam] = $AdminUpn }
    if ($PartnerDelegated) {
        if ($TenantId -match '^[0-9a-fA-F-]{36}$') {
            throw "-PartnerDelegated requires the domain form (client.onmicrosoft.com), not a GUID."
        }
        $exoArgs['DelegatedOrganization'] = $TenantId
    }

    # A stale EXO connection from an earlier run would be what Get-ConnectionInformation
    # reports below - drop it first so the identity check reflects THIS sign-in.
    $stale = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($stale.Count -gt 0) {
        Write-Host ("  Closing {0} pre-existing Exchange Online connection(s) before connecting." -f $stale.Count) -ForegroundColor DarkGray
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }

    try {
        Connect-ExchangeOnline @exoArgs
    } catch {
        # Broker construction failed. Retry on the WebView2 path, where
        # RuntimeBroker..ctor is never reached at all.
        if ($_.Exception.Message -match 'Object reference not set|RuntimeBroker' -and
            $exoWamParam -and -not $exoArgs.ContainsKey($exoWamParam)) {
            Write-Host "  [RETRY] EXO WAM broker failed to construct - retrying with -$exoWamParam" -ForegroundColor DarkYellow
            Write-Host "          (needs the WebView2 Evergreen Runtime installed)" -ForegroundColor DarkGray
            $exoArgs[$exoWamParam] = $true
            Connect-ExchangeOnline @exoArgs
        } else { throw }
    }

    # FIX (round 12): Get-ConnectionInformation only populates .Organization for
    # app-only (-Organization) or GDAP (-DelegatedOrganization) connections. On a
    # normal interactive admin sign-in it is EMPTY, so the previous check aborted
    # every interactive run with "reported no Organization". The tenant identity
    # that is always populated is .TenantID; the friendly org name is resolved
    # afterwards from Get-OrganizationConfig (best effort).
    $conn = Get-ConnectionInformation |
            Where-Object { $_.State -eq 'Connected' } |
            Select-Object -Last 1
    if (-not $conn) {
        throw "Connect-ExchangeOnline returned but no connection is in state 'Connected'. Aborting - cannot confirm which tenant this is."
    }
    if ([string]::IsNullOrWhiteSpace($conn.TenantID) -and [string]::IsNullOrWhiteSpace($conn.Organization)) {
        throw "Exchange Online connected but reported neither TenantID nor Organization. Aborting - cannot confirm which tenant this is."
    }
    $script:exoUpn      = $conn.UserPrincipalName
    $script:exoTenantId = $conn.TenantID
    $script:exoOrg      = if ($conn.Organization) { $conn.Organization } else { $conn.TenantID }

    try {
        $orgCfg = Get-OrganizationConfig -ErrorAction Stop
        $friendly = if ($orgCfg.DisplayName) { $orgCfg.DisplayName } else { $orgCfg.Name }
        if ($friendly) { $script:exoOrg = "{0} [{1}]" -f $friendly, $script:exoOrg }
    } catch {
        Write-Host ("  (could not read Get-OrganizationConfig for a friendly org name: {0})" -f $_.Exception.Message) -ForegroundColor DarkGray
    }
}

$connectGraphLeg = {
    $script:connectStage = 'GRAPH'
    # Built as a splat from detected parameter names. Nothing auth-related is
    # hardcoded (round 10).
    $mgArgs = @{
        TenantId    = $TenantId
        Scopes      = $graphScopes
        NoWelcome   = $true
        ErrorAction = 'Stop'
    }
    if ($UseDeviceCode -and $mgDeviceParam) { $mgArgs[$mgDeviceParam] = $true }
    if ($AdminUpn -and $mgHintParam)        { $mgArgs[$mgHintParam]   = $AdminUpn }

    try {
        Connect-MgGraph @mgArgs
    } catch {
        # Same MSAL conflict, opposite leg. Device code bypasses the broker.
        if ($_.Exception.Message -match 'Object reference not set|RuntimeBroker|Method not found' -and
            $mgDeviceParam -and -not $mgArgs.ContainsKey($mgDeviceParam)) {
            Write-Host "  [RETRY] Graph broker failed - retrying with -$mgDeviceParam" -ForegroundColor DarkYellow
            $mgArgs[$mgDeviceParam] = $true
            Connect-MgGraph @mgArgs
        } else { throw }
    }

    $ctx = Get-MgContext
    if (-not $ctx -or [string]::IsNullOrWhiteSpace($ctx.TenantId)) {
        throw "Connect-MgGraph returned no usable context (TenantId empty). Aborting before evidence collection."
    }
    $script:mgCtx     = $ctx
    $resolvedTenantId = $ctx.TenantId
}

try {
    # Deterministic module load order. Do NOT let Connect-* auto-import decide.
    $script:connectStage = 'IMPORT'
    if ($GraphFirst) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module ExchangeOnlineManagement       -ErrorAction Stop
    } else {
        Import-Module ExchangeOnlineManagement       -ErrorAction Stop
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    }
    Write-Host ("  Connect order: {0}" -f $(if ($GraphFirst) { 'Graph -> EXO (-GraphFirst)' } else { 'EXO -> Graph (default)' })) -ForegroundColor DarkGray

    # Dot-sourced so assignments land in this scope, not a child scope.
    if ($GraphFirst) {
        . $connectGraphLeg
        . $connectExoLeg
    } else {
        . $connectExoLeg
        . $connectGraphLeg
    }
    $ctx = $script:mgCtx

    # FIX (round 12): both legs are up - make sure they landed in the SAME tenant.
    $script:connectStage = 'TENANT-CROSSCHECK'
    if ($script:exoTenantId -and $resolvedTenantId -and
        $script:exoTenantId -ne $resolvedTenantId) {
        $mismatch = "Graph connected to tenant {0} but Exchange Online connected to tenant {1}." -f $resolvedTenantId, $script:exoTenantId
        if ($PartnerDelegated) {
            Write-Host "  [WARN] $mismatch (expected under -PartnerDelegated: EXO reports the partner tenant)" -ForegroundColor DarkYellow
        } else {
            throw "$mismatch Aborting - the two sessions are not in the same tenant."
        }
    }

} catch {
    $m = $_.Exception.Message
    Write-Host ("`n  CONNECTION FAILED at stage: {0} - no evidence collected." -f $script:connectStage) -ForegroundColor Red
    Write-Host "  $m" -ForegroundColor Red

    if ($m -match 'Object reference not set|RuntimeBroker|Method not found') {
        Write-Host "`n  MSAL/WAM assembly conflict between ExchangeOnlineManagement and the" -ForegroundColor Yellow
        Write-Host "  Graph SDK (msgraph-sdk-powershell issue #3576). Both bundle their own" -ForegroundColor Yellow
        Write-Host "  Microsoft.Identity.Client and .NET Framework cannot load both versions." -ForegroundColor Yellow
        Write-Host "  The automatic non-broker retry ALSO failed. Next steps:" -ForegroundColor Yellow
        Write-Host ("    - flip the connect order: {0}" -f $(if ($GraphFirst) { 'drop -GraphFirst' } else { 'add -GraphFirst' })) -ForegroundColor Yellow
        Write-Host "    - install the WebView2 Evergreen Runtime, then retry with -DisableWam" -ForegroundColor Yellow
        Write-Host "    - or run the Graph and EXO legs in separate PowerShell processes" -ForegroundColor Yellow
    }
    if ($m -match 'download has failed|connection was interrupted') {
        Write-Host "`n  The embedded sign-in dialog could not reach login.microsoftonline.com." -ForegroundColor Yellow
        Write-Host "  This is the LEGACY IE control (WinINET), which appears when the WebView2" -ForegroundColor Yellow
        Write-Host "  runtime is absent - it uses Internet Explorer proxy/zone/TLS settings," -ForegroundColor Yellow
        Write-Host "  not the system browser's. Install the WebView2 Evergreen Runtime first." -ForegroundColor Yellow
        Write-Host "  If a TLS-inspecting appliance is in the path, use device-code auth." -ForegroundColor Yellow
    }
    if ($m -match 'parameter cannot be found') {
        Write-Host "`n  A parameter name did not match this module build. Re-run with" -ForegroundColor Yellow
        Write-Host "  -ShowAuthCapabilities to see exactly what these modules support." -ForegroundColor Yellow
    }
    if ($m -match 'AADSTS50020') {
        Write-Host "`n  AADSTS50020: your account does not exist in that tenant. Verify -TenantId." -ForegroundColor Yellow
    }

    Stop-IRTranscript
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    throw "Connection failed - aborted before evidence collection."
}

Write-Host "`n  ===================================================" -ForegroundColor Cyan
Write-Host "  VERIFY THIS IS THE CORRECT ENGAGEMENT BEFORE PROCEEDING" -ForegroundColor Cyan
Write-Host "  ===================================================" -ForegroundColor Cyan
Write-Host ("  Graph account   : {0}" -f $ctx.Account) -ForegroundColor Cyan
Write-Host ("  Graph tenant    : {0}  (requested: {1})" -f $resolvedTenantId, $TenantId) -ForegroundColor Cyan
Write-Host ("  EXO account     : {0}" -f $script:exoUpn) -ForegroundColor Cyan
Write-Host ("  EXO organization: {0}" -f $script:exoOrg) -ForegroundColor Cyan
Write-Host ("  EXO tenant      : {0}" -f $script:exoTenantId) -ForegroundColor Cyan
Write-Host ("  Target mailbox  : {0}" -f $UserPrincipalName) -ForegroundColor Cyan
if ($AdminUpn -and $script:exoUpn -and $script:exoUpn -ne $AdminUpn) {
    Write-Host ("  [WARN] Connected as '{0}' but -AdminUpn requested '{1}'." -f $script:exoUpn, $AdminUpn) -ForegroundColor Red
}
if (-not $SkipTenantConfirm) {
    $idOk = Read-Host "`n  Type 'yes' to confirm these identities are correct for this engagement"
    if ($idOk -ne 'yes') {
        Stop-IRTranscript
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        throw "Aborted by operator at identity confirmation."
    }
} else {
    Write-Host "  (-SkipTenantConfirm set - identity NOT interactively confirmed.)" -ForegroundColor DarkYellow
}

$user = Get-MgUser -UserId $UserPrincipalName -Property Id,DisplayName,UserPrincipalName,AccountEnabled -ErrorAction Stop
$uid  = $user.Id
Write-Host ("`n  Target: {0} ({1})  ObjectId={2}" -f $user.DisplayName,$user.UserPrincipalName,$uid) -ForegroundColor Yellow
Write-Host ("  Window: {0:yyyy-MM-dd HH:mm} -> {1:yyyy-MM-dd HH:mm} (local)" -f $CompromiseStart,$CompromiseEnd) -ForegroundColor Yellow

if (-not $SkipTenantConfirm -and $script:exoOrg -and $script:exoOrg -notmatch '^[0-9a-fA-F-]{36}$') {
    $upnDomain = ($UserPrincipalName -split '@')[-1]
    $orgStem   = (($script:exoOrg -replace '\s*\[.*\]$','') -split '\.')[0]
    if ($upnDomain -notlike "*$orgStem*" -and $orgStem -notlike "*$(($upnDomain -split '\.')[0])*") {
        Add-Finding "Target domain '$upnDomain' does not obviously match organization '$($script:exoOrg)' - confirmed by operator, noted for the case record." 'MEDIUM'
    }
}

# ---------------------------------------------------------------------------
#  Pre-flight
# ---------------------------------------------------------------------------
Write-Step "Pre-flight capability checks"
$canReadSignIns = $false
$canSearchAudit = $false

Invoke-Collect 'PreFlight_SignInLogs' {
    $sw   = [System.Diagnostics.Stopwatch]::StartNew()
    $resp = Get-GraphOnce "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1"
    $sw.Stop()
    $script:canReadSignIns = $true
    if ($resp.value) { Write-Host ("  Sign-in logs: READABLE ({0:N1}s)" -f $sw.Elapsed.TotalSeconds) -ForegroundColor Green }
    else { Write-Host ("  Sign-in logs: readable, tenant probe returned 0 rows ({0:N1}s)" -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkYellow }
}
if (-not $canReadSignIns) {
    Add-NotCollected 'SignInLogs' 'Sign-in log API not readable - no Entra ID P1/P2 licence, or AuditLog.Read.All not consented.'
}

$auditEnabled = $null
Invoke-Collect 'PreFlight_Auditing' {
    Write-Host "  Querying Exchange audit config (first EXO cmdlet in a session is slow - 10-20s is normal)..." -ForegroundColor DarkGray
    $adminAudit = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
    $script:auditEnabled = $adminAudit.UnifiedAuditLogIngestionEnabled
    if ($script:auditEnabled) { Write-Host "  Unified audit log ingestion: ENABLED" -ForegroundColor Green }
    else { Add-Finding "Unified audit ingestion appears DISABLED on this tenant." 'HIGH' }

    $mbAudit = Get-Mailbox -Identity $UserPrincipalName | Select-Object AuditEnabled, AuditLogAgeLimit
    Write-Host ("  Mailbox auditing: AuditEnabled={0}  AgeLimit={1}" -f $mbAudit.AuditEnabled, $mbAudit.AuditLogAgeLimit) -ForegroundColor DarkYellow
    if ($mbAudit.AuditEnabled -eq $false) {
        Add-Finding "Mailbox auditing is DISABLED for $UserPrincipalName - mailbox activity cannot be reconstructed." 'HIGH'
    }
}

Invoke-Collect 'PreFlight_AuditPermissions' {
    $probe = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -ResultSize 1 `
                -WarningVariable pw -ErrorVariable pe -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    $msg = (@($pw) + @($pe) | ForEach-Object { "$_" }) -join ' '

    if ($msg -match 'Unauthorized|Forbidden|AccessDenied|user scopes') {
        $script:canSearchAudit = $false
        Add-NotCollected 'UnifiedAuditLog (all record types)' `
            "Audit search DENIED for $($script:exoUpn) in $($script:exoOrg). The account lacks the 'Audit Logs' or 'View-Only Audit Logs' role in the TARGET tenant."
        Add-Finding "Audit log evidence UNAVAILABLE (permissions)." 'HIGH'
    } elseif ($probe) {
        $script:canSearchAudit = $true
        Write-Host "  Audit search: PERMITTED (tenant probe returned data)" -ForegroundColor Green
    } else {
        $script:canSearchAudit = $true
        Write-Host "  Audit search: no error, tenant probe returned 0 rows. Proceeding." -ForegroundColor DarkYellow
    }
}

# ===========================================================================
#                        PHASE 1 :  INVESTIGATE  (read-only)
# ===========================================================================

$suspiciousRules        = @()
$mbx                    = $null
$newDevices             = @()
$interactive            = @()
$script:nonInteractive  = @()
$script:sentMail        = @()
$script:perms           = @()
$script:sendAs          = @()
$script:cas             = $null
$script:devices         = @()
$script:grants          = @()
$script:mailScoped      = @()
$script:mfaReg          = $null
$script:mfaOnly         = @()
$script:newAuth         = @()
$script:auditItemCount  = $null
$script:auditAdminCount = $null
$script:ruleEvents      = @()

Write-Step "Collecting inbox rules & forwarding config"
Invoke-Collect 'InboxRules' {
    $script:inboxRules = Get-InboxRule -Mailbox $UserPrincipalName |
        Select-Object Name, Identity, RuleIdentity, Enabled, Priority,
                      @{n='RedirectTo';           e={ $_.RedirectTo            -join '; ' }},
                      @{n='ForwardTo';            e={ $_.ForwardTo             -join '; ' }},
                      @{n='ForwardAsAttachmentTo';e={ $_.ForwardAsAttachmentTo -join '; ' }},
                      DeleteMessage, MoveToFolder, MarkAsRead, StopProcessingRules,
                      @{n='From';                 e={ $_.From                  -join '; ' }},
                      @{n='SubjectContainsWords'; e={ $_.SubjectContainsWords  -join '; ' }},
                      @{n='BodyContainsWords';    e={ $_.BodyContainsWords     -join '; ' }}

    Save-Evidence $script:inboxRules 'InboxRules' 'Mailbox has no client-side inbox rules at all.'

    $script:suspiciousRules = $script:inboxRules | Where-Object {
        $_.DeleteMessage -eq $true -or
        $_.RedirectTo -or $_.ForwardTo -or $_.ForwardAsAttachmentTo -or
        $_.MoveToFolder -match 'RSS|Archive|Deleted|Conversation History'
    }
    Save-Evidence $script:suspiciousRules 'InboxRules_SUSPICIOUS' 'No rule matched the malicious-pattern heuristics.'
    if ($script:suspiciousRules) {
        Add-Finding ("{0} suspicious inbox rule(s) - see InboxRules_SUSPICIOUS.csv" -f @($script:suspiciousRules).Count) 'HIGH'
    }
}

Invoke-Collect 'MailboxForwarding' {
    $script:mbx = Get-Mailbox -Identity $UserPrincipalName |
        Select-Object DisplayName, PrimarySmtpAddress, ForwardingAddress,
                      ForwardingSmtpAddress, DeliverToMailboxAndForward
    Save-Evidence $script:mbx 'MailboxForwarding'
    if ($script:mbx.ForwardingSmtpAddress -or $script:mbx.ForwardingAddress) {
        Add-Finding ("Mailbox-level forwarding is SET: {0}{1}" -f $script:mbx.ForwardingAddress, $script:mbx.ForwardingSmtpAddress) 'HIGH'
    }
}

Write-Step "Mailbox delegation & permissions"
Invoke-Collect 'MailboxPermissions' {
    $script:perms = Get-MailboxPermission -Identity $UserPrincipalName |
        Where-Object { $_.User -notlike 'NT AUTHORITY\SELF' -and -not $_.IsInherited } |
        Select-Object User, @{n='AccessRights';e={ $_.AccessRights -join '; ' }}, Deny
    Save-Evidence $script:perms 'MailboxPermissions_FullAccess' 'No non-default FullAccess grants (clean/expected state).'
    if ($script:perms) { Add-Finding ("{0} non-default FullAccess grant(s) on the mailbox" -f @($script:perms).Count) 'HIGH' }
}
Invoke-Collect 'RecipientPermissions' {
    $script:sendAs = Get-RecipientPermission -Identity $UserPrincipalName |
        Where-Object { $_.Trustee -notlike 'NT AUTHORITY\SELF' } |
        Select-Object Trustee, @{n='AccessRights';e={ $_.AccessRights -join '; ' }}
    Save-Evidence $script:sendAs 'MailboxPermissions_SendAs' 'No SendAs delegations (clean/expected state).'
    if ($script:sendAs) { Add-Finding ("{0} SendAs delegation(s) on the mailbox" -f @($script:sendAs).Count) 'HIGH' }
}
Invoke-Collect 'CASMailbox' {
    $script:cas = Get-CASMailbox -Identity $UserPrincipalName |
        Select-Object DisplayName, ActiveSyncEnabled, ImapEnabled, PopEnabled,
                      OwaEnabled, MAPIEnabled, EwsEnabled, SmtpClientAuthenticationDisabled
    Save-Evidence $script:cas 'CASMailbox_Protocols'
    if ($script:cas.ImapEnabled -or $script:cas.PopEnabled) {
        Add-Finding "Legacy protocols enabled (IMAP and/or POP) - common BEC access path." 'MEDIUM'
    }
}

Write-Step "Message trace (sent by user during window)"
Invoke-Collect 'MessageTrace' {
    $trace = $null
    if (Get-Command Get-MessageTraceV2 -ErrorAction SilentlyContinue) {
        $trace = Get-MessageTraceV2 -SenderAddress $UserPrincipalName `
                    -StartDate $CompromiseStart -EndDate $CompromiseEnd -ResultSize 5000
    } else {
        $all = [System.Collections.Generic.List[object]]::new(); $page = 1
        do {
            $batch = Get-MessageTrace -SenderAddress $UserPrincipalName `
                        -StartDate $CompromiseStart -EndDate $CompromiseEnd `
                        -PageSize 1000 -Page $page
            if ($batch) { $all.AddRange(@($batch)) }
            $page++
        } while ($batch -and $batch.Count -eq 1000 -and $page -le 10)
        $trace = $all
    }
    $script:sentMail = @($trace | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status)
    Save-Evidence $script:sentMail 'SentMail_MessageTrace' `
        'No sent mail in window. Trace retention is ~10 days - if the window is older, use Start-HistoricalSearch.'
}

Write-Step "Entra sign-in logs (interactive + non-interactive)"
$startFilter  = $CompromiseStart.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$endFilter    = $CompromiseEnd.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$signInFilter = "userId eq '$uid' and createdDateTime ge $startFilter and createdDateTime le $endFilter"
Write-Host "  Filter: $signInFilter" -ForegroundColor DarkGray

Invoke-Collect 'SignInLogs_Interactive' {
    $script:interactive = Get-MgAuditLogSignIn -Filter $signInFilter -All |
        Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, IpAddress,
                      @{n='City';e={$_.Location.City}}, @{n='Country';e={$_.Location.CountryOrRegion}},
                      ClientAppUsed, @{n='Status';e={$_.Status.ErrorCode}},
                      @{n='Failure';e={$_.Status.FailureReason}}, IsInteractive,
                      @{n='Device';e={$_.DeviceDetail.DisplayName}},
                      @{n='DeviceId';e={$_.DeviceDetail.DeviceId}},
                      @{n='DeviceOS';e={$_.DeviceDetail.OperatingSystem}},
                      @{n='Browser';e={$_.DeviceDetail.Browser}},
                      @{n='DeviceCompliant';e={$_.DeviceDetail.IsCompliant}},
                      @{n='DeviceManaged';e={$_.DeviceDetail.IsManaged}},
                      @{n='DeviceTrustType';e={$_.DeviceDetail.TrustType}},
                      UserAgent
    Save-Evidence $script:interactive 'SignInLogs_Interactive'

    if (-not $script:interactive) {
        $probe = Get-MgAuditLogSignIn -Filter "userId eq '$uid'" -Top 5 |
                 Select-Object CreatedDateTime, AppDisplayName, IpAddress
        if ($probe) {
            Add-Finding ("Account HAS sign-in records but none inside your window. Most recent: {0:yyyy-MM-dd HH:mm}Z - widen the window." -f $probe[0].CreatedDateTime) 'MEDIUM'
            Save-Evidence $probe 'SignInLogs_OUTSIDE_WINDOW_SAMPLE'
        } else {
            Write-Host "     -> No sign-in records for this account at all (retention: 7d without P1/P2, 30d with)." -ForegroundColor DarkYellow
        }
    }
}

Invoke-Collect 'SignInLogs_NonInteractive' {
    $filter = [uri]::EscapeDataString("$signInFilter and signInEventTypes/any(t: t eq 'nonInteractiveUser')")
    $uri    = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$filter&`$top=999"
    $raw = Get-GraphPaged -Uri $uri -Label 'SignInLogs_NonInteractive'
    $script:nonInteractive = @($raw | ForEach-Object {
        [pscustomobject]@{
            CreatedDateTime   = $_.createdDateTime
            UserPrincipalName = $_.userPrincipalName
            AppDisplayName    = $_.appDisplayName
            IpAddress         = $_.ipAddress
            Country           = $_.location.countryOrRegion
            City              = $_.location.city
            ClientAppUsed     = $_.clientAppUsed
            Status            = $_.status.errorCode
            Failure           = $_.status.failureReason
            ResourceDisplay   = $_.resourceDisplayName
            Device            = $_.deviceDetail.displayName
            DeviceId          = $_.deviceDetail.deviceId
            DeviceOS          = $_.deviceDetail.operatingSystem
            Browser           = $_.deviceDetail.browser
            DeviceCompliant   = $_.deviceDetail.isCompliant
            DeviceManaged     = $_.deviceDetail.isManaged
            UserAgent         = $_.userAgent
        }
    })
    Save-Evidence $script:nonInteractive 'SignInLogs_NonInteractive' `
        'No non-interactive sign-ins in window. Token-refresh activity is the usual persistence signal here.'
}

Invoke-Collect 'SignIn_CountrySummary' {
    $geoSummary = $script:interactive | Group-Object Country |
        Select-Object Name, Count | Sort-Object Count -Descending
    Save-Evidence $geoSummary 'SignIn_CountrySummary' 'Derived from interactive sign-ins, which were empty.'
}

Write-Step "Registered authentication methods (MFA persistence check)"
$authMethods = @()
Invoke-Collect 'AuthMethods' {
    $script:authMethods = Get-MgUserAuthenticationMethod -UserId $uid -All | ForEach-Object {
        $ap = $_.AdditionalProperties
        [pscustomobject]@{
            MethodId    = $_.Id
            MethodType  = $ap['@odata.type'] -replace '#microsoft.graph.',''
            DisplayName = $ap['displayName']
            CreatedDate = if ($ap['createdDateTime']) { [datetime]$ap['createdDateTime'] } else { $null }
            Detail      = ($ap.GetEnumerator() |
                           Where-Object { $_.Key -notin '@odata.type','displayName','createdDateTime' } |
                           ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
        }
    }
    Save-Evidence $script:authMethods 'AuthenticationMethods'

    $script:mfaOnly = @($script:authMethods | Where-Object { $_.MethodType -ne 'passwordAuthenticationMethod' })
    $mfaOnly = $script:mfaOnly
    if (-not $mfaOnly) {
        Add-Finding "NO MFA METHODS REGISTERED - account is password-only. Likely root cause; require MFA registration as part of recovery." 'HIGH'
    } else {
        Write-Host ("  {0} non-password method(s): {1}" -f @($mfaOnly).Count, (($mfaOnly.MethodType | Sort-Object -Unique) -join ', ')) -ForegroundColor Green
    }

    $script:newAuth = @($script:authMethods | Where-Object {
        $_.CreatedDate -and $_.CreatedDate -ge $CompromiseStart -and $_.CreatedDate -le $CompromiseEnd
    })
    $newAuth = $script:newAuth
    if ($newAuth) {
        Add-Finding ("{0} auth method(s) registered DURING the window - treat as attacker persistence" -f @($newAuth).Count) 'HIGH'
        Save-Evidence $newAuth 'AuthenticationMethods_NEW_IN_WINDOW'
    } else {
        Write-Host "  No auth method carries a createdDateTime inside the window." -ForegroundColor DarkYellow
        Write-Host "  NOTE: password and some phone methods do not expose createdDateTime - confirm in the Entra portal." -ForegroundColor DarkYellow
    }
}

Invoke-Collect 'AuthMethodRegistrationDetail' {
    $r = Get-GraphOnce "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails/$uid"
    $regOut = [pscustomobject]@{
        UserPrincipalName   = $r.userPrincipalName
        IsAdmin             = $r.isAdmin
        IsMfaRegistered     = $r.isMfaRegistered
        IsMfaCapable        = $r.isMfaCapable
        IsSsprRegistered    = $r.isSsprRegistered
        IsSsprCapable       = $r.isSsprCapable
        DefaultMfaMethod    = $r.defaultMfaMethod
        MethodsRegistered   = ($r.methodsRegistered -join '; ')
        LastUpdatedDateTime = $r.lastUpdatedDateTime
    }
    $script:mfaReg = $regOut
    Save-Evidence $regOut 'AuthenticationMethods_RegistrationDetail'
    if ($r.isMfaRegistered -eq $false) { Add-Finding "Registration report confirms isMfaRegistered=false." 'HIGH' }
    if ($r.isAdmin -eq $true) { Add-Finding "Compromised account holds an ADMIN role - escalate scope, review tenant-wide changes in the window." 'HIGH' }
}

Write-Step "Entra registered devices for user"
Invoke-Collect 'RegisteredDevices' {
    $rawDevices = Get-MgUserRegisteredDevice -UserId $uid -All
    if (-not $rawDevices) {
        Write-EmptyDiag 'RegisteredDevices' 'User has no Entra-registered or joined devices. Expected for a web/OWA-only account; suspicious if the user normally has a managed workstation.'
    } else {
        $devices = $rawDevices | ForEach-Object {
            $ap = $_.AdditionalProperties
            if ($ap -and $ap['displayName']) {
                [pscustomobject]@{
                    DisplayName      = $ap['displayName']
                    OperatingSystem  = $ap['operatingSystem']
                    TrustType        = $ap['trustType']
                    IsManaged        = $ap['isManaged']
                    IsCompliant      = $ap['isCompliant']
                    RegistrationDate = if ($ap['registrationDateTime']) { [datetime]$ap['registrationDateTime'] } else { $null }
                    ApproxLastSignIn = if ($ap['approximateLastSignInDateTime']) { [datetime]$ap['approximateLastSignInDateTime'] } else { $null }
                    DeviceId         = $ap['deviceId']
                    ObjectId         = $_.Id
                }
            } else {
                $d = Get-MgDevice -DeviceId $_.Id -ErrorAction SilentlyContinue
                [pscustomobject]@{
                    DisplayName      = $d.DisplayName
                    OperatingSystem  = $d.OperatingSystem
                    TrustType        = $d.TrustType
                    IsManaged        = $d.IsManaged
                    IsCompliant      = $d.IsCompliant
                    RegistrationDate = $d.RegistrationDateTime
                    ApproxLastSignIn = $d.ApproximateLastSignInDateTime
                    DeviceId         = $d.DeviceId
                    ObjectId         = $_.Id
                }
            }
        }
        $script:devices = @($devices)
        Save-Evidence $devices 'RegisteredDevices'
        $script:newDevices = $devices | Where-Object {
            $_.RegistrationDate -and
            $_.RegistrationDate -ge $CompromiseStart -and $_.RegistrationDate -le $CompromiseEnd
        }
        if ($script:newDevices) {
            Add-Finding ("{0} device(s) registered during the window - verify before deleting" -f @($script:newDevices).Count) 'HIGH'
            Save-Evidence $script:newDevices 'RegisteredDevices_NEW_IN_WINDOW'
        }
    }
}

Write-Step "OAuth app consent grants (attacker persistence check)"
Invoke-Collect 'OAuthGrants' {
    $script:grants = @(Get-MgUserOauth2PermissionGrant -UserId $uid -All | ForEach-Object {
        $sp = Get-MgServicePrincipal -ServicePrincipalId $_.ClientId -ErrorAction SilentlyContinue
        [pscustomobject]@{
            App         = $sp.DisplayName
            AppId       = $sp.AppId
            Scope       = $_.Scope
            ConsentType = $_.ConsentType
            Publisher   = $sp.PublisherName
        }
    })
    $grants = $script:grants
    Save-Evidence $grants 'OAuth_ConsentGrants' 'No user-level OAuth consent grants.'
    $script:mailScoped = @($grants | Where-Object { $_.Scope -match 'Mail\.|MailboxSettings|offline_access|IMAP|POP|SMTP' })
    $mailScoped = $script:mailScoped
    if ($mailScoped) {
        Add-Finding ("{0} OAuth grant(s) carry mail-access scopes - review for unfamiliar apps: {1}" -f `
            @($mailScoped).Count, (($mailScoped.App | Sort-Object -Unique) -join ', ')) 'MEDIUM'
    }
}

Write-Step "Unified audit log (mailbox + admin activity)"

function Search-AuditRetry {
    param([string]$RecordType, [int]$MaxAttempts = 3)
    $sid  = "IR-$IssueId-$RecordType-" + (Get-Random)
    $rows = [System.Collections.Generic.List[object]]::new()

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        do {
            $batch = Search-UnifiedAuditLog -UserIds $UserPrincipalName `
                        -StartDate $CompromiseStart -EndDate $CompromiseEnd `
                        -RecordType $RecordType -ResultSize 5000 `
                        -SessionId $sid -SessionCommand ReturnLargeSet `
                        -WarningVariable auditWarn -ErrorVariable auditErr `
                        -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

            $msg = (@($auditWarn) + @($auditErr) | ForEach-Object { "$_" }) -join ' '
            if ($msg -match 'Unauthorized|Forbidden|AccessDenied|user scopes') {
                Add-NotCollected "UnifiedAuditLog ($RecordType)" `
                    "Search denied or backend error: $($msg.Substring(0, [Math]::Min(200, $msg.Length)))"
                return $null
            }
            if ($batch) { $rows.AddRange(@($batch)) }
        } while ($batch -and $batch.Count -eq 5000)

        if ($rows.Count -gt 0) { return $rows }
        if ($i -lt $MaxAttempts) {
            Write-Host "     (attempt $i returned 0 rows - polling same session in 5s)" -ForegroundColor DarkGray
            Start-Sleep -Seconds 5
        }
    }
    return @()
}

if (-not $canSearchAudit) {
    Write-Host "  Skipping audit queries - pre-flight established the account cannot search this tenant's audit log." -ForegroundColor Red
} else {
    Invoke-Collect 'UnifiedAuditLog' {
        $reason = if ($script:auditEnabled -eq $false) {
            'Unified audit ingestion is DISABLED on this tenant.'
        } else {
            'Query succeeded with no events in window. Check mailbox auditing is on and the window is inside retention (90d E3 / 365d E5).'
        }

        $audit = Search-AuditRetry -RecordType 'ExchangeItem'
        if ($null -eq $audit) { Write-Host "  UnifiedAuditLog_ExchangeItem: NOT COLLECTED (see findings)" -ForegroundColor Red }
        else { $script:auditItemCount = @($audit).Count; Save-Evidence ($audit | Select-Object CreationDate, Operations, UserIds, AuditData) 'UnifiedAuditLog_ExchangeItem' $reason }

        $adminAudit = Search-AuditRetry -RecordType 'ExchangeAdmin'
        if ($null -eq $adminAudit) { Write-Host "  UnifiedAuditLog_ExchangeAdmin: NOT COLLECTED (see findings)" -ForegroundColor Red }
        else {
            $script:auditAdminCount = @($adminAudit).Count
            Save-Evidence ($adminAudit | Select-Object CreationDate, Operations, UserIds, AuditData) 'UnifiedAuditLog_ExchangeAdmin' $reason
            $script:ruleEvents = @($adminAudit | Where-Object { $_.Operations -match 'InboxRule|Set-Mailbox|ForwardingSmtpAddress' })
            $ruleEvents = $script:ruleEvents
            if ($ruleEvents) {
                Add-Finding ("{0} rule/forwarding admin event(s) in the window" -f @($ruleEvents).Count) 'HIGH'
                Save-Evidence $ruleEvents 'UnifiedAuditLog_RULE_EVENTS'
            }
        }
    }
}

# ===========================================================================
#                        PHASE 2 :  REMEDIATE
# ===========================================================================
$script:passwordReset   = $false
$script:sessionsRevoked = $false
if ($Remediate) {
    Write-Step "REMEDIATION PHASE (containment actions)"

    if ($PSCmdlet.ShouldProcess($UserPrincipalName,'Reset password TWICE (force change)')) {
        function New-IRPassword {
            $upper = [char[]](65..90); $lower = [char[]](97..122)
            $digit = [char[]](48..57); $sym   = [char[]]'!@#$%^&*()-_=+[]{}'
            $chars = @(($upper | Get-Random), ($lower | Get-Random),
                       ($digit | Get-Random), ($sym   | Get-Random))
            $pool  = $upper + $lower + $digit + $sym
            $chars += 1..16 | ForEach-Object { $pool | Get-Random }
            return -join ($chars | Sort-Object { Get-Random })
        }

        # Reset twice: the first value is a throwaway that invalidates anything the
        # attacker may have set or cached; the second is the credential handed over.
        $newPwd = $null
        foreach ($pass in 1, 2) {
            $newPwd = New-IRPassword
            Update-MgUser -UserId $uid -PasswordProfile @{ Password = $newPwd; ForceChangePasswordNextSignIn = $true } -ErrorAction Stop
            Write-Host ("  Password reset {0}/2 done." -f $pass) -ForegroundColor Green
            if ($pass -eq 1) { Start-Sleep -Seconds 5 }
        }

        Stop-IRTranscript
        Write-Host "  Password reset twice. Temp credential (deliver out-of-band, do NOT paste into the ticket):" -ForegroundColor Yellow
        Write-Host "  $newPwd" -ForegroundColor Yellow
        if ($EmitTempPasswordFile) {
            $pwdFile = Join-Path $OutputPath ("{0}_TEMP_PASSWORD.txt" -f $IssueId)
            $newPwd | Out-File $pwdFile -Encoding UTF8 -WhatIf:$false
            Write-Host "  Written to: $pwdFile  (NOT in the evidence zip - delete after handoff)" -ForegroundColor DarkYellow
        }
        Read-Host "  Press ENTER once the credential has been captured" | Out-Null
        Start-IRTranscript
        Remove-Variable newPwd -ErrorAction SilentlyContinue
        $script:passwordReset = $true
    }

    if ($PSCmdlet.ShouldProcess($UserPrincipalName,'Revoke ALL sign-in sessions and sign the user out everywhere')) {
        # Revoke-MgUserSignInSession invalidates every refresh token and session
        # cookie, which signs the user out of all devices/apps once the current
        # access tokens expire (up to ~1h). Run twice to catch anything issued
        # between the password reset and the first revoke.
        Revoke-MgUserSignInSession -UserId $uid -ErrorAction Stop | Out-Null
        Write-Host "  Sessions revoked / user signed out (pass 1)." -ForegroundColor Green
        Start-Sleep -Seconds 10
        Revoke-MgUserSignInSession -UserId $uid -ErrorAction Stop | Out-Null
        Write-Host "  Sessions revoked / user signed out (pass 2)." -ForegroundColor Green
        $script:sessionsRevoked = $true
    }

    # Forwarding and inbox rules are deliberately LEFT IN PLACE: they are
    # evidence and are surfaced in the triage summary for manual handling.
    if ($mbx -and ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress)) {
        Write-Host "  NOTE: mailbox forwarding is SET and was NOT cleared - see triage summary." -ForegroundColor Yellow
    }
    if ($suspiciousRules) {
        Write-Host ("  NOTE: {0} suspicious inbox rule(s) were NOT disabled - see triage summary." -f @($suspiciousRules).Count) -ForegroundColor Yellow
    }

    if ($BlockSignIn) {
        if ($PSCmdlet.ShouldProcess($UserPrincipalName,'Block sign-in (AccountEnabled=$false)')) {
            Update-MgUser -UserId $uid -AccountEnabled:$false
            Write-Host "  Account sign-in BLOCKED." -ForegroundColor Green
        }
    }

    if ($newDevices) {
        Write-Host ("  NOTE: {0} device(s) registered in window flagged for MANUAL review/deletion." -f @($newDevices).Count) -ForegroundColor Yellow
    }
    Write-Host "  NOTE: MFA methods are NOT auto-removed. Review AuthenticationMethods*.csv." -ForegroundColor Yellow
}

# ===========================================================================
#  TRIAGE SUMMARY  (printed in both modes, written to TRIAGE_SUMMARY.txt)
# ===========================================================================
Write-Step "TRIAGE SUMMARY - $IssueId"
$script:triage = [System.Collections.Generic.List[string]]::new()
function Add-Triage {
    param([string]$Text, [string]$Color = 'Gray')
    $script:triage.Add($Text)
    Write-Host "  $Text" -ForegroundColor $Color
}
function Add-TriageHeader { param([string]$Text) Add-Triage '' ; Add-Triage ("-- {0} --" -f $Text) 'Cyan' }

Add-Triage ("Case      : {0}" -f $IssueId) 'White'
Add-Triage ("Target    : {0} ({1})" -f $user.DisplayName, $UserPrincipalName) 'White'
Add-Triage ("ObjectId  : {0}" -f $uid) 'White'
Add-Triage ("Tenant    : {0}  /  EXO org: {1}" -f $resolvedTenantId, $script:exoOrg) 'White'
Add-Triage ("Window    : {0:yyyy-MM-dd HH:mm} -> {1:yyyy-MM-dd HH:mm} (local)" -f $CompromiseStart, $CompromiseEnd) 'White'
Add-Triage ("Mode      : {0}" -f $(if ($Remediate) { 'INVESTIGATE + REMEDIATE' } else { 'INVESTIGATE (read-only)' })) 'White'
Add-Triage ("Account   : {0}" -f $(if ($user.AccountEnabled -eq $false) { 'sign-in BLOCKED' } else { 'sign-in enabled' })) 'White'

# ---- Sign-ins ----
Add-TriageHeader 'SIGN-INS'
$ia = @($script:interactive); $ni = @($script:nonInteractive)
$allSignIns = $ia + $ni
Add-Triage ("Interactive     : {0}   Non-interactive: {1}" -f $ia.Count, $ni.Count) 'White'
if ($allSignIns.Count -gt 0) {
    $failed = @($allSignIns | Where-Object { $_.Status -and $_.Status -ne 0 })
    Add-Triage ("Failed attempts : {0}" -f $failed.Count)
    $countries = $allSignIns | Where-Object Country | Group-Object Country | Sort-Object Count -Descending
    if ($countries) {
        Add-Triage ("Countries       : {0}" -f (($countries | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count }) -join ', ')) $(if ($countries.Count -gt 1) { 'Yellow' } else { 'Gray' })
    }
    $ips = $allSignIns | Where-Object IpAddress | Group-Object IpAddress | Sort-Object Count -Descending
    Add-Triage ("Distinct IPs    : {0}" -f @($ips).Count)
    foreach ($ip in ($ips | Select-Object -First 10)) {
        $sample = $ip.Group | Select-Object -First 1
        $loc = @($sample.City, $sample.Country) | Where-Object { $_ } 
        Add-Triage ("   {0,-40} {1,4}x  {2}" -f $ip.Name, $ip.Count, ($loc -join ', '))
    }
    $apps = $allSignIns | Where-Object AppDisplayName | Group-Object AppDisplayName | Sort-Object Count -Descending | Select-Object -First 8
    if ($apps) { Add-Triage ("Top apps        : {0}" -f (($apps | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count }) -join ', ')) }
    $clients = $allSignIns | Where-Object ClientAppUsed | Group-Object ClientAppUsed | Sort-Object Count -Descending
    if ($clients) { Add-Triage ("Client apps     : {0}" -f (($clients | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count }) -join ', ')) }
    $legacy = @($allSignIns | Where-Object { $_.ClientAppUsed -match 'IMAP|POP|SMTP|Other clients|Exchange ActiveSync|Authenticated SMTP' })
    if ($legacy) { Add-Triage ("Legacy-protocol sign-ins: {0}  <- review" -f $legacy.Count) 'Red' }
    $devs = $allSignIns | Where-Object { $_.Device -or $_.DeviceOS -or $_.Browser } |
            Group-Object { "{0} | {1} | {2}" -f $(if ($_.Device) { $_.Device } else { '(unregistered)' }), $_.DeviceOS, $_.Browser } | Sort-Object Count -Descending | Select-Object -First 10
    if ($devs) {
        Add-Triage "Devices seen in sign-ins (name | OS | browser):"
        foreach ($d in $devs) { Add-Triage ("   {0,4}x  {1}" -f $d.Count, $d.Name) }
    }
} else {
    Add-Triage "No sign-in records in window (see NOT COLLECTED / findings for why)." 'DarkYellow'
}

# ---- Sent mail ----
Add-TriageHeader 'OUTBOUND MAIL (message trace, sent by user in window)'
$sm = @($script:sentMail)
Add-Triage ("Messages sent   : {0}" -f $sm.Count) 'White'
if ($sm.Count -gt 0) {
    $rcpts = $sm | Where-Object RecipientAddress | Group-Object RecipientAddress | Sort-Object Count -Descending
    $extDomains = $sm | Where-Object RecipientAddress | ForEach-Object { ($_.RecipientAddress -split '@')[-1] } |
                  Where-Object { $_ -ne (($UserPrincipalName -split '@')[-1]) } | Group-Object | Sort-Object Count -Descending
    Add-Triage ("Distinct rcpts  : {0}   External domains: {1}" -f @($rcpts).Count, @($extDomains).Count)
    foreach ($dm in ($extDomains | Select-Object -First 10)) { Add-Triage ("   {0,4}x  {1}" -f $dm.Count, $dm.Name) }
    $subjects = $sm | Where-Object Subject | Group-Object Subject | Sort-Object Count -Descending | Select-Object -First 8
    if ($subjects) {
        Add-Triage "Top subjects:"
        foreach ($sj in $subjects) { Add-Triage ("   {0,4}x  {1}" -f $sj.Count, $sj.Name) }
    }
    $firstSent = ($sm | Sort-Object Received | Select-Object -First 1).Received
    $lastSent  = ($sm | Sort-Object Received | Select-Object -Last 1).Received
    Add-Triage ("First/last sent : {0:yyyy-MM-dd HH:mm} -> {1:yyyy-MM-dd HH:mm}" -f $firstSent, $lastSent)
}

# ---- Forwarding (SUSPICIOUS - left in place) ----
Add-TriageHeader 'MAILBOX FORWARDING  (NOT changed by this script)'
if ($mbx -and ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress)) {
    Add-Triage "!! SUSPICIOUS: mailbox-level forwarding is SET" 'Red'
    if ($mbx.ForwardingAddress)     { Add-Triage ("   ForwardingAddress          : {0}" -f $mbx.ForwardingAddress) 'Red' }
    if ($mbx.ForwardingSmtpAddress) { Add-Triage ("   ForwardingSmtpAddress      : {0}" -f $mbx.ForwardingSmtpAddress) 'Red' }
    Add-Triage ("   DeliverToMailboxAndForward : {0}" -f $mbx.DeliverToMailboxAndForward) 'Red'
    Add-Triage "   -> Left in place for manual review. Clear with: Set-Mailbox -Identity '$UserPrincipalName' -ForwardingAddress `$null -ForwardingSmtpAddress `$null -DeliverToMailboxAndForward `$false" 'DarkYellow'
} elseif ($mbx) {
    Add-Triage "No mailbox-level forwarding configured." 'Green'
} else {
    Add-Triage "Forwarding config NOT collected." 'DarkYellow'
}

# ---- Inbox rules (SUSPICIOUS - left in place) ----
Add-TriageHeader 'INBOX RULES  (NOT changed by this script)'
$sr = @($suspiciousRules)
Add-Triage ("Total rules: {0}   Suspicious: {1}" -f @($script:inboxRules).Count, $sr.Count) $(if ($sr.Count) { 'Red' } else { 'Green' })
foreach ($r in $sr) {
    $why = @()
    if ($r.DeleteMessage -eq $true)        { $why += 'deletes mail' }
    if ($r.RedirectTo)                     { $why += "redirects to $($r.RedirectTo)" }
    if ($r.ForwardTo)                      { $why += "forwards to $($r.ForwardTo)" }
    if ($r.ForwardAsAttachmentTo)          { $why += "forwards (attachment) to $($r.ForwardAsAttachmentTo)" }
    if ($r.MoveToFolder)                   { $why += "moves to '$($r.MoveToFolder)'" }
    if ($r.MarkAsRead -eq $true)           { $why += 'marks read' }
    $cond = @()
    if ($r.From)                 { $cond += "from: $($r.From)" }
    if ($r.SubjectContainsWords) { $cond += "subject~: $($r.SubjectContainsWords)" }
    if ($r.BodyContainsWords)    { $cond += "body~: $($r.BodyContainsWords)" }
    Add-Triage ("!! '{0}'  enabled={1}  priority={2}" -f $r.Name, $r.Enabled, $r.Priority) 'Red'
    Add-Triage ("      actions : {0}" -f ($why -join '; ')) 'Red'
    if ($cond) { Add-Triage ("      when    : {0}" -f ($cond -join '; ')) 'Red' }
}
if ($sr.Count) {
    Add-Triage "   -> Left in place for manual review. Disable with:" 'DarkYellow'
    foreach ($r in $sr) {
        $ruleRef = if ($r.RuleIdentity) { $r.RuleIdentity } else { $r.Identity }
        Add-Triage ("      Disable-InboxRule -Mailbox '{0}' -Identity '{1}'   # '{2}'" -f $UserPrincipalName, $ruleRef, $r.Name) 'DarkYellow'
    }
}

# ---- Delegation / protocols / OAuth ----
Add-TriageHeader 'DELEGATION, PROTOCOLS, OAUTH'
Add-Triage ("FullAccess grants : {0}{1}" -f @($script:perms).Count,  $(if ($script:perms)  { '  -> ' + (($script:perms.User)     -join ', ') } else { '' })) $(if ($script:perms)  { 'Red' } else { 'Gray' })
Add-Triage ("SendAs grants     : {0}{1}" -f @($script:sendAs).Count, $(if ($script:sendAs) { '  -> ' + (($script:sendAs.Trustee) -join ', ') } else { '' })) $(if ($script:sendAs) { 'Red' } else { 'Gray' })
if ($script:cas) {
    Add-Triage ("Protocols         : IMAP={0} POP={1} ActiveSync={2} OWA={3} MAPI={4} EWS={5} SMTPAuthDisabled={6}" -f `
        $script:cas.ImapEnabled, $script:cas.PopEnabled, $script:cas.ActiveSyncEnabled, $script:cas.OwaEnabled,
        $script:cas.MAPIEnabled, $script:cas.EwsEnabled, $script:cas.SmtpClientAuthenticationDisabled) $(if ($script:cas.ImapEnabled -or $script:cas.PopEnabled) { 'Yellow' } else { 'Gray' })
}
Add-Triage ("OAuth grants      : {0} total, {1} with mail scopes{2}" -f @($script:grants).Count, @($script:mailScoped).Count,
    $(if ($script:mailScoped) { '  -> ' + (($script:mailScoped.App | Sort-Object -Unique) -join ', ') } else { '' })) $(if ($script:mailScoped) { 'Yellow' } else { 'Gray' })

# ---- MFA ----
Add-TriageHeader 'MFA / AUTHENTICATION METHODS'
if ($script:mfaReg) {
    Add-Triage ("Registered={0}  Capable={1}  Default={2}  IsAdmin={3}" -f $script:mfaReg.IsMfaRegistered, $script:mfaReg.IsMfaCapable, $script:mfaReg.DefaultMfaMethod, $script:mfaReg.IsAdmin) `
        $(if ($script:mfaReg.IsMfaRegistered -eq $false -or $script:mfaReg.IsAdmin -eq $true) { 'Red' } else { 'Green' })
    Add-Triage ("Methods (report): {0}" -f $script:mfaReg.MethodsRegistered)
}
$mo = @($script:mfaOnly)
if ($mo.Count -eq 0 -and @($script:authMethods).Count -gt 0) { Add-Triage "!! NO non-password methods registered - password-only account" 'Red' }
foreach ($m in $mo) {
    $flag = if ($script:newAuth -and ($script:newAuth.MethodId -contains $m.MethodId)) { '  <- NEW IN WINDOW' } else { '' }
    Add-Triage ("   {0,-40} {1,-30} {2}{3}" -f $m.MethodType, $m.DisplayName, $(if ($m.CreatedDate) { $m.CreatedDate.ToString('yyyy-MM-dd') } else { '' }), $flag) $(if ($flag) { 'Red' } else { 'Gray' })
}

# ---- Devices ----
Add-TriageHeader 'ENTRA REGISTERED DEVICES'
$dv = @($script:devices); $nd = @($script:newDevices)
Add-Triage ("Registered: {0}   New in window: {1}" -f $dv.Count, $nd.Count) $(if ($nd.Count) { 'Red' } else { 'Gray' })
foreach ($d in $dv) {
    $flag = if ($nd -and ($nd.ObjectId -contains $d.ObjectId)) { '  <- NEW IN WINDOW' } else { '' }
    Add-Triage ("   {0,-30} {1,-18} {2,-14} managed={3,-5} compliant={4,-5} reg={5}{6}" -f $d.DisplayName, $d.OperatingSystem, $d.TrustType, $d.IsManaged, $d.IsCompliant,
        $(if ($d.RegistrationDate) { $d.RegistrationDate.ToString('yyyy-MM-dd') } else { '-' }), $flag) $(if ($flag) { 'Red' } else { 'Gray' })
}

# ---- Audit ----
Add-TriageHeader 'UNIFIED AUDIT LOG'
Add-Triage ("ExchangeItem events : {0}" -f $(if ($null -ne $script:auditItemCount)  { $script:auditItemCount }  else { 'NOT COLLECTED' }))
Add-Triage ("ExchangeAdmin events: {0}   rule/forwarding admin events: {1}" -f $(if ($null -ne $script:auditAdminCount) { $script:auditAdminCount } else { 'NOT COLLECTED' }), @($script:ruleEvents).Count) $(if ($script:ruleEvents) { 'Red' } else { 'Gray' })

# ---- Actions ----
Add-TriageHeader 'CONTAINMENT STATUS'
if ($Remediate) {
    Add-Triage ("Password reset x2      : {0}" -f $(if ($script:passwordReset)   { 'DONE (credential shown above, force-change at next sign-in)' } else { 'SKIPPED / WhatIf' })) $(if ($script:passwordReset)   { 'Green' } else { 'Yellow' })
    Add-Triage ("Sessions revoked x2    : {0}" -f $(if ($script:sessionsRevoked) { 'DONE (user signed out everywhere)' } else { 'SKIPPED / WhatIf' })) $(if ($script:sessionsRevoked) { 'Green' } else { 'Yellow' })
    Add-Triage ("Sign-in blocked        : {0}" -f $(if ($BlockSignIn) { 'YES' } else { 'no (-BlockSignIn not set)' }))
} else {
    Add-Triage "Read-only run - NO containment performed. Re-run with -Remediate to reset the password twice and revoke sessions." 'Yellow'
}
Add-Triage "Forwarding             : NOT changed (manual)" 'DarkYellow'
Add-Triage "Inbox rules            : NOT changed (manual)" 'DarkYellow'
Add-Triage "MFA methods / devices  : NOT changed (manual)" 'DarkYellow'

$script:triage | Out-File (Join-Path $caseFolder 'TRIAGE_SUMMARY.txt') -Encoding UTF8 -WhatIf:$false
Write-Host "`n  Written to TRIAGE_SUMMARY.txt" -ForegroundColor Cyan

# ===========================================================================
#  Findings + evidence-gap roll-up
# ===========================================================================
Write-Step "Findings summary"
if ($script:findings.Count -gt 0) {
    foreach ($f in $script:findings) {
        $c = if ($f -like '`[HIGH`]*') { 'Red' } else { 'DarkYellow' }
        Write-Host "  $f" -ForegroundColor $c
    }
    $script:findings | Out-File (Join-Path $caseFolder 'FINDINGS.txt') -Encoding UTF8 -WhatIf:$false
} else {
    Write-Host "  No automated findings raised." -ForegroundColor DarkYellow
}

Write-Step "Evidence gaps (NOT collected)"
if ($script:notCollected.Count -gt 0) {
    Write-Host "  The following sources FAILED and are absent from the evidence set." -ForegroundColor Red
    Write-Host "  Their absence is NOT evidence of a clean mailbox." -ForegroundColor Red
    foreach ($n in $script:notCollected) { Write-Host "   - $n" -ForegroundColor Red }
    $header = @(
        "NOT COLLECTED - $IssueId - $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
        "Target: $UserPrincipalName",
        "Tenant: $TenantId ($resolvedTenantId)",
        "Organization: $script:exoOrg",
        "Operator: $script:exoUpn",
        "",
        "These evidence sources FAILED to collect. Their absence must not be read",
        "as a negative finding. Resolve the cause and re-run before closing.",
        ""
    )
    ($header + $script:notCollected) | Out-File (Join-Path $caseFolder 'NOT_COLLECTED.txt') -Encoding UTF8 -WhatIf:$false
    Write-Host "`n  Written to NOT_COLLECTED.txt" -ForegroundColor Cyan
} else {
    Write-Host "  All collectors completed. Empty results are genuine." -ForegroundColor Green
}

# ===========================================================================
#  Package evidence
# ===========================================================================
Write-Step "Packaging evidence"
Stop-IRTranscript
Start-Sleep -Milliseconds 500

$zip = Join-Path $OutputPath ("{0}_evidence.zip" -f $IssueId)
if (Test-Path $zip) { Remove-Item $zip -Force -WhatIf:$false -ErrorAction SilentlyContinue }

try {
    Compress-Archive -Path (Join-Path $caseFolder '*') -DestinationPath $zip -WhatIf:$false -ErrorAction Stop
    Write-Host "`nEvidence folder : $caseFolder" -ForegroundColor Cyan
    Write-Host "Evidence zip    : $zip"          -ForegroundColor Cyan
} catch {
    Write-Host "  Direct zip failed ($($_.Exception.Message)). Retrying via staging copy..." -ForegroundColor DarkYellow
    $stage = Join-Path $env:TEMP ("IRstage_{0}_{1}" -f $IssueId,(Get-Random))
    Copy-Item $caseFolder $stage -Recurse -Force -WhatIf:$false
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -WhatIf:$false
    Remove-Item $stage -Recurse -Force -WhatIf:$false -ErrorAction SilentlyContinue
    Write-Host "`nEvidence zip (via staging): $zip" -ForegroundColor Cyan
}

if ($KeepConnected) {
    Write-Host "`nSessions left OPEN (-KeepConnected). Disconnect manually when done:" -ForegroundColor Yellow
    Write-Host "  Disconnect-MgGraph; Disconnect-ExchangeOnline -Confirm:`$false" -ForegroundColor DarkGray
} else {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Write-Host "`nSessions disconnected. Re-run with -KeepConnected if you need follow-up cmdlets." -ForegroundColor DarkGray
}

Write-Host "`nDone. Attach the zip to $IssueId. (Non-MS steps: Modus/MyPortal/KACE/SFTP done manually.)" -ForegroundColor Cyan