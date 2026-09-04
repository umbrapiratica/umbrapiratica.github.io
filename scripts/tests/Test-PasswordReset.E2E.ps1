# End-to-end checks: run the whole script against a faked M365 estate and assert
# on what the operator is actually told.  Covers the containment paths that must
# never lie - a reset that failed, one that was accepted but not confirmed, and a
# block-sign-in that Graph rejected.
# Run:  pwsh -File scripts/tests/Test-PasswordReset.E2E.ps1
param([string]$Script = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-CompromisedMailboxIR.ps1'))
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot/M365Stubs.ps1"

$global:UID       = '4975e8b0-31e3-4c30-be0e-5807d156c8d6'
$global:TargetUpn = 'victim@fabrikam7391.local'
$global:OpUri     = "https://graph.microsoft.com/v1.0/users/$global:UID/authentication/operations/op1?aadgdc=DUB02P"
$script:fails = 0
$script:caseN = 0

function Invoke-Case {
    param([string]$Name, [hashtable]$World, [string[]]$Expect, [string[]]$Reject, [string[]]$ExtraArgs = @())
    $script:caseN++
    $global:GraphCalls = @(); $global:Patches = @(); $global:ResetPosts = 0
    $global:ResetAction = $World.ResetAction
    $global:OpStatus    = $World.OpStatus
    $global:OpDetail    = $World.OpDetail
    $global:PatchFails  = [bool]$World.PatchFails
    $global:LastPwdChange = $World.LastPwdChange

    $out = Join-Path ([IO.Path]::GetTempPath()) ("irtest-{0}" -f $script:caseN)
    Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
    $a = @{ TenantId='testtenant7391.onmicrosoft.com'; UserPrincipalName=$global:TargetUpn
            IssueId='CS-0001'; OutputPath=$out
            SkipTenantConfirm=$true; KeepConnected=$true; Remediate=$true }
    foreach ($x in $ExtraArgs) { $a[$x.TrimStart('-')] = $true }
    $text = (& $Script @a *>&1 | Out-String)

    Write-Host ("`n--- {0} ---" -f $Name) -ForegroundColor Cyan
    foreach ($e in $Expect) {
        if ($text -match [regex]::Escape($e)) { Write-Host "  PASS  says: $e" -ForegroundColor Green }
        else { Write-Host "  FAIL  missing: $e" -ForegroundColor Red; $script:fails++ }
    }
    if ($text -match 'HARNESS FAILURE') { Write-Host "  FAIL  a forwarding/inbox-rule write was attempted" -ForegroundColor Red; $script:fails++ }
    else { Write-Host "  PASS  forwarding and inbox rules untouched" -ForegroundColor Green }
    foreach ($r in $Reject) {
        if ($text -match [regex]::Escape($r)) { Write-Host "  FAIL  must NOT say: $r" -ForegroundColor Red; $script:fails++ }
        else { Write-Host "  PASS  never says: $r" -ForegroundColor Green }
    }
    return $text
}

$now = (Get-Date).ToUniversalTime()
$old = $now.AddDays(-30).ToString('o')
$new = $now.ToString('o')

# 1. everything works
$t = Invoke-Case 'reset succeeds, operation confirms, directory stamp moves' `
    @{ OpStatus='succeeded'; LastPwdChange=$new } `
    @('Password reset 1/2 CONFIRMED by Graph','Password reset 2/2 CONFIRMED by Graph',
      'status : CONFIRMED','NEW PASSWORD','DONE + CONFIRMED','Sessions revoked / user signed out (pass 2)') `
    @('[FAILED] password reset','NOT CONFIRMED','PASSWORD WAS NOT CHANGED')
if ($global:Patches.Count -ne 0) { Write-Host "  FAIL  PATCH used even though the action worked" -ForegroundColor Red; $script:fails++ }
else { Write-Host "  PASS  no PATCH of the user object" -ForegroundColor Green }

# 2. the user's tenant: broken UPN, PATCH always 400
$t = Invoke-Case 'broken-UPN tenant: action succeeds where PATCH 400s' `
    @{ OpStatus='succeeded'; PatchFails=$true; LastPwdChange=$new } `
    @('Password reset 2/2 CONFIRMED by Graph','via resetPassword action','NEW PASSWORD','DONE + CONFIRMED') `
    @('[FAILED] password reset','PATCH passwordProfile ->','PASSWORD WAS NOT CHANGED')
if ($global:Patches.Count -ne 0) { Write-Host "  FAIL  PATCHed the user object on a tenant where PATCH 400s" -ForegroundColor Red; $script:fails++ }
else { Write-Host "  PASS  never PATCHes the broken user object" -ForegroundColor Green }

# 3. both routes fail -> no password may be handed over
$t = Invoke-Case 'operation FAILS and PATCH 400s -> nothing handed over' `
    @{ OpStatus='failed'; OpDetail='password does not meet policy'; PatchFails=$true; LastPwdChange=$old } `
    @('[FAILED] password reset 1/2','PASSWORD WAS NOT CHANGED','account is still on the attacker-known password',
      'HTTP 400 Request_BadRequest: Property userPrincipalName is invalid.','password does not meet policy',
      'FAILED - account NOT contained','Graph rejected the stored userPrincipalName') `
    @('NEW PASSWORD','deliver out-of-band','Press ENTER once the credential')

# 4. 202 accepted, no Location header -> handed over but flagged UNCONFIRMED
$t = Invoke-Case '202 with no operation URL -> reported UNCONFIRMED' `
    @{ ResetAction='nolocation'; LastPwdChange=$new } `
    @('ACCEPTED but NOT CONFIRMED','status : NOT CONFIRMED','VERIFY this password works',
      'NEW PASSWORD','ACCEPTED but NOT CONFIRMED - verify the credential works before closing') `
    @('status : CONFIRMED')

# 5. operation says succeeded but the directory stamp never moves
$t = Invoke-Case 'operation succeeds but lastPasswordChangeDateTime never moves' `
    @{ OpStatus='succeeded'; LastPwdChange=$old } `
    @('status : CONFIRMED','lastPasswordChangeDateTime has NOT moved','VERIFY the credential works',
      'the new password may not have taken effect') `
    @()

# 6. -BlockSignIn on a tenant where PATCH 400s
$t = Invoke-Case '-BlockSignIn against a user Graph will not PATCH' `
    @{ OpStatus='succeeded'; PatchFails=$true; LastPwdChange=$new } `
    @('[FAILED] sign-in NOT blocked','BLOCK SIGN-IN FAILED','FAILED - account can still sign in') `
    @('Account sign-in BLOCKED.') `
    @('-BlockSignIn')

# 7. dry run
$t = Invoke-Case '-WhatIf plans the reset and executes nothing' `
    @{ OpStatus='succeeded'; LastPwdChange=$new } `
    @('resetPassword','polled until succeeded/failed','lastPasswordChangeDateTime   # before/after cross-check',
      'NOTHING was executed') `
    @('NEW PASSWORD','Password reset 1/2') `
    @('-WhatIf')
if ($global:ResetPosts -ne 0) { Write-Host "  FAIL  -WhatIf still POSTed a reset" -ForegroundColor Red; $script:fails++ }
else { Write-Host "  PASS  -WhatIf issued no reset call" -ForegroundColor Green }

Write-Host ""
if ($script:fails) { Write-Host "$script:fails FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "all end-to-end checks passed" -ForegroundColor Green
