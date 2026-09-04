# Unit checks for the password-reset plumbing in Invoke-CompromisedMailboxIR.ps1.
# The functions under test are lifted out of the script by AST so the checks run
# without a tenant, without the Graph/EXO modules, and without executing the
# script itself.  Run:  pwsh -File scripts/tests/Test-PasswordReset.Unit.ps1
$ErrorActionPreference = 'Stop'
$script:fails = 0
function Assert($cond, $label) {
    if ($cond) { Write-Host "  PASS  $label" -ForegroundColor Green }
    else       { Write-Host "  FAIL  $label" -ForegroundColor Red; $script:fails++ }
}

# --- lift the helper functions out of the script under test ----------------
$path = if ($args[0]) { (Resolve-Path $args[0]).Path } else { Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-CompromisedMailboxIR.ps1' }
$tok = $null; $err = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tok, [ref]$err)
if ($err) { throw "parse errors" }
$want = 'Get-IRGraphError','Get-IRHeaderValue','Wait-IRPasswordResetOperation','Get-IRLastPasswordChange','Invoke-IRPasswordReset','Resolve-ParamName','New-IRPassword'
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    if ($want -contains $f.Name) { . ([scriptblock]::Create($f.Extent.Text)) }
}
$script:PasswordMethodId = '28c10230-6103-485e-b985-444c60001490'
$script:CanReadGraphHeaders = $true
$script:PwdOpTimeoutSec = 30

# --- fake Graph -------------------------------------------------------------
$script:calls = @()
function New-GraphError([int]$code, [string]$errcode, [string]$msg) {
    $body = @{ error = @{ code = $errcode; message = $msg } } | ConvertTo-Json -Compress
    $text = "PATCH https://graph.microsoft.com/v1.0/users/x`nHTTP/1.1 $code Bad Request`nDate: now`nContent-Type: application/json`n$body"
    $ex = New-Object System.Exception $text
    $rec = New-Object System.Management.Automation.ErrorRecord $ex, 'GraphErr', 'InvalidOperation', $null
    return $rec
}
function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string]$Method, [string]$Uri, $Body, [string]$ContentType, $OutputType,
          [string]$ResponseHeadersVariable, [string]$StatusCodeVariable)
    $script:calls += "$Method $Uri"
    $r = & $script:graphHandler $Method $Uri $Body
    if ($ResponseHeadersVariable -and $r.Headers) { Set-Variable -Name $ResponseHeadersVariable -Value $r.Headers -Scope 1 }
    if ($r.Throw) { throw $r.Throw }
    return $r.Body
}
function Get-GraphOnce { param([string]$Uri) Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject }

$script:OPURI = 'https://graph.microsoft.com/v1.0/users/u1/authentication/operations/op1?aadgdc=DUB02P'

Write-Host "`n== Get-IRGraphError ==" -ForegroundColor Cyan
$e = New-GraphError 400 'Request_BadRequest' 'Property userPrincipalName is invalid.'
$t = Get-IRGraphError $e
Assert ($t -eq 'HTTP 400 Request_BadRequest: Property userPrincipalName is invalid.') "extracts code+message (got: $t)"
$plain = New-Object System.Management.Automation.ErrorRecord ((New-Object System.Exception "boom`nsecond line")), 'x', 'NotSpecified', $null
Assert ((Get-IRGraphError $plain) -eq 'boom') 'falls back to first line of a non-Graph error'

Write-Host "`n== Get-IRHeaderValue ==" -ForegroundColor Cyan
Assert ((Get-IRHeaderValue @{ 'Location' = @($script:OPURI) } 'Location') -eq $OPURI) 'string[] header value'
Assert ((Get-IRHeaderValue @{ 'location' = $OPURI } 'Location') -eq $OPURI)   'case-insensitive key'
Assert ($null -eq (Get-IRHeaderValue @{ 'X' = 'y' } 'Location'))               'missing header -> null'
Assert ($null -eq (Get-IRHeaderValue $null 'Location'))                        'null headers -> null'

Write-Host "`n== Wait-IRPasswordResetOperation ==" -ForegroundColor Cyan
$script:n = 0
$script:graphHandler = { param($m,$u,$b)
    $script:n++
    $st = if ($script:n -ge 3) { 'succeeded' } else { 'running' }
    @{ Body = [pscustomobject]@{ status = $st; statusDetail = '' } } }
$r = Wait-IRPasswordResetOperation -OperationUri $script:OPURI -TimeoutSeconds 30
Assert ($r.State -eq 'succeeded') "polls until succeeded (got $($r.State) after $script:n reads)"

$script:graphHandler = { param($m,$u,$b) @{ Body = [pscustomobject]@{ status = 'failed'; statusDetail = 'password does not meet policy' } } }
$r = Wait-IRPasswordResetOperation -OperationUri $script:OPURI -TimeoutSeconds 30
Assert ($r.State -eq 'failed' -and $r.Detail -match 'policy') 'returns failed + detail'

$script:graphHandler = { param($m,$u,$b) @{ Body = [pscustomobject]@{ status = 'running'; statusDetail = '' } } }
$sw = [Diagnostics.Stopwatch]::StartNew()
$r = Wait-IRPasswordResetOperation -OperationUri $script:OPURI -TimeoutSeconds 7
$sw.Stop()
Assert ($r.State -eq 'unconfirmed' -and $r.Detail -match "still 'running'") "times out as unconfirmed (got $($r.State))"
Assert ($sw.Elapsed.TotalSeconds -lt 20) "honours the timeout ($([int]$sw.Elapsed.TotalSeconds)s)"

$script:n = 0
$script:graphHandler = { param($m,$u,$b)
    $script:n++
    if ($script:n -le 3) { @{ Throw = (New-GraphError 404 'ResourceNotFound' 'operation not found') } }
    else { @{ Body = [pscustomobject]@{ status = 'succeeded'; statusDetail = '' } } } }
$r = Wait-IRPasswordResetOperation -OperationUri $script:OPURI -TimeoutSeconds 40
Assert ($r.State -eq 'succeeded') 'rides out a 404 while the operation record catches up'

$script:graphHandler = { param($m,$u,$b) @{ Throw = (New-GraphError 403 'Authorization_RequestDenied' 'Insufficient privileges') } }
$r = Wait-IRPasswordResetOperation -OperationUri $script:OPURI -TimeoutSeconds 40
Assert ($r.State -eq 'unconfirmed' -and $r.Detail -match 'Insufficient privileges') 'a 403 stops polling immediately'

Write-Host "`n== Invoke-IRPasswordReset ==" -ForegroundColor Cyan
# 1. action accepted, operation succeeds
$script:calls = @()
$script:graphHandler = { param($m,$u,$b)
    if ($u -match 'resetPassword') { return @{ Headers = @{ Location = @($script:OPURI) } } }
    if ($u -match '/operations/')  { return @{ Body = [pscustomobject]@{ status = 'succeeded' } } }
    throw "unexpected $m $u" }
$r = Invoke-IRPasswordReset -UserId 'u1' -Password 'Pw!12345678901234'
Assert ($r.Success -and $r.Confirmed -and $r.Method -eq 'resetPassword action') 'happy path -> Success + Confirmed'
Assert (-not ($script:calls -match '^PATCH')) 'PATCH is never attempted once the action works'

# 2. broken-UPN tenant: PATCH would 400, action works
$script:graphHandler = { param($m,$u,$b)
    if ($u -match 'resetPassword') { return @{ Headers = @{ Location = @($script:OPURI) } } }
    if ($u -match '/operations/')  { return @{ Body = [pscustomobject]@{ status = 'succeeded' } } }
    return @{ Throw = (New-GraphError 400 'Request_BadRequest' 'Property userPrincipalName is invalid.') } }
$r = Invoke-IRPasswordReset -UserId 'u1' -Password 'Pw!12345678901234'
Assert ($r.Success -and $r.Confirmed) 'broken-UPN tenant still gets a confirmed reset'

# 3. 202 with no Location header -> accepted but UNCONFIRMED
$script:graphHandler = { param($m,$u,$b)
    if ($u -match 'resetPassword') { return @{ Headers = @{ 'request-id' = 'abc' } } }
    throw "unexpected $m $u" }
$r = Invoke-IRPasswordReset -UserId 'u1' -Password 'Pw!12345678901234'
Assert ($r.Success -and -not $r.Confirmed -and $r.Detail -match 'no operation URL') '202 without Location -> Success but NOT Confirmed'

# 4. accepted then the operation FAILS, PATCH also 400 -> total failure
$script:graphHandler = { param($m,$u,$b)
    if ($u -match 'resetPassword') { return @{ Headers = @{ Location = @($script:OPURI) } } }
    if ($u -match '/operations/')  { return @{ Body = [pscustomobject]@{ status = 'failed'; statusDetail = 'banned password' } } }
    return @{ Throw = (New-GraphError 400 'Request_BadRequest' 'Property userPrincipalName is invalid.') } }
$r = Invoke-IRPasswordReset -UserId 'u1' -Password 'Pw!12345678901234'
Assert (-not $r.Success -and -not $r.Confirmed) 'operation failed + PATCH failed -> Success=$false'
Assert (($r.Errors -join ' ') -match 'banned password' -and ($r.Errors -join ' ') -match 'userPrincipalName') 'both route failures are reported'

# 5. accepted then FAILS, but PATCH works -> confirmed via PATCH
$script:graphHandler = { param($m,$u,$b)
    if ($u -match 'resetPassword') { return @{ Headers = @{ Location = @($script:OPURI) } } }
    if ($u -match '/operations/')  { return @{ Body = [pscustomobject]@{ status = 'failed'; statusDetail = 'writeback error' } } }
    return @{ Body = $null } }
$r = Invoke-IRPasswordReset -UserId 'u1' -Password 'Pw!12345678901234'
Assert ($r.Success -and $r.Confirmed -and $r.Method -eq 'PATCH passwordProfile') 'falls back to PATCH after a failed operation'

# 6. action 403, PATCH works
$script:graphHandler = { param($m,$u,$b)
    if ($u -match 'resetPassword') { return @{ Throw = (New-GraphError 403 'Authorization_RequestDenied' 'Insufficient privileges') } }
    return @{ Body = $null } }
$r = Invoke-IRPasswordReset -UserId 'u1' -Password 'Pw!12345678901234'
Assert ($r.Success -and $r.Method -eq 'PATCH passwordProfile' -and ($r.Errors -join ' ') -match 'Insufficient privileges') '403 on the action falls back to PATCH'

# 7. no header-capture support in the installed module
$script:CanReadGraphHeaders = $false
$script:graphHandler = { param($m,$u,$b) if ($u -match 'resetPassword') { return @{ Body = $null } }; throw "unexpected $m $u" }
$r = Invoke-IRPasswordReset -UserId 'u1' -Password 'Pw!12345678901234'
Assert ($r.Success -and -not $r.Confirmed -and $r.Detail -match 'ResponseHeadersVariable') 'old module build -> Success but NOT Confirmed'
$script:CanReadGraphHeaders = $true
$script:PwdOpTimeoutSec = 30

Write-Host "`n== Get-IRLastPasswordChange ==" -ForegroundColor Cyan
$script:graphHandler = { param($m,$u,$b) @{ Body = [pscustomobject]@{ lastPasswordChangeDateTime = '2026-09-04T15:00:00Z' } } }
Assert ((Get-IRLastPasswordChange -UserId 'u1') -is [datetime]) 'parses the timestamp'
$script:graphHandler = { param($m,$u,$b) @{ Throw = (New-GraphError 403 'Authorization_RequestDenied' 'nope') } }
Assert ($null -eq (Get-IRLastPasswordChange -UserId 'u1')) 'unreadable -> $null, never throws'

Write-Host ""
if ($script:fails) { Write-Host "$script:fails FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "all unit checks passed" -ForegroundColor Green
