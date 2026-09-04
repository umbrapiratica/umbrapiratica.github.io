# Fakes for every Exchange Online / Microsoft Graph command the runbook calls.
# Set-Mailbox, Disable-InboxRule and Remove-InboxRule THROW on purpose: forwarding
# and inbox rules are evidence and the script must never write to them.
# ---- fake M365 estate: every cmdlet the script touches ----------------------
function Get-Module { param([switch]$ListAvailable,[string]$Name,[Parameter(ValueFromRemainingArguments)]$Rest)
    $n = if ($Name) { $Name } else { [string]$Rest }
    [pscustomobject]@{ Name = $n; Version = [version]'3.9.0' } }
function Import-Module { param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Start-Transcript { param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Stop-Transcript  { param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Start-Sleep      { param([Parameter(ValueFromRemainingArguments)]$Rest) }   # tests must not idle
function Read-Host        { param([Parameter(ValueFromRemainingArguments)]$Rest) 'yes' }

function Connect-ExchangeOnline    { param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Disconnect-ExchangeOnline { param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Get-ConnectionInformation { param([Parameter(ValueFromRemainingArguments)]$Rest)
    [pscustomobject]@{ State='Connected'; TenantID='11111111-2222-3333-4444-555555555555'; UserPrincipalName='admin@msp.com'; Organization='' } }
function Get-OrganizationConfig    { param([Parameter(ValueFromRemainingArguments)]$Rest) [pscustomobject]@{ DisplayName='Contoso Ltd'; Name='contoso' } }
function Connect-MgGraph    { param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Disconnect-MgGraph { param([Parameter(ValueFromRemainingArguments)]$Rest) }
function Get-MgContext      { param([Parameter(ValueFromRemainingArguments)]$Rest)
    [pscustomobject]@{ TenantId='11111111-2222-3333-4444-555555555555'; Account='admin@msp.com'; Scopes=@('User.ReadWrite.All') } }

function Get-MgUser { param([Parameter(ValueFromRemainingArguments)]$Rest)
    [pscustomobject]@{ Id=$global:UID; DisplayName='Victim User'; UserPrincipalName='victim@contoso.local'; AccountEnabled=$true } }
function Get-AdminAuditLogConfig { param([Parameter(ValueFromRemainingArguments)]$Rest) [pscustomobject]@{ UnifiedAuditLogIngestionEnabled=$true } }
function Get-Mailbox { param([Parameter(ValueFromRemainingArguments)]$Rest)
    [pscustomobject]@{ AuditEnabled=$true; AuditLogAgeLimit='90.00:00:00'; DisplayName='Victim User'
        PrimarySmtpAddress='victim@contoso.com'; ForwardingSmtpAddress='smtp:attacker@evil.tld'
        ForwardingAddress=$null; DeliverToMailboxAndForward=$true; RecipientTypeDetails='UserMailbox' } }
function Set-Mailbox { throw 'HARNESS FAILURE: Set-Mailbox must never be called - forwarding is evidence.' }
function Disable-InboxRule { throw 'HARNESS FAILURE: Disable-InboxRule must never be called - rules are evidence.' }
function Remove-InboxRule  { throw 'HARNESS FAILURE: Remove-InboxRule must never be called - rules are evidence.' }
function Get-InboxRule { param([Parameter(ValueFromRemainingArguments)]$Rest)
    @([pscustomobject]@{ Name='...'; Enabled=$true; Description='move to RSS'; ForwardTo=$null; RedirectTo='attacker@evil.tld'
        ForwardAsAttachmentTo=$null; MoveToFolder='RSS Feeds'; DeleteMessage=$true; MarkAsRead=$true; StopProcessingRules=$true; Identity='r1' }) }
function Get-MailboxPermission  { param([Parameter(ValueFromRemainingArguments)]$Rest) @() }
function Get-RecipientPermission{ param([Parameter(ValueFromRemainingArguments)]$Rest) @() }
function Get-CASMailbox { param([Parameter(ValueFromRemainingArguments)]$Rest)
    [pscustomobject]@{ ImapEnabled=$true; PopEnabled=$false; SmtpClientAuthenticationDisabled=$false
        OwaEnabled=$true; ActiveSyncEnabled=$true; EwsEnabled=$true; MAPIEnabled=$true } }
function Get-MessageTrace { param([Parameter(ValueFromRemainingArguments)]$Rest) @() }
function Search-UnifiedAuditLog { param([Parameter(ValueFromRemainingArguments)]$Rest) @() }
function Get-MgAuditLogSignIn { param([Parameter(ValueFromRemainingArguments)]$Rest) @() }
function Get-MgUserAuthenticationMethod { param([Parameter(ValueFromRemainingArguments)]$Rest)
    @([pscustomobject]@{ Id='m-phone'; AdditionalProperties=@{ '@odata.type'='#microsoft.graph.phoneAuthenticationMethod'; phoneNumber='+1 555' } }
      [pscustomobject]@{ Id='28c10230-6103-485e-b985-444c60001490'; AdditionalProperties=@{ '@odata.type'='#microsoft.graph.passwordAuthenticationMethod' } }) }
function Get-MgUserRegisteredDevice { param([Parameter(ValueFromRemainingArguments)]$Rest) @() }
function Get-MgDevice { param([Parameter(ValueFromRemainingArguments)]$Rest) $null }
function Get-MgUserOauth2PermissionGrant { param([Parameter(ValueFromRemainingArguments)]$Rest) @() }
function Get-MgServicePrincipal { param([Parameter(ValueFromRemainingArguments)]$Rest) $null }
function Revoke-MgUserSignInSession { param([Parameter(ValueFromRemainingArguments)]$Rest) $true }

# ---- fake Graph REST -------------------------------------------------------
function New-GraphError([int]$code,[string]$errcode,[string]$msg) {
    $body = @{ error = @{ code=$errcode; message=$msg } } | ConvertTo-Json -Compress
    $ex = New-Object System.Exception ("HTTP/1.1 $code Bad Request`nContent-Type: application/json`n$body")
    New-Object System.Management.Automation.ErrorRecord $ex,'GraphErr','InvalidOperation',$null
}
function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string]$Method,[string]$Uri,$Body,[string]$ContentType,$OutputType,
          [string]$ResponseHeadersVariable,[string]$StatusCodeVariable,
          [Parameter(ValueFromRemainingArguments)]$Rest)
    $global:GraphCalls += ,"$Method $Uri"

    if ($Method -eq 'GET' -and $Uri -match 'verifiedDomains') {
        return [pscustomobject]@{ value = @([pscustomobject]@{ verifiedDomains = @([pscustomobject]@{ name='contoso.com' }) }) } }
    if ($Method -eq 'GET' -and $Uri -match 'lastPasswordChangeDateTime') {
        return [pscustomobject]@{ lastPasswordChangeDateTime = $global:LastPwdChange } }
    if ($Method -eq 'GET' -and $Uri -match 'onPremisesSyncEnabled') {
        return [pscustomobject]@{ userPrincipalName=$global:TargetUpn; onPremisesSyncEnabled=$true; userType='Member'; accountEnabled=$true } }
    if ($Method -eq 'GET' -and $Uri -match 'userRegistrationDetails') {
        return [pscustomobject]@{ isMfaRegistered=$true; isMfaCapable=$true; isSsprRegistered=$false
            defaultMfaMethod='mobilePhone'; methodsRegistered=@('mobilePhone'); lastUpdatedDateTime='2026-09-01T00:00:00Z' } }
    if ($Method -eq 'GET' -and $Uri -match 'auditLogs/signIns') { return [pscustomobject]@{ value=@() } }

    if ($Method -eq 'POST' -and $Uri -match 'resetPassword') {
        $global:ResetPosts++
        if ($global:ResetAction -eq 'throw403') { throw (New-GraphError 403 'Authorization_RequestDenied' 'Insufficient privileges to complete the operation.') }
        if ($global:ResetAction -eq 'nolocation') { return $null }
        if ($ResponseHeadersVariable) { Set-Variable -Name $ResponseHeadersVariable -Value @{ Location = @($global:OpUri) } -Scope 1 }
        return $null
    }
    if ($Method -eq 'GET' -and $Uri -match '/authentication/operations/') {
        return [pscustomobject]@{ status=$global:OpStatus; statusDetail=$global:OpDetail } }

    if ($Method -eq 'PATCH' -and $Uri -match '/users/') {
        $global:Patches += ,($Body | ConvertTo-Json -Compress -Depth 5)
        if ($global:PatchFails) { throw (New-GraphError 400 'Request_BadRequest' 'Property userPrincipalName is invalid.') }
        return $null
    }
    if ($Method -eq 'DELETE') { return $null }
    return $null
}
