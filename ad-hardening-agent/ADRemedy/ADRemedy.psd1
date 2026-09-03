@{
    RootModule        = 'ADRemedy.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b7d4c1e2-9a53-4f18-8c6d-2e5f7a91b304'
    Author            = 'ADRemedy'
    Description       = 'Read-only Active Directory review that explains how to remediate what it finds, including BloodHound ACL and attack-path edges. Runs its own LDAP checks, imports PingCastle, SharpHound and CSV scan output, and renders a self-contained HTML report built for teaching.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-ADRemedyAudit',
        'Import-ADRemedyFindings',
        'Get-ADRemedyGuidance',
        'New-ADRemedyReport'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('ActiveDirectory', 'Security', 'Audit', 'BlueTeam', 'Remediation', 'BloodHound')
            ReleaseNotes = 'Initial release: 39 catalog entries covering 42 BloodHound edges, 22 live checks, PingCastle/SharpHound/CSV import, HTML report.'
        }
    }
}
