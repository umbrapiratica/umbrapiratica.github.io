# ADRemedy - read-only Active Directory review with remediation guidance.
# Dot-sources Private helpers and checks first, then Public commands.

$script:ADRemedyModuleRoot = $PSScriptRoot
$script:ADRemedyCatalog = $null

$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue)
$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in ($private + $public)) {
    try {
        . $file.FullName
    } catch {
        Write-Error "Failed to import '$($file.FullName)': $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function $public.BaseName
