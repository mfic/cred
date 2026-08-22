#requires -Version 5.1
<#
    Cred -- per-repository encrypted credentials for PowerShell 5.1 and 7.

    Load order matters: Private first (Platform before everything, because the
    rest asks it what OS this is), then Public.
#>

Set-StrictMode -Version 1.0

$script:CredModuleRoot = $PSScriptRoot

$privateOrder = @(
    'Platform.ps1'
    'Errors.ps1'
    'Json.ps1'
    'Process.ps1'
    'Secrets.ps1'
    'Providers.ps1'
    'Config.ps1'
    'Store.ps1'
)

foreach ($name in $privateOrder) {
    $file = Join-Path $PSScriptRoot "Private\$name"
    if (-not (Test-Path -LiteralPath $file)) { throw "Cred module is incomplete: missing Private\$name" }
    . $file
}

$public = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue |
            Sort-Object Name)
foreach ($file in $public) { . $file.FullName }

$exported = @(
    'Add-CredRecipient'
    'Get-Cred'
    'Get-CredAgentBrief'
    'Get-CredCredential'
    'Get-CredEnvironment'
    'Get-CredList'
    'Get-CredProject'
    'Get-CredProvider'
    'Get-CredRecipient'
    'Initialize-CredProject'
    'Invoke-CredCommand'
    'New-CredIdentity'
    'Register-CredProvider'
    'Remove-Cred'
    'Remove-CredRecipient'
    'Repair-CredHealth'
    'Set-Cred'
    'Test-CredHealth'
    'Unregister-CredProject'
    'Update-CredAgentBrief'
)

Export-ModuleMember -Function $exported -Alias @()
