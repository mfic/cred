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
    'FileIo.ps1'
    'Entry.ps1'
    'Json.ps1'
    'Process.ps1'
    'Secrets.ps1'
    'Providers.ps1'
    'Identity.ps1'
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

# This list and FunctionsToExport in Cred.psd1 are intersected at load, so a
# function named in only one of them is simply not exported. Reading the
# manifest here instead would need Import-PowerShellDataFile, which does not
# exist on Windows PowerShell 5.1; the two lists are held together by
# 'exports exactly what the manifest declares' in tests/Unit.Tests.ps1
# instead, which fails rather than letting them drift.
$exported = @(
    'Add-CredRecipient'
    'Assert-CredReadModeApplies'
    'ConvertTo-CredCallArguments'
    'ConvertTo-CredMaskedValue'
    'ConvertTo-CredValueStat'
    'Export-Cred'
    'Export-CredFile'
    'Get-Cred'
    'Get-CredAgentBrief'
    'Get-CredCredential'
    'Get-CredEnvironment'
    'Get-CredCommandSpec'
    'Get-CredEnvironmentReport'
    'Get-CredExistingCredentialCount'
    'Get-CredExitCode'
    'Get-CredIdentityInfo'
    'Get-CredIdentityProtection'
    'Get-CredList'
    'Get-CredProject'
    'Get-CredProvider'
    'Get-CredRecipient'
    'Get-CredStoreEnvironment'
    'Import-Cred'
    'Initialize-CredProject'
    'Invoke-CredCommand'
    'Invoke-CredReadMode'
    'New-CredIdentity'
    'Open-CredStore'
    'Protect-CredIdentity'
    'Read-CredCommandOptions'
    'Read-CredOptions'
    'Read-CredStdinSecret'
    'Read-CredValue'
    'Register-CredProject'
    'Register-CredProvider'
    'Remove-Cred'
    'Remove-CredRecipient'
    'Repair-CredHealth'
    'Resolve-CredReadMode'
    'Set-Cred'
    'Split-CredArgv'
    'Split-CredReference'
    'Test-CredHealth'
    'Unprotect-CredIdentity'
    'Unregister-CredProject'
    'Update-CredAgentBrief'
)

Export-ModuleMember -Function $exported -Alias @()
