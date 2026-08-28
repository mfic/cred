@{
    RootModule        = 'Cred.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b0f4c5a2-6d31-4a7e-9c58-2f1e7d8a3b64'
    Author            = 'Jan Quest'
    CompanyName       = 'Unknown'
    Copyright         = '(c) Jan Quest. All rights reserved.'
    Description       = 'Per-repository encrypted credentials for PowerShell 5.1 and 7. Secrets live in an age-encrypted file committed alongside the code; plaintext never touches disk.'

    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @(
        'Add-CredRecipient'
        'Export-Cred'
        'Export-CredFile'
        'Get-Cred'
        'Get-CredAgentBrief'
        'Get-CredCredential'
        'Get-CredEnvironment'
        'Get-CredEnvironmentReport'
        'Get-CredExitCode'
        'Get-CredIdentityInfo'
        'Get-CredList'
        'Get-CredProject'
        'Get-CredProvider'
        'Get-CredRecipient'
        'Get-CredStoreEnvironment'
        'Import-Cred'
        'Initialize-CredProject'
        'Invoke-CredCommand'
        'New-CredIdentity'
        'Open-CredStore'
        'Protect-CredIdentity'
        'Read-CredOptions'
        'Read-CredValue'
        'Register-CredProvider'
        'Remove-Cred'
        'Remove-CredRecipient'
        'Repair-CredHealth'
        'Set-Cred'
        'Split-CredArgv'
        'Split-CredReference'
        'Test-CredHealth'
        'Unprotect-CredIdentity'
        'Unregister-CredProject'
        'Update-CredAgentBrief'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('secrets', 'credentials', 'age', 'encryption', 'security', 'Windows', 'Linux', 'macOS')
            LicenseUri   = ''
            ProjectUri   = ''
            ReleaseNotes = 'Initial release: age-backed per-repo credential store with get / exec / PSCredential access paths.'
        }
    }
}
