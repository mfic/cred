#requires -Version 5.1

function Get-CredCredential {
    <#
        .SYNOPSIS
        Return a credential as a native [PSCredential].

        .DESCRIPTION
        The PowerShell-native access path. The password is materialised as a
        SecureString and never travels through the pipeline as plain text.

        A 'secret' credential (an API key with no username) still works: pass
        -UserName to supply whatever username the API expects, otherwise the
        credential's own key name is used. Plenty of .NET and PowerShell APIs
        want a PSCredential even when only the password carries meaning.

        .EXAMPLE
        $cred = Get-CredCredential acme-api/db
        Invoke-Sqlcmd -ServerInstance db01 -Credential $cred

        .EXAMPLE
        $cred = Get-CredCredential acme-api/gh -UserName token
        Invoke-RestMethod $url -Authentication Basic -Credential $cred
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [string]$UserName,
        [string]$Project,
        [string]$Path
    )

    $ref = Split-CredReference -Reference $Name
    if ($ref.Project -and -not $Project) { $Project = $ref.Project }
    $key = $ref.Key

    $ctx    = Resolve-CredProject -Name $Project -Path $Path
    $values = Read-CredStoreValues -Project $ctx
    $entry  = Get-CredEntryOrThrow -Project $ctx -Key $key -Values $values

    if (-not $UserName) {
        $UserName = if ($entry.Contains('user') -and $entry['user']) { [string]$entry['user'] } else { $key }
    }
    $secure = ConvertTo-CredSecureString -PlainText ([string]$entry['secret'])

    return [System.Management.Automation.PSCredential]::new($UserName, $secure)
}
