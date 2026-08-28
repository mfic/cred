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

    $entry = Get-CredEntryView -Name $Name -Project $Project -Path $Path
    $key   = $entry.Key
    $ctx   = $entry.Context
    $view  = $entry.View

    # This used to ignore the kind entirely, so asking for a PSCredential over
    # a binary file credential handed back a base64 blob as the password and
    # looked like it had worked. Same rule as Get-Cred: text is returnable,
    # binary is not a string.
    if ($view.IsBinary) {
        throw (New-CredBinaryContentError -ProjectName $ctx.Name -Key $key -Noun 'a password')
    }

    if (-not $UserName) {
        $UserName = if ($view.Fields.Contains('user') -and $view.Fields['user']) { [string]$view.Fields['user'] } else { $key }
    }
    $secure = ConvertTo-CredSecureString -PlainText ([string]$view.Fields['secret'])

    return [System.Management.Automation.PSCredential]::new($UserName, $secure)
}
