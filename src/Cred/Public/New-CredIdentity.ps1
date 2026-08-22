#requires -Version 5.1

function New-CredIdentity {
    <#
        .SYNOPSIS
        Create this machine's personal key, or show the public half of it.

        .DESCRIPTION
        The secret key is written outside every repository, into the cred home
        directory (%APPDATA%\cred on Windows, ~/.config/cred elsewhere), with
        permissions restricted to you. Nothing else in cred ever writes key
        material to disk.

        The public half is safe to share and to commit: it is what goes into a
        project's `recipients` list.

        .EXAMPLE
        New-CredIdentity
        Create a key if one does not exist and print the public half.

        .EXAMPLE
        New-CredIdentity -Show
        Print the public half of the existing key, creating nothing.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [ValidateNotNullOrEmpty()][string]$Provider = 'age',
        [string]$Path,
        [switch]$Show,
        [switch]$Force
    )

    $providerObj = Get-CredProviderInternal -Name $Provider
    $null        = Assert-CredProviderAvailable -Provider $providerObj

    if (-not $Path) { $Path = Get-CredAgeIdentityPath -Config $null }
    $exists = Test-Path -LiteralPath $Path -PathType Leaf

    if ($Show) {
        return [pscustomobject]@{
            Provider  = $Provider
            Path      = $Path
            Recipient = (& $providerObj.GetRecipient $null)
            Created   = $false
        }
    }

    if ($exists -and -not $Force) {
        Write-Verbose "Identity already exists at '$Path'."
        Protect-CredPath -Path $Path
        return [pscustomobject]@{
            Provider  = $Provider
            Path      = $Path
            Recipient = (& $providerObj.GetRecipient $null)
            Created   = $false
        }
    }

    if ($exists -and $Force) {
        $backup = "$Path.$([datetime]::UtcNow.ToString('yyyyMMddHHmmss')).bak"
        if ($PSCmdlet.ShouldProcess($Path, "Back up to '$backup' and replace")) {
            Move-Item -LiteralPath $Path -Destination $backup -Force
            Protect-CredPath -Path $backup
            Write-Warning "Existing key moved to '$backup'. Stores encrypted only to the old key can no longer be read with the new one."
        }
    }

    if (-not $PSCmdlet.ShouldProcess($Path, 'Create key')) { return }

    $result = & $providerObj.NewIdentity $Path
    return [pscustomobject]@{
        Provider  = $Provider
        Path      = $result.Path
        Recipient = $result.Recipient
        Created   = $true
    }
}
