#requires -Version 5.1

function Protect-CredIdentity {
    <#
        .SYNOPSIS
        Wrap your age key with the operating system's keystore.

        .DESCRIPTION
        By default the key is a file whose only protection is its ACL: anything
        running as you can read it, and so can anyone who walks off with the
        disk. Wrapping it with DPAPI binds it to your Windows account on this
        machine, so the file on disk is useless to anyone else.

        Nothing else changes. The unwrapped key is never written anywhere -- it
        is unwrapped in memory and handed to age over a pipe -- and the store
        itself stays OS-independent, so it still travels with the code and still
        opens on Linux.

        Back the key up somewhere safe BEFORE wrapping it. A DPAPI-wrapped key
        does not survive a reinstall, a new machine, or a changed account.

        .EXAMPLE
        Protect-CredIdentity

        .EXAMPLE
        Protect-CredIdentity -Backup C:\safe\age-key-backup.txt
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [string]$Path,
        [string]$Backup,
        [switch]$Force,
        # Which backend's key. Only providers whose key is a file cred manages
        # can be wrapped; any other is refused by name rather than silently
        # having age's key wrapped on its behalf.
        [string]$Provider = 'age'
    )

    $null = Assert-CredKeystoreSupported -ProviderName $Provider

    if (-not (Test-CredKeystoreAvailable)) {
        throw (New-CredErrorRecord -Code 'ProviderMissing' `
            -Message "No OS keystore is available on this platform." `
            -Next @("On Windows this uses DPAPI and needs nothing installed.",
                    "Elsewhere, protect the key file itself with a passphrase: age -p identity.txt"))
    }

    if (-not $Path) { $Path = Get-CredIdentityPath -Config $null -ProviderName $Provider }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw (New-CredErrorRecord -Code 'NoIdentity' -Target $Path `
            -Message "No key at '$Path' to wrap." -Next "Create one first: cred keygen")
    }
    if (Test-CredIdentityIsWrapped -Path $Path) {
        Write-Verbose "'$Path' is already wrapped."
        return [pscustomobject]@{ Path = $Path; Protection = (Get-CredKeystoreName); Changed = $false }
    }

    $text = Get-CredFileText -Path $Path

    if ($Backup) {
        if ((Test-Path -LiteralPath $Backup) -and -not $Force) {
            throw (New-CredErrorRecord -Code 'Usage' -Target $Backup `
                -Message "'$Backup' already exists." -Next "Choose another path, or pass -Force.")
        }
        Write-CredPrivateFileText -Path $Backup -Text $text
        Write-Warning "Unwrapped key copied to '$Backup'. That file is the key -- store it somewhere safe and offline."
    }
    elseif (-not $Force) {
        Write-Warning "No -Backup given. If this account or machine is lost, a wrapped key cannot be recovered."
    }

    $target = Join-Path (Split-Path -Parent $Path) $script:CredWrappedIdentityName
    if (-not $PSCmdlet.ShouldProcess($Path, "Wrap with $(Get-CredKeystoreName)")) { return }
    $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream

    Write-CredPrivateFileText -Path $target -Text (New-CredWrappedIdentityJson -IdentityText $text)

    # Prove the wrapped copy opens before removing the original.
    $check = Get-CredIdentityText -Path $target
    if ($check.Trim() -ne $text.Trim()) {
        Remove-Item -LiteralPath $target -Force -Confirm:$false -ErrorAction SilentlyContinue
        throw (New-CredErrorRecord -Code 'NoIdentity' `
            -Message 'The wrapped key did not read back identically, so nothing was changed.' `
            -Next "Your original key at '$Path' is untouched. Please report this.")
    }

    if ($Path -ne $target) { Remove-Item -LiteralPath $Path -Force -Confirm:$false }

    return [pscustomobject]@{
        Path       = $target
        Protection = (Get-CredKeystoreName)
        Changed    = $true
        Backup     = $Backup
    }
}

function Unprotect-CredIdentity {
    <#
        .SYNOPSIS
        Unwrap the key back to a plain, permission-restricted file.

        .DESCRIPTION
        Do this before moving to a new machine or account: a DPAPI-wrapped key
        cannot be opened anywhere else.

        .EXAMPLE
        Unprotect-CredIdentity
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param([string]$Path, [string]$Provider = 'age')

    $null = Assert-CredKeystoreSupported -ProviderName $Provider
    if (-not $Path) { $Path = Get-CredIdentityPath -Config $null -ProviderName $Provider }

    if (-not (Test-CredIdentityIsWrapped -Path $Path)) {
        Write-Verbose "'$Path' is not wrapped."
        return [pscustomobject]@{ Path = $Path; Protection = 'none'; Changed = $false }
    }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Unwrap to a plaintext key file')) { return }
    $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream

    $text   = Get-CredIdentityText -Path $Path
    $target = Join-Path (Split-Path -Parent $Path) 'identity.txt'

    Write-CredPrivateFileText -Path $target -Text $text
    Remove-Item -LiteralPath $Path -Force -Confirm:$false

    Write-Warning "'$target' is now a plaintext key, protected only by file permissions."
    return [pscustomobject]@{ Path = $target; Protection = 'none'; Changed = $true }
}

function Get-CredIdentityInfo {
    <#
        .SYNOPSIS
        Where your key is, how it is protected, and what its public half is.

        .EXAMPLE
        Get-CredIdentityInfo
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string]$Path, [string]$Provider = 'age')

    if (-not $Path) { $Path = Get-CredIdentityPath -Config $null -ProviderName $Provider }
    $exists  = Test-Path -LiteralPath $Path -PathType Leaf
    $wrapped = $exists -and (Test-CredIdentityIsWrapped -Path $Path)

    [pscustomobject]@{
        Path             = $Path
        Exists           = $exists
        Protection       = if ($wrapped) { (ConvertFrom-CredJson (Get-CredFileText -Path $Path)).protection } else { 'file-permissions' }
        Private          = if ($exists) { Test-CredPathIsPrivate -Path $Path } else { $false }
        KeystoreAvailable = (Test-CredKeystoreAvailable)
        Recipient        = if ($exists) { try { & (Get-CredProviderInternal -Name $Provider).GetRecipient $null } catch { $null } } else { $null }
    }
}
