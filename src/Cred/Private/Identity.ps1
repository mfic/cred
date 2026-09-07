#requires -Version 5.1
<#
    Identity.ps1 -- the identity file, and nothing else.

    `<CRED_HOME>/identity.txt` or `identity.wrapped.json` is one of the five
    files ARCHITECTURE.md calls the contract, and it was the only one with no
    module of its own: the wrapped form was written in Providers.ps1, read
    again in Providers.ps1, parsed a third time in Keystore.ps1, and its crypto
    lived in Platform.ps1. Adding a reader was a four-file edit, and a fourth
    reader did get added before anyone noticed.

    Everything that reads or writes the file goes through here. What a keystore
    *is* stays in Platform.ps1 (Protect-/Unprotect-CredSecretBytes); this file
    only knows the format that names one.

    Peer of identity_path / identity_protection / identity_is_wrapped /
    identity_text / wrap_identity in python/cred_store.py.
#>

$script:CredWrappedIdentityName = 'identity.wrapped.json'
$script:CredIdentityFormat      = 'cred-identity'

function Read-CredIdentityFile {
    <#
        .SYNOPSIS
        What an identity file is, without unwrapping it.

        .DESCRIPTION
        Returns Path, Exists, IsWrapped, Protection and Meta. Wrapping is
        detected by content and never by filename, so renaming a key cannot
        misrepresent it, and Protection is read from the file rather than
        derived from the platform -- a key wrapped on another machine is
        exactly the case worth being able to see.

        Never returns key material: Get-CredIdentityText is the one door to
        that, and it is the one that can fail.

        .EXAMPLE
        (Read-CredIdentityFile -Path $p).Protection
        # dpapi-currentuser
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)

    $result = [pscustomobject]@{
        Path       = $Path
        Exists     = (Test-Path -LiteralPath $Path -PathType Leaf)
        IsWrapped  = $false
        Protection = 'file-permissions'
        Meta       = $null
    }
    if (-not $result.Exists) { return $result }

    try {
        $head = (Get-CredFileText -Path $Path).TrimStart()
        if (-not $head.StartsWith('{')) { return $result }
        $meta = ConvertFrom-CredJson $head
        if (-not $meta -or $meta.format -ne $script:CredIdentityFormat) { return $result }

        $result.IsWrapped = $true
        $result.Meta      = $meta
        # A wrapped file that cannot say how it was wrapped is not something to
        # guess about, so it reports 'unknown' rather than this machine's answer.
        $result.Protection = if ($meta.protection) { [string]$meta.protection } else { 'unknown' }
    }
    catch {
        Write-Verbose "Could not read '$Path' as an identity file: $($_.Exception.Message)"
    }
    return $result
}

function Test-CredIdentityIsWrapped {
    <#
        .SYNOPSIS
        Is this identity file wrapped by an OS keystore rather than plaintext?
        Detected by content, not by filename, so renaming a key cannot lie.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path)

    return (Read-CredIdentityFile -Path $Path).IsWrapped
}

function Get-CredIdentityText {
    <#
        .SYNOPSIS
        The age identity as text, unwrapping the OS keystore if needed.

        .DESCRIPTION
        The plaintext form exists only as a return value in memory. Callers hand
        it to age over stdin and never write it anywhere.

        A key wrapped by a mechanism this machine does not have gets a refusal
        naming the mechanism, rather than a decryption failure -- which is the
        whole reason the file names its own protection.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)

    $file = Read-CredIdentityFile -Path $Path
    if (-not $file.IsWrapped) { return (Get-CredFileText -Path $Path) }

    if ($file.Protection -ne (Get-CredKeystoreName)) {
        throw (New-CredErrorRecord -Code 'NoIdentity' -Target $Path `
            -Message "'$Path' is wrapped with '$($file.Protection)', which this machine cannot open." `
            -Next @("Open it on the machine and account that wrapped it, then: cred key unprotect",
                    "Or restore an unwrapped backup of the key."))
    }

    $blob  = [Convert]::FromBase64String([string]$file.Meta.data)
    $plain = Unprotect-CredSecretBytes -Bytes $blob
    try   { return [System.Text.Encoding]::UTF8.GetString($plain) }
    finally { [array]::Clear($plain, 0, $plain.Length) }
}

function Write-CredIdentityFile {
    <#
        .SYNOPSIS
        Write an identity file, plain or keystore-wrapped, restricted to you.

        .DESCRIPTION
        -Wrap seals the text with this machine's keystore and records which one
        in the file, so the reader dispatches on what the file says. Either way
        the bytes go through Write-CredPrivateFileText, which restricts the file
        before publishing it.

        The wrapping half used to be New-CredWrappedIdentityJson in
        Providers.ps1, with the write a separate call at the one call site --
        which is how "wrapped" and "written safely" could come apart.

        .EXAMPLE
        Write-CredIdentityFile -Path $target -Text $key -Wrap
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Text,
        [switch]$Wrap
    )

    if (-not $PSCmdlet.ShouldProcess($Path, $(if ($Wrap) { 'Write wrapped identity' } else { 'Write identity' }))) { return }
    $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream

    if (-not $Wrap) {
        Write-CredPrivateFileText -Path $Path -Text $Text
        return $Path
    }

    $bytes = $null
    try {
        $bytes   = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $wrapped = Protect-CredSecretBytes -Bytes $bytes
        $json    = ConvertTo-CredJson ([ordered]@{
            format     = $script:CredIdentityFormat
            version    = 1
            protection = (Get-CredKeystoreName)
            note       = 'Wrapped by the OS keystore. Only the account that wrapped it can open it. Keep a separate backup of the unwrapped key.'
            data       = [Convert]::ToBase64String($wrapped)
        })
        Write-CredPrivateFileText -Path $Path -Text $json
    }
    finally { if ($bytes) { [array]::Clear($bytes, 0, $bytes.Length) } }
    return $Path
}
