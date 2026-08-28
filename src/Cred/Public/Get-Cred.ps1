#requires -Version 5.1

function Get-Cred {
    <#
        .SYNOPSIS
        Read one credential value.

        .DESCRIPTION
        Returns the secret as a [string] by default so it pipes cleanly, or as
        a [SecureString] with -AsSecureString.

        .EXAMPLE
        Get-Cred acme-api/stripe

        .EXAMPLE
        Get-Cred acme-api/db -Field user

        .EXAMPLE
        Invoke-RestMethod $url -Headers @{ Authorization = "Bearer $(Get-Cred acme-api/gh)" }
    #>
    [CmdletBinding()]
    [OutputType([string], [System.Security.SecureString], [byte[]])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [ValidateSet('secret', 'user')][string]$Field = 'secret',
        [switch]$AsSecureString,
        # Exact bytes rather than a [string]. This is how a file credential is
        # read without a lossy trip through text, and it is what the CLI uses.
        [switch]$AsBytes,
        [string]$Project,
        [string]$Path
    )

    # One decryption, already resolved. A caller who needs the kind as well as
    # the value calls Open-CredStore rather than passing a [ref] in here.
    $entry = Get-CredEntryView -Name $Name -Project $Project -Path $Path
    $key   = $entry.Key
    $ctx   = $entry.Context
    $view  = $entry.View

    # Exact bytes are the same question for every kind, so they are one call.
    if ($AsBytes) { return (Get-CredEntryBytes -Projection $view -Field $Field -ProjectName $ctx.Name) }

    if ($view.Kind -eq 'file') {
        # Binary has no faithful [string] form; handing back a mangled one
        # would look like it worked.
        if ($view.IsBinary) {
            throw (New-CredBinaryContentError -ProjectName $ctx.Name -Key $key -Noun 'a string')
        }
        $text = [string]$view.Fields['secret']
        if ($AsSecureString) { return (ConvertTo-CredSecureString -PlainText $text) }
        return $text
    }

    if (-not $view.Fields.Contains($Field)) {
        throw (New-CredErrorRecord -Code 'NoCredential' -Category ObjectNotFound -Target $Field `
            -Message "'$($ctx.Name)/$key' has no '$Field' field." `
            -Next @("It is a '$($view.Kind)' credential with: $(@($view.Fields.Keys) -join ', ')",
                    "To give it a username: cred add $($ctx.Name)/$key --user <name>"))
    }

    $value = [string]$view.Fields[$Field]
    if ($AsSecureString) { return (ConvertTo-CredSecureString -PlainText $value) }
    return $value
}

function Read-CredValue {
    <#
        .SYNOPSIS
        One credential's bytes, together with what it is.

        .DESCRIPTION
        For a caller that has to decide how to write a value out: the bytes are
        the same question for every kind, but a `file` credential is written
        raw and everything else is written as text, and binary content must not
        be sent to a terminal at all.

        This exists so the CLI can answer all of that with a single call.
        `cred get` used to open the store itself and index .Entries, which put
        store resolution and entry-kind policy inside a script that is supposed
        to parse argv and print.

        Still one decryption. Peer of read_value in cred_store.py.

        .EXAMPLE
        $v = Read-CredValue acme-api/ssl-key
        if ($v.Kind -eq 'file') { [System.IO.File]::WriteAllBytes($p, $v.Bytes) }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [ValidateSet('secret', 'user')][string]$Field = 'secret',
        [string]$Project,
        [string]$Path
    )

    $entry = Get-CredEntryView -Name $Name -Project $Project -Path $Path
    $view  = $entry.View

    return [pscustomobject]@{
        Project  = $entry.Context.Name
        Key      = $entry.Key
        Kind     = $view.Kind
        IsBinary = [bool]$view.IsBinary
        Bytes    = (Get-CredEntryBytes -Projection $view -Field $Field -ProjectName $entry.Context.Name)
    }
}
