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
    # The comma matters here too: `return` enumerates arrays like Write-Output
    # does, so without it an empty or one-byte secret would cross this second
    # pipeline boundary and come back flattened again even though
    # Get-CredEntryBytes already protected its own return.
    if ($AsBytes) { return ,(Get-CredEntryBytes -Projection $view -Field $Field -ProjectName $ctx.Name) }

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

function Read-CredStdinSecret {
    <#
        .SYNOPSIS
        Read stdin as a secret: raw UTF-8 bytes, minus one trailing newline.

        .DESCRIPTION
        `cred get --check` needs to read its candidate from stdin the same way
        `cred add --stdin` does, but bin/cred-ps.ps1 is a script outside the
        module and cannot reach the private Resolve-CredSecretInput that
        Set-Cred uses -- this is the public door to the same logic. Peer of
        read_stdin_secret in cred.py.

        .EXAMPLE
        $candidate = Read-CredStdinSecret
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return (Resolve-CredSecretInput -FromStdin -AllowEmpty)
}

# A partial reveal shows this many characters at the end. Anything at or
# under twice that many characters reveals nothing at all, so a short secret
# cannot have most of itself exposed through the "boundary" it supposedly
# keeps hidden.
$script:CredMaskBoundary = 3
$script:CredMaskFill     = '*' * 8

function ConvertTo-CredMaskedValue {
    <#
        .SYNOPSIS
        A partial reveal: a few trailing characters and the length, nothing
        else.

        .DESCRIPTION
        Suffix rather than prefix: many secrets carry a format prefix
        (`sk_live_`, `ghp_`) that is already public knowledge, so a prefix
        reveal would give away less than it looks like while a suffix reveal
        is the credit-card-UX convention a reader actually recognises. Enough
        for a caller -- human or agent -- to eyeball which credential this is
        (the prod key vs. the test key, the new rotation vs. the old one)
        without ever holding a value that would work as the credential
        itself. Peer of mask_value in cred_store.py.

        .EXAMPLE
        ConvertTo-CredMaskedValue -Text 'demo-key-abcdefghijklmno'
        # ********mno (24 characters)
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $n      = $Text.Length
    $plural = if ($n -eq 1) { '' } else { 's' }
    if ($n -le ($script:CredMaskBoundary * 2)) {
        return "$($script:CredMaskFill) ($n character$plural)"
    }
    $tail = $Text.Substring($n - $script:CredMaskBoundary)
    return "$($script:CredMaskFill)$tail ($n character$plural)"
}

function ConvertTo-CredValueStat {
    <#
        .SYNOPSIS
        Length and character composition, no characters at all.

        .DESCRIPTION
        Enough to catch an empty paste, a stray trailing newline, or a value
        that is obviously not what it should be -- without exposing a single
        character of it. Peer of value_stat in cred_store.py.

        .EXAMPLE
        ConvertTo-CredValueStat -Text 'Tr0ub4dor&3'
        # 11 characters -- upper, lower, digit, symbol
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $n = $Text.Length
    if ($n -eq 0) { return '0 characters' }
    $plural  = if ($n -eq 1) { '' } else { 's' }

    # Per-character .NET classification, not an ASCII regex, so this agrees
    # with Python's str.isupper()/islower()/isdigit()/isspace() on Unicode
    # input too -- see the interop test for 'pässwörd☃日本語end'.
    $chars   = $Text.ToCharArray()
    $classes = [System.Collections.Generic.List[string]]::new()
    if ($chars | Where-Object { [char]::IsUpper($_) } | Select-Object -First 1) { $classes.Add('upper') }
    if ($chars | Where-Object { [char]::IsLower($_) } | Select-Object -First 1) { $classes.Add('lower') }
    if ($chars | Where-Object { [char]::IsDigit($_) } | Select-Object -First 1) { $classes.Add('digit') }
    if ($chars | Where-Object { [char]::IsWhiteSpace($_) } | Select-Object -First 1) { $classes.Add('whitespace') }
    if ($chars | Where-Object { -not [char]::IsLetterOrDigit($_) -and -not [char]::IsWhiteSpace($_) } | Select-Object -First 1) { $classes.Add('symbol') }

    if ($classes.Count -eq 0) { return "$n character$plural" }
    return "$n character$plural — $($classes -join ', ')"
}
