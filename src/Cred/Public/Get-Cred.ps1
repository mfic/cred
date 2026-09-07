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
    # input too -- see the interop test that stats a non-ASCII password.
    #
    # One (predicate, label) list rather than five near-identical pipelines:
    # adding a class is a row, and the order the labels come out in is the
    # order they are written here, which is the order value_stat uses.
    $tests = @(
        @{ Label = 'upper';      Test = { param($c) [char]::IsUpper($c) } }
        @{ Label = 'lower';      Test = { param($c) [char]::IsLower($c) } }
        @{ Label = 'digit';      Test = { param($c) [char]::IsDigit($c) } }
        @{ Label = 'whitespace'; Test = { param($c) [char]::IsWhiteSpace($c) } }
        @{ Label = 'symbol';     Test = { param($c) -not [char]::IsLetterOrDigit($c) -and -not [char]::IsWhiteSpace($c) } }
    )
    $chars   = $Text.ToCharArray()
    $classes = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $tests) {
        foreach ($c in $chars) {
            if (& $t.Test $c) { $classes.Add($t.Label); break }
        }
    }

    if ($classes.Count -eq 0) { return "$n character$plural" }
    # The separator is an em dash, built from its code point rather than typed
    # into the source: see "Encoding" in ARCHITECTURE.md. Python's value_stat
    # emits the same character and the two outputs are compared byte for byte.
    return "$n character$plural $([char]0x2014) $($classes -join ', ')"
}

# ----------------------------------------------------------- cred get modes --
# `cred get` can read a value four ways: whole, as a masked shape, as an
# equality test, or as metadata about it. Which one was asked for, whether the
# combination makes sense, whether it means anything for this credential, and
# what each one prints are all rules about credentials rather than about argv
# -- so they live here and the CLI calls them, in three steps because the
# middle one needs the decrypted value and the first one must not wait for it.
# Peers: resolve_read_mode, assert_read_mode_applies and apply_read_mode in
# python/cred_store.py.

function Resolve-CredReadMode {
    <#
        .SYNOPSIS
        Which of `cred get`'s mutually exclusive read modes was asked for.

        .DESCRIPTION
        Always one of 'full', 'partial', 'check', 'stat'. 'full' is the
        ordinary whole-value path: the bare command falls into it and
        `-Reveal full` names it explicitly, so both get that path's file
        handling rather than the refusal in Assert-CredReadModeApplies.

        Throws on an unknown reveal mode, on more than one mode at once, and on
        any of them beside -Out, which hands back the exact bytes on purpose.

        Peer of resolve_read_mode in python/cred_store.py.

        .EXAMPLE
        Resolve-CredReadMode -Reveal partial
        # partial

        .EXAMPLE
        Resolve-CredReadMode
        # full -- the ordinary whole-value path
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # Whatever --reveal carried: a mode name, or $true for a bare flag.
        [AllowNull()][object]$Reveal,
        [switch]$Check,
        [switch]$Stat,
        # Whether --out was given at all. Its value is not this decision's business.
        [switch]$Out
    )

    $revealMode = $null
    if ($null -ne $Reveal -and $Reveal -isnot [bool]) {
        $revealMode = ([string]$Reveal).ToLowerInvariant()
    }
    elseif ($Reveal -is [bool] -and $Reveal) {
        $revealMode = ''
    }
    if ($null -ne $revealMode -and $revealMode -notin @('partial', 'full')) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument `
            -Message "Unknown --reveal mode '$revealMode'." `
            -Next 'The only modes are: --reveal partial, --reveal full')
    }

    $asked = @()
    if ($null -ne $revealMode) { $asked += 'reveal' }
    if ($Check) { $asked += 'check' }
    if ($Stat)  { $asked += 'stat' }

    if ($asked.Count -gt 1) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument `
            -Message "--$($asked[0]) cannot be combined with --$($asked[1]).")
    }
    if ($asked.Count -gt 0 -and $Out) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument `
            -Message "--$($asked[0]) cannot be combined with --out." `
            -Next '--out writes the exact bytes on purpose; none of these give back the working credential.')
    }
    if ($asked.Count -eq 0) { return 'full' }
    if ($asked[0] -eq 'reveal') {
        return $(if ($revealMode -eq 'partial') { 'partial' } else { 'full' })
    }
    return $asked[0]
}

function Assert-CredReadModeApplies {
    <#
        .SYNOPSIS
        A restrictive read mode has to mean something for this credential.

        .DESCRIPTION
        Masking, stat and equality-checking a blob of file content do not.
        Reading it whole does, which is why 'full' is not restrictive and never
        reaches this refusal.

        Peer of assert_read_mode_applies in python/cred_store.py.

        .EXAMPLE
        Assert-CredReadModeApplies -Mode stat -Value (Read-CredValue acme-api/ssl-key)
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][string]$Mode,
        [Parameter(Mandatory)][object]$Value
    )

    if ($Mode -eq 'full' -or $Value.Kind -ne 'file') { return }

    $flag = if ($Mode -eq 'partial') { 'reveal' } else { $Mode }
    $next = @("See what it is: cred list $($Value.Project)")
    if ($flag -eq 'reveal') {
        $next += "Read it: cred get $($Value.Project)/$($Value.Key) --out <path>"
    }
    throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $Value.Key `
        -Message "'$($Value.Project)/$($Value.Key)' is a file credential; --$flag does not apply to file content." `
        -Next $next)
}

function Invoke-CredReadMode {
    <#
        .SYNOPSIS
        The exact bytes a read mode writes, and the exit code it implies.

        .DESCRIPTION
        Returns Bytes, Newline and ExitCode. Bytes rather than text because
        'full' has to hand back file content unchanged: piping `cred get` to a
        file must produce the file that went in. Newline says whether a
        trailing newline is permitted at all -- never after file content,
        whatever the caller asked for -- and the caller still decides with -n
        whether to use the permission.

        -Candidate belongs to 'check' and must have come from stdin, never from
        argv, which would land it in shell history and process listings and
        defeat the entire point. -ToTerminal belongs to 'full': the one thing
        this module cannot know for itself is whether stdout is a terminal, and
        binary content must not be written to one.

        Peer of apply_read_mode in python/cred_store.py.

        .EXAMPLE
        $r = Invoke-CredReadMode -Mode stat -Value (Read-CredValue acme-api/db)
        [Console]::Out.Write($r.Text); exit $r.ExitCode
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Mode,
        [Parameter(Mandatory)][object]$Value,
        [AllowNull()][AllowEmptyString()][string]$Candidate,
        [switch]$ToTerminal
    )

    $utf8 = [System.Text.UTF8Encoding]::new($false)

    if ($Mode -eq 'full') {
        if ($Value.Kind -eq 'file') {
            if ($Value.IsBinary -and $ToTerminal) {
                throw (New-CredBinaryTerminalError -ProjectName $Value.Project -Key $Value.Key)
            }
            return [pscustomobject]@{ Bytes = $Value.Bytes; Newline = $false; ExitCode = 0 }
        }
        return [pscustomobject]@{ Bytes = $Value.Bytes; Newline = $true; ExitCode = 0 }
    }

    $text = $utf8.GetString($Value.Bytes)
    $readout = {
        param($Out, $Code)
        [pscustomobject]@{ Bytes = $utf8.GetBytes($Out); Newline = $true; ExitCode = $Code }
    }

    switch ($Mode) {
        'partial' { return (& $readout (ConvertTo-CredMaskedValue -Text $text) 0) }
        'stat'    { return (& $readout (ConvertTo-CredValueStat -Text $text)   0) }
        'check'   {
            $matched = [string]::Equals($Candidate, $text, [System.StringComparison]::Ordinal)
            return (& $readout $(if ($matched) { 'match' } else { 'no match' }) $(if ($matched) { 0 } else { 1 }))
        }
    }
    throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument `
        -Message "Unknown read mode '$Mode'.")
}
