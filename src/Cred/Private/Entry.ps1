#requires -Version 5.1
<#
    Entry.ps1 -- what a credential entry is.

    One module answers all of it: which kind of credential this is, what its
    exact bytes are, which environment variables it becomes, and how it should
    be listed.

    Those questions used to be answered independently at every call site --
    Set-Cred, Get-Cred, Get-CredList, Get-CredEnvironment, Export-CredFile,
    Get-CredCredential and the CLI, plus the same spread again in
    python/cred.py. Two of the copies had already drifted: Get-CredList read
    'type' straight off the definition instead of asking Get-CredEntryKind, so
    a store that had outlived its config.json listed a file credential as a
    secret; and Get-CredCredential did not consider kind at all, so asking for
    a PSCredential over a file credential handed back a base64 blob as the
    password.

    Callers now ask Resolve-CredEntry once and read the answer.
#>

# Every write re-encrypts the whole store, so a large file is not just its own
# cost -- it is paid again on every unrelated `cred add`. Certificates and keys
# are kilobytes; anything past this is a sign the store is the wrong home.
$script:CredMaxFileBytes = 1MB

function Get-CredEnvNames {
    <#
        .SYNOPSIS
        The environment variable names a credential maps to.

        The single home of the naming convention. It was written out three
        times in this module and five times in the Python peer, and the copies
        disagreed: a userpass entry whose definition carried no 'env' map
        produced KEY_PASSWORD in Python and a bare KEY here, so `cred exec`
        injected a different variable name depending on which implementation
        you ran.

        A file credential maps to nothing, by design.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [ValidateSet('secret', 'userpass', 'file')][string]$Kind = 'secret',
        [object]$Env
    )

    $names = [ordered]@{}
    if ($Kind -eq 'file') { return $names }

    $slug = ($Key -replace '[^A-Za-z0-9]', '_').ToUpperInvariant()
    if ($Kind -eq 'userpass') {
        $names['user']   = "${slug}_USER"
        $names['secret'] = "${slug}_PASSWORD"
    }
    else {
        $names['secret'] = $slug
    }

    # An explicit mapping in config.json wins over the convention.
    if ($Env -is [System.Collections.IDictionary]) {
        foreach ($f in @($Env.Keys)) {
            $field = [string]$f
            if ($field -notin @('user', 'secret')) { continue }
            $value = [string]$Env[$f]
            if ($value) { $names[$field] = $value }
        }
    }
    return $names
}

function Get-CredEntryKind {
    <#
        .SYNOPSIS
        The type of a credential, trusting the store over the config.

        'encoding' is only ever set by the file importer, so a store that has
        outlived its config.json still reports the right kind.

        The store only wins where it has something to say. Get-CredList runs
        without -Verify and therefore without an entry at all, so a declared
        credential must still be able to report its own type rather than
        defaulting to 'secret'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)]$Entry, $Definition)

    if ($Entry.Contains('encoding')) { return 'file' }
    if ($Entry.Contains('user'))     { return 'userpass' }

    if ($Definition -and $Definition.Contains('type')) {
        $declared = [string]$Definition.type
        if ($declared -in @('secret', 'userpass', 'file')) { return $declared }
    }
    return 'secret'
}

function ConvertTo-CredFileContent {
    <#
        .SYNOPSIS
        A file's exact bytes as (Text, Encoding) for the store.

        Text stays text so the value is still greppable once decrypted and
        diffs sensibly; anything that is not clean UTF-8 goes to base64. NUL
        forces base64 too -- it decodes fine but is not text by any useful
        definition.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $text = $null
    try {
        # throwOnInvalidBytes, so this is a real validity check and not a
        # silent substitution of U+FFFD for every byte age gave us back.
        $strict = [System.Text.UTF8Encoding]::new($false, $true)
        $text = $strict.GetString($Bytes)
    }
    catch { $text = $null }

    if ($null -eq $text -or $text.Contains([char]0)) {
        return [pscustomobject]@{
            Text     = [Convert]::ToBase64String($Bytes)
            Encoding = 'base64'
        }
    }
    return [pscustomobject]@{ Text = $text; Encoding = $null }
}

function ConvertFrom-CredFileContent {
    <#
        .SYNOPSIS
        The exact bytes that were imported. Inverse of ConvertTo-CredFileContent.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)]$Entry)

    $value = [string]$Entry['secret']
    if ($Entry.Contains('encoding') -and $Entry['encoding'] -eq 'base64') {
        try { return [Convert]::FromBase64String($value) }
        catch {
            throw (New-CredErrorRecord -Code 'StoreCorrupt' -Category InvalidData `
                -Message "This credential's stored content is not valid base64." `
                -Next @('The store decrypted, so this is corruption inside it.',
                        'Restore it from git: git checkout HEAD -- .creds/'))
        }
    }
    return [System.Text.UTF8Encoding]::new($false).GetBytes($value)
}

function Resolve-CredEntry {
    <#
        .SYNOPSIS
        Everything a caller needs to know about one credential, decided once.

        .DESCRIPTION
        Takes a store entry and its (optional) config.json declaration and
        returns the projection every access path wants: the kind, the
        value-bearing fields, the environment variables it becomes, and the
        line `cred list` should show.

        Callers must not re-derive any of this. That is the whole point of the
        module: the rules live here, so a new credential type is one edit
        rather than eleven.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)]$Entry,
        $Definition
    )

    $kind = Get-CredEntryKind -Entry $Entry -Definition $Definition

    # Only the value-bearing fields. Bookkeeping like 'encoding' must never
    # become a field, and must never become an environment variable.
    $fields = [ordered]@{}
    foreach ($f in @('user', 'secret')) {
        if ($Entry.Contains($f)) { $fields[$f] = [string]$Entry[$f] }
    }

    $isBinary = $false
    $fileName = ''
    if ($kind -eq 'file') {
        $isBinary = ($Entry.Contains('encoding') -and $Entry['encoding'] -eq 'base64')
        if ($Definition -and $Definition.Contains('filename') -and $Definition.filename) {
            $fileName = [string]$Definition.filename
        }
    }

    $envSource = if ($Definition -and $Definition.env) { $Definition.env } else { $null }
    $envNames  = Get-CredEnvNames -Key $Key -Kind $kind -Env $envSource

    $envVars = [ordered]@{}
    foreach ($f in @($fields.Keys)) {
        if (-not $envNames.Contains($f)) { continue }
        $envVars[[string]$envNames[$f]] = $fields[$f]
    }

    # A file credential has no env mapping, so that column would be empty
    # where the interesting fact -- which file it was -- fits neatly.
    $display = if ($kind -eq 'file' -and $fileName) { "file: $fileName" }
               else { @($envNames.Values) -join ', ' }

    return [pscustomobject]@{
        Key      = $Key
        Kind     = $kind
        Entry    = $Entry
        Fields   = $fields
        IsBinary = $isBinary
        FileName = $fileName
        EnvNames = $envNames
        EnvVars  = $envVars
        Display  = $display
    }
}

function Get-CredEntryBytes {
    <#
        .SYNOPSIS
        The exact bytes of a credential, whatever kind it is.

        A file credential comes back as the bytes that were imported. Anything
        else is the requested field as UTF-8, with no trailing newline.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]$Projection,
        [string]$Field = 'secret',
        [string]$ProjectName
    )

    if ($Projection.Kind -eq 'file') {
        return (ConvertFrom-CredFileContent -Entry $Projection.Entry)
    }

    if (-not $Projection.Fields.Contains($Field)) {
        $label = if ($ProjectName) { "$ProjectName/$($Projection.Key)" } else { $Projection.Key }
        throw (New-CredErrorRecord -Code 'NoCredential' -Category ObjectNotFound -Target $Field `
            -Message "'$label' has no '$Field' field." `
            -Next "It has: $(@($Projection.Fields.Keys) -join ', ')")
    }
    return [System.Text.UTF8Encoding]::new($false).GetBytes([string]$Projection.Fields[$Field])
}

function Read-CredImportFile {
    <#
        .SYNOPSIS
        The exact bytes of a file being imported as a credential.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][string]$Path, [switch]$Force)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw (New-CredErrorRecord -Code 'NoCredential' -Category ObjectNotFound -Target $Path `
            -Message "There is no file at '$Path'." `
            -Next 'Check the path. -File takes the file to import, not its content.')
    }
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path).ProviderPath)
    if ($bytes.Length -gt $script:CredMaxFileBytes -and -not $Force) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $Path `
            -Message "'$(Split-Path -Leaf $Path)' is $([int]($bytes.Length / 1KB)) KiB; the limit is $([int]($script:CredMaxFileBytes / 1KB)) KiB." `
            -Next @('The whole store is re-encrypted on every write, so a large file is paid for again on every unrelated ''cred add''.',
                    'Keys and certificates are kilobytes. If this really belongs here: cred add ... --file <path> --force'))
    }
    return $bytes
}

