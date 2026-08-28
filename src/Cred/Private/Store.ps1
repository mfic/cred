#requires -Version 5.1
<#
    Store.ps1 -- the encrypted half.

    Plaintext shape (never written to disk, only ever a byte[] in memory):

      { "version": 1, "values": { "<key>": { "user": "...", "secret": "..." } } }

    Read is lock-free because every write is an atomic file replace. Write takes
    an exclusive lock on .creds/.lock so two `cred add` runs cannot lose an
    update.
#>

$script:CredStoreVersion = 1
$script:CredLockFileName = '.lock'

function Lock-CredStore {
    <#
        .SYNOPSIS
        Take the project's exclusive write lock. Dispose the result to release.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CredsDir,
        # A single write holds the lock for as long as two backend invocations
        # take -- a second or two, more on a loaded machine. Six concurrent
        # writers is therefore a perfectly ordinary queue, not a stuck process,
        # so the timeout has to be generous enough not to cry wolf.
        [int]$TimeoutMs = 60000
    )

    if (-not (Test-Path -LiteralPath $CredsDir)) {
        $null = New-Item -ItemType Directory -Path $CredsDir -Force -Confirm:$false
    }
    $lockPath = Join-Path $CredsDir $script:CredLockFileName
    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    $delay    = 15

    while ($true) {
        try {
            # The lock file is created once and then left in place. Deleting it
            # on release (FileOptions.DeleteOnClose) looks tidier but is racy:
            # a waiter can obtain a handle to a file that is already pending
            # deletion while a third process creates a fresh file under the same
            # name, at which point two processes both believe they hold the lock
            # and one of them loses its update. .creds/.gitignore keeps it out of
            # git; it is always empty.
            return [System.IO.FileStream]::new(
                $lockPath,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None,
                4,
                [System.IO.FileOptions]::None)
        }
        catch [System.IO.IOException] {
            if ([datetime]::UtcNow -ge $deadline) {
                throw (New-CredErrorRecord -Code 'StoreLocked' -Target $lockPath `
                    -Message "Another cred process is holding the write lock for this project." `
                    -Next @("Wait a moment and retry.",
                            "If nothing else is running, delete the stale lock: Remove-Item '$lockPath'"))
            }
            Start-Sleep -Milliseconds $delay
            $delay = [Math]::Min($delay * 2, 250)
        }
    }
}

function Read-CredStoreValues {
    <#
        .SYNOPSIS
        Decrypt the project's store and return an ordered hashtable of values.
        Returns an empty table when the store does not exist yet.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Project)

    if (-not $Project.StorePath -or -not (Test-Path -LiteralPath $Project.StorePath -PathType Leaf)) {
        return [ordered]@{}
    }

    $provider = Get-CredProviderInternal -Name $Project.Config.provider
    $null     = Assert-CredProviderAvailable -Provider $provider

    $cipher = [System.IO.File]::ReadAllBytes($Project.StorePath)
    if ($cipher.Length -eq 0) { return [ordered]@{} }

    $plain = $null
    try {
        $plain = & $provider.Decrypt $cipher $Project.StorePath $Project.Config
        $json  = [System.Text.Encoding]::UTF8.GetString($plain)
        try { $data = ConvertFrom-CredJson $json }
        catch {
            throw (New-CredErrorRecord -Code 'StoreCorrupt' -Target $Project.StorePath `
                -Message "The store decrypted, but its contents are not valid JSON." `
                -Next @("Restore it from git: git checkout HEAD -- '$($Project.StorePath)'",
                        "Or start over: cred init --force"))
        }
        if ($null -eq $data -or -not $data.values) { return [ordered]@{} }
        return $data.values
    }
    finally {
        if ($plain) { [array]::Clear($plain, 0, $plain.Length) }
        if (Get-Variable -Name json -Scope 0 -ErrorAction SilentlyContinue) {
            Remove-Variable -Name json -Scope 0 -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function New-CredStoreView {
    <#
        .SYNOPSIS
        One decrypted store, with every entry already resolved.

        .DESCRIPTION
        The read path's spine, and the counterpart to Update-CredStoreValues on
        the write side. Writes had a single shared path through four callers;
        reads had seven callers each hand-assembling resolve -> decrypt -> look
        up the definition -> project, which is why Get-Cred and
        Get-CredEnvironment had grown [ref] out-parameters to smuggle the
        projection back out without decrypting a second time.

        Entries covers the union of what is stored and what is declared, so a
        value with no declaration and a declaration with no value both survive
        the trip.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][object]$Values
    )

    $defs    = $Context.Config.credentials
    $entries = [ordered]@{}

    $keys = [System.Collections.Generic.List[string]]::new()
    foreach ($k in @($Values.Keys)) { if (-not $keys.Contains($k)) { $keys.Add($k) } }
    foreach ($k in @($defs.Keys))   { if (-not $keys.Contains($k)) { $keys.Add($k) } }

    foreach ($key in ($keys | Sort-Object)) {
        $entry = if ($Values.Contains($key)) { $Values[$key] } else { [ordered]@{} }
        $def   = if ($defs.Contains($key))   { $defs[$key] }   else { $null }
        $entries[$key] = Resolve-CredEntry -Key $key -Entry $entry -Definition $def
    }

    return [pscustomobject]@{
        Project = $Context.Name
        Context = $Context
        Values  = $Values
        Entries = $entries
        Keys    = @($entries.Keys)
    }
}

function Assert-CredKnownKeys {
    <#
        .SYNOPSIS
        Fail with a useful list when -Only names a credential the store has not
        got. Shared so every caller of Get-CredStoreEnvironment says the same
        thing about the same mistake.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Store,
        [string[]]$Only
    )

    if (-not $Only) { return }
    $missing = @($Only | Where-Object { -not $Store.Values.Contains($_) })
    if (-not $missing) { return }

    $known = @($Store.Values.Keys) | Sort-Object
    throw (New-CredErrorRecord -Code 'NoCredential' -Category ObjectNotFound -Target $missing[0] `
        -Message "Project '$($Store.Project)' has no credential named '$($missing -join "', '")'." `
        -Next @(if ($known) { "It has: $($known -join ', ')" } else { "It has no credentials yet." }
                "Add one with: cred add $($Store.Project)/$($missing[0])"))
}

function Get-CredStoreEnvironment {
    <#
        .SYNOPSIS
        The variables a store injects, and the file credentials it leaves out.

        .DESCRIPTION
        Both answers come from the one decryption behind $Store, so a caller
        that wants to report what was skipped does not pay for a second pass.
        This is what `cred exec` and `cred env` are built on.

        Validating -Only happens here rather than in the callers, so every
        caller says the same thing about the same mistake.

        .EXAMPLE
        $projected = Get-CredStoreEnvironment -Store (Open-CredStore acme-api)
        $projected.Variables['DB_PASSWORD']
        $projected.Skipped
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Store,
        [string[]]$Only,
        [string[]]$Exclude,
        [string]$Prefix
    )

    Assert-CredKnownKeys -Store $Store -Only $Only

    $result  = @{}
    $skipped = [System.Collections.Generic.List[string]]::new()

    foreach ($key in @($Store.Values.Keys)) {
        if ($Only    -and $key -notin $Only)  { continue }
        if ($Exclude -and $key -in  $Exclude) { continue }

        $view = $Store.Entries[$key]

        # File credentials are deliberately not injected: the content is a PEM
        # or a certificate, and `export KEY=-----BEGIN...` breaks the shell it
        # is pasted into. Export-CredFile is the way to get one of these.
        if ($view.Kind -eq 'file') {
            $skipped.Add($key) | Out-Null
            continue
        }

        foreach ($varName in @($view.EnvVars.Keys)) {
            $name = if ($Prefix) { "$Prefix$varName" } else { [string]$varName }
            if ($result.ContainsKey($name)) {
                Write-Warning "Two credentials in '$($Store.Project)' both map to `$env:$name; '$key' wins. Give one of them a distinct 'env' name in .creds/config.json."
            }
            $result[$name] = [string]$view.EnvVars[$varName]
        }
    }

    return [pscustomobject]@{
        Variables = $result
        Skipped   = @($skipped | Sort-Object)
    }
}

# Lived in Public/Get-Cred.ps1, which meant this private file called upward
# into a public one that never exported it. It is a store concern: it only
# exists to turn a missing key into a 'did you mean'.
function Get-CredNearestKey {
    <#
        .SYNOPSIS
        Cheap "did you mean" suggestion (Levenshtein, distance <= 2).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Key, [string[]]$Candidates)

    if (-not $Candidates -or [string]::IsNullOrEmpty($Key)) { return $null }
    $best = $null; $bestScore = [int]::MaxValue

    foreach ($c in $Candidates) {
        $a = $Key.ToLowerInvariant(); $b = ([string]$c).ToLowerInvariant()
        if ($b.Length -eq 0) { continue }
        $prev = 0..$b.Length
        for ($i = 1; $i -le $a.Length; $i++) {
            $cur = @($i) + (1..$b.Length | ForEach-Object { 0 })
            for ($j = 1; $j -le $b.Length; $j++) {
                $cost = if ($a[$i - 1] -eq $b[$j - 1]) { 0 } else { 1 }
                $cur[$j] = [Math]::Min([Math]::Min($cur[$j - 1] + 1, $prev[$j] + 1), $prev[$j - 1] + $cost)
            }
            $prev = $cur
        }
        $d = $prev[$b.Length]
        if ($d -lt $bestScore) { $bestScore = $d; $best = $c }
    }
    if ($bestScore -le 2) { return $best }
    return $null
}

function Get-CredEntryOrThrow {
    <#
        .SYNOPSIS
        Pull one credential out of an already-decrypted value set, or explain
        precisely what is missing and how to add it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Project,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Key,
        [Parameter(Mandatory)][object]$Values
    )

    if ([string]::IsNullOrEmpty($Key)) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument `
            -Message 'No credential name was given.' `
            -Next "Use: cred get <project>/<key>")
    }
    if (-not $Values.Contains($Key)) {
        $known = @($Values.Keys) | Sort-Object
        $hint  = Get-CredNearestKey -Key $Key -Candidates $known
        throw (New-CredErrorRecord -Code 'NoCredential' -Category ObjectNotFound -Target $Key `
            -Message "Project '$($Project.Name)' has no credential named '$Key'." `
            -Next @(
                if ($hint) { "Did you mean '$($Project.Name)/$hint'?" }
                if ($known) { "It has: $($known -join ', ')" } else { "It has no credentials yet." }
                "Add it with: cred add $($Project.Name)/$Key"))
    }
    return $Values[$Key]
}

function Get-CredEntryView {
    <#
        .SYNOPSIS
        A reference such as 'acme-api/db' resolved all the way to one entry:
        split the name, open the store, prove the credential exists, hand back
        what it is.

        .DESCRIPTION
        Every single-credential read path wants exactly this and nothing else,
        and each one used to spell it out itself -- four lines that had to stay
        in step across Get-Cred, Get-CredCredential, Export-CredFile and the
        CLI. The order matters (Get-CredEntryOrThrow before touching .Entries,
        so a missing key gets the message with the near-miss hint rather than a
        null), which is precisely the kind of thing that drifts when it is
        written out four times.

        Still one decryption: the opened store comes back too, for a caller
        that has more to ask of it.

        .EXAMPLE
        $e = Get-CredEntryView -Name acme-api/db
        $e.View.Kind
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [string]$Project,
        [string]$Path
    )

    $ref = Split-CredReference -Reference $Name
    $key = $ref.Key
    if ($ref.Project -and -not $Project) { $Project = $ref.Project }

    $store = Open-CredStore -Project $Project -Path $Path
    $ctx   = $store.Context
    $null  = Get-CredEntryOrThrow -Project $ctx -Key $key -Values $store.Values

    return [pscustomobject]@{
        Key     = $key
        Context = $ctx
        View    = $store.Entries[$key]
        Store   = $store
    }
}

function Write-CredStoreValues {
    <#
        .SYNOPSIS
        Encrypt and atomically replace the project's store.
        Caller is responsible for holding the write lock.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Project,
        [Parameter(Mandatory)][object]$Values
    )

    $provider = Get-CredProviderInternal -Name $Project.Config.provider
    $null     = Assert-CredProviderAvailable -Provider $provider

    $payload = [ordered]@{ version = $script:CredStoreVersion; values = $Values }
    $plain   = $null
    try {
        $plain  = $script:CredUtf8NoBom.GetBytes((ConvertTo-CredJson $payload -Compress))
        $cipher = & $provider.Encrypt $plain $Project.Config

        # Stage the ciphertext beside the store, then prove we can decrypt that
        # exact file before it becomes the store. Until the move, the old store
        # is untouched and still good. Staging first also gives a keystore-
        # wrapped identity a real path to point age at, since in that mode stdin
        # is carrying the key.
        $staged = New-CredStagedFile -Path $Project.StorePath -Bytes $cipher
        try {
            $verify = $null
            try { $verify = & $provider.Decrypt $cipher $staged $Project.Config }
            catch { $verify = $null }

            # Every byte, not just the length. A length-only check passes on a
            # store that decrypts to the right size and the wrong content,
            # which is precisely the corruption this gate exists to catch.
            # python/cred_store.py compares the full bytes; so does this.
            $identical = $false
            if ($verify -and $verify.Length -eq $plain.Length) {
                $identical = $true
                for ($i = 0; $i -lt $plain.Length; $i++) {
                    if ($verify[$i] -ne $plain[$i]) { $identical = $false; break }
                }
            }

            if (-not $identical) {
                throw (New-CredErrorRecord -Code 'DecryptFailed' `
                    -Message 'The new store encrypted, but you could not decrypt it again, so it was not saved.' `
                    -Next @("You are probably not one of this project's recipients.",
                            "Check with: cred recipients",
                            "Add yourself: cred recipients add (cred keygen --show)"))
            }
            [array]::Clear($verify, 0, $verify.Length)

            Move-CredTempIntoPlace -Temp $staged -Destination $Project.StorePath
        }
        finally {
            if (Test-Path -LiteralPath $staged -PathType Leaf) {
                Remove-Item -LiteralPath $staged -Force -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    }
    finally {
        if ($plain) { [array]::Clear($plain, 0, $plain.Length) }
    }
}

function Update-CredStoreValues {
    <#
        .SYNOPSIS
        Read-modify-write the store under the project's exclusive lock.
        The scriptblock receives the current values and returns the new ones.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Project,
        [Parameter(Mandatory)][scriptblock]$Mutate
    )

    $lock = Lock-CredStore -CredsDir $Project.CredsDir
    try {
        # Re-read config inside the lock: another process may have added a
        # recipient or a definition since we resolved the project.
        if (Test-Path -LiteralPath $Project.ConfigPath -PathType Leaf) {
            $Project.Config = Read-CredConfig -Path $Project.ConfigPath
            $Project.StorePath = Join-Path $Project.CredsDir $Project.Config.store
        }
        $values = Read-CredStoreValues -Project $Project
        $result = & $Mutate $values $Project
        if ($null -ne $result) { $values = $result }
        Write-CredStoreValues -Project $Project -Values $values
        Write-CredConfig -Path $Project.ConfigPath -Config $Project.Config
    }
    finally {
        $lock.Dispose()
    }
}
