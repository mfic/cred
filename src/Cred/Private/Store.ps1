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
        $null = New-Item -ItemType Directory -Path $CredsDir -Force
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
            Remove-Variable -Name json -Scope 0 -ErrorAction SilentlyContinue
        }
    }
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

            if (-not $verify -or $verify.Length -ne $plain.Length) {
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
                Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
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
