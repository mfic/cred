#requires -Version 5.1
<#
    Providers.ps1 -- the crypto backend seam.

    A provider is a PSCustomObject with these members. Everything above this
    file talks to secrets only through this shape, so swapping backends (or
    adding one) touches nothing else.

      Name           [string]   identifier used in .creds/config.json
      Summary        [string]   one line for `cred doctor`
      StoreFileName  [string]   default name of the ciphertext file
      InstallHint    [string]   what to tell the user when it is missing
      Test           [scriptblock] () -> @{ Available; Path; Detail }
      NewIdentity    [scriptblock] ($Path) -> @{ Path; Recipient }
      GetRecipient   [scriptblock] ($Config) -> [string] this machine's public key
      Encrypt        [scriptblock] ($PlainBytes, $Config) -> [byte[]]
      Decrypt        [scriptblock] ($CipherBytes, $CipherPath, $Config) -> [byte[]]

    And, optionally, the key half -- which used to sit outside the seam
    entirely, so `cred key protect` reached straight into age and DPAPI and
    would happily wrap an age key file for a project that used neither:

      IdentityPath     [scriptblock] ($Config) -> [string] or $null
      SupportsKeystore [bool]

    A provider that declares neither is taken to keep its keys somewhere cred
    does not manage -- a remote KMS or a vault, say, where there is no local
    key file to point at and nothing for cred to wrap. age is currently the
    only provider, but the seam is what a second one plugs into.

    Providers must never write plaintext to disk and never accept secret
    material as a command-line argument.
#>

$script:CredProviders = @{}

function Register-CredProviderInternal {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Provider)

    # Fill in the optional half of the contract once, here, so no caller has to
    # test for the members' existence.
    if (-not $Provider.PSObject.Properties['IdentityPath']) {
        Add-Member -InputObject $Provider -NotePropertyName IdentityPath `
                   -NotePropertyValue { param($Config) $null } -Force
    }
    if (-not $Provider.PSObject.Properties['SupportsKeystore']) {
        Add-Member -InputObject $Provider -NotePropertyName SupportsKeystore `
                   -NotePropertyValue $false -Force
    }
    $script:CredProviders[$Provider.Name] = $Provider
}

function Resolve-CredProviderName {
    <#
        .SYNOPSIS
        Which provider a call means: what it asked for, else what the project
        configured, else the default.

        Peer of provider_for in cred_store.py, which the Python side has always
        shared. Keeping the cascade in one place is what stops the two editions
        drifting on what an unconfigured project uses.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([object]$Config, [string]$ProviderName)

    if ($ProviderName) { return $ProviderName }
    if ($Config -and $Config.provider) { return [string]$Config.provider }
    return 'age'
}

function Get-CredIdentityPath {
    <#
        .SYNOPSIS
        Where this project's key lives, according to its provider.

        Replaces Get-CredAgeIdentityPath at every call site outside this file.
        The old name was the honest one -- it always returned an age path --
        which is precisely why the keystore commands were age-only.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([object]$Config, [string]$ProviderName)

    $ProviderName = Resolve-CredProviderName -Config $Config -ProviderName $ProviderName
    $provider = Get-CredProviderInternal -Name $ProviderName
    $path     = & $provider.IdentityPath $Config
    if (-not $path) {
        throw (New-CredErrorRecord -Code 'NoIdentity' -Target $ProviderName `
            -Message "The '$ProviderName' provider does not keep its key in a file cred manages." `
            -Next @("Its keys live somewhere cred does not own; manage them where they live.",
                    "Only providers with a cred-managed key file support 'cred key'."))
    }
    return $path
}

function Assert-CredKeystoreSupported {
    <#
        .SYNOPSIS
        Refuse a keystore operation the provider cannot honour, rather than
        wrapping some other provider's key file.
    #>
    [CmdletBinding()]
    param([object]$Config, [string]$ProviderName)

    $ProviderName = Resolve-CredProviderName -Config $Config -ProviderName $ProviderName
    $provider = Get-CredProviderInternal -Name $ProviderName
    if (-not $provider.SupportsKeystore) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidOperation -Target $ProviderName `
            -Message "The '$ProviderName' provider has no key for cred to wrap." `
            -Next @("It holds your private key somewhere with its own protection.",
                    "'cred key protect' applies to providers whose key is a file cred manages, such as age."))
    }
    return $provider
}

function Get-CredProviderInternal {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Name)

    if (-not $script:CredProviders.ContainsKey($Name)) {
        throw (New-CredErrorRecord -Code 'ProviderMissing' `
            -Message "Unknown encryption provider '$Name'." `
            -Next @("Known providers: $(($script:CredProviders.Keys | Sort-Object) -join ', ')",
                    "Fix the 'provider' field in .creds/config.json."))
    }
    return $script:CredProviders[$Name]
}

function Assert-CredProviderAvailable {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Provider)

    $state = & $Provider.Test
    if (-not $state.Available) {
        throw (New-CredErrorRecord -Code 'ProviderMissing' `
            -Message "Encryption backend '$($Provider.Name)' is not available: $($state.Detail)" `
            -Next @($Provider.InstallHint, "Then re-run 'cred doctor'."))
    }
    return $state
}

# ---------------------------------------------------------------- age --------

function Get-CredAgeIdentityPath {
    <#
        .SYNOPSIS
        Where this machine's age secret key lives. Never inside a repo.

        Precedence: $env:CRED_IDENTITY_FILE > project config 'identityFile' >
                    <CRED_HOME>/identity.txt
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([object]$Config)

    if ($env:CRED_IDENTITY_FILE) { return $env:CRED_IDENTITY_FILE }
    if ($Config -and $Config.PSObject.Properties['identityFile'] -and $Config.identityFile) {
        $p = [string]$Config.identityFile
        if ([System.IO.Path]::IsPathRooted($p)) { return $p }
        return (Join-Path (Get-CredHomeDirectory) $p)
    }
    # A keystore-wrapped key wins over a plaintext one, so that `cred key
    # protect` takes effect without anyone having to reconfigure anything.
    $credHome = Get-CredHomeDirectory
    $wrapped  = Join-Path $credHome $script:CredWrappedIdentityName
    if (Test-Path -LiteralPath $wrapped -PathType Leaf) { return $wrapped }
    return (Join-Path $credHome 'identity.txt')
}

$script:CredWrappedIdentityName = 'identity.wrapped.json'
$script:CredIdentityFormat      = 'cred-identity'

function Test-CredIdentityIsWrapped {
    <#
        .SYNOPSIS
        Is this identity file wrapped by an OS keystore rather than plaintext?
        Detected by content, not by filename, so renaming a key cannot lie.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        $head = (Get-CredFileText -Path $Path).TrimStart()
        if (-not $head.StartsWith('{')) { return $false }
        $o = ConvertFrom-CredJson $head
        return ($o -and $o.format -eq $script:CredIdentityFormat)
    }
    catch { return $false }
}

function Get-CredIdentityText {
    <#
        .SYNOPSIS
        The age identity as text, unwrapping the OS keystore if needed.

        The plaintext form exists only as a return value in memory. Callers hand
        it to age over stdin and never write it anywhere.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-CredIdentityIsWrapped -Path $Path)) {
        return (Get-CredFileText -Path $Path)
    }

    $meta = ConvertFrom-CredJson (Get-CredFileText -Path $Path)
    if ($meta.protection -ne (Get-CredKeystoreName)) {
        throw (New-CredErrorRecord -Code 'NoIdentity' -Target $Path `
            -Message "'$Path' is wrapped with '$($meta.protection)', which this machine cannot open." `
            -Next @("Open it on the machine and account that wrapped it, then: cred key unprotect",
                    "Or restore an unwrapped backup of the key."))
    }
    $blob  = [Convert]::FromBase64String([string]$meta.data)
    $plain = Unprotect-CredSecretBytes -Bytes $blob
    try   { return [System.Text.Encoding]::UTF8.GetString($plain) }
    finally { [array]::Clear($plain, 0, $plain.Length) }
}

function New-CredWrappedIdentityJson {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$IdentityText)

    $bytes = $null
    try {
        $bytes   = [System.Text.Encoding]::UTF8.GetBytes($IdentityText)
        $wrapped = Protect-CredSecretBytes -Bytes $bytes
        return (ConvertTo-CredJson ([ordered]@{
            format     = $script:CredIdentityFormat
            version    = 1
            protection = (Get-CredKeystoreName)
            note       = 'Wrapped by the OS keystore. Only the account that wrapped it can open it. Keep a separate backup of the unwrapped key.'
            data       = [Convert]::ToBase64String($wrapped)
        }))
    }
    finally { if ($bytes) { [array]::Clear($bytes, 0, $bytes.Length) } }
}

function Invoke-CredAge {
    <#
        .SYNOPSIS
        Run age with an identity, choosing how to hand the key over.

        A plaintext key file is passed by path. A keystore-wrapped key is
        unwrapped in memory and piped to age's stdin (-i -), which forces the
        ciphertext to be named as a file argument -- fine, because ciphertext on
        disk is exactly what the store already is. Either way the unwrapped key
        never exists as a file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IdentityPath,
        [Parameter(Mandatory)][string[]]$BaseArguments,
        [byte[]]$CipherBytes,
        [string]$CipherPath
    )

    $age = Resolve-CredExecutable -Name 'age' -OverridePath $env:CRED_AGE_PATH

    if (-not (Test-CredIdentityIsWrapped -Path $IdentityPath)) {
        return Invoke-CredProcess -FilePath $age `
                                  -ArgumentList ($BaseArguments + @('-i', $IdentityPath)) `
                                  -InputBytes $CipherBytes
    }

    $identityText  = Get-CredIdentityText -Path $IdentityPath
    $identityBytes = $null
    $staged        = $null
    try {
        $identityBytes = [System.Text.Encoding]::UTF8.GetBytes($identityText)

        # stdin now carries the key, so the ciphertext has to be a path.
        $path = $CipherPath
        if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $staged = Join-Path ([System.IO.Path]::GetTempPath()) "cred-ct-$([guid]::NewGuid().ToString('N')).age"
            [System.IO.File]::WriteAllBytes($staged, $CipherBytes)   # ciphertext only
            $path = $staged
        }
        return Invoke-CredProcess -FilePath $age `
                                  -ArgumentList ($BaseArguments + @('-i', '-', $path)) `
                                  -InputBytes $identityBytes
    }
    finally {
        if ($identityBytes) { [array]::Clear($identityBytes, 0, $identityBytes.Length) }
        if ($staged -and (Test-Path -LiteralPath $staged)) {
            Remove-Item -LiteralPath $staged -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

$script:CredAgeProvider = [pscustomobject]@{
    Name          = 'age'
    Summary       = 'age (X25519, RFC 9180-style HPKE-ish envelope, authenticated ChaCha20-Poly1305)'
    StoreFileName = 'store.age'
    InstallHint   = "Install age:  winget install FiloSottile.age   (or: brew install age / apt install age)"

    # cred owns this key file, so it is cred's to locate and to wrap.
    IdentityPath     = { param($Config) Get-CredAgeIdentityPath -Config $Config }
    SupportsKeystore = $true

    Test = {
        $path = Resolve-CredExecutable -Name 'age' -OverridePath $env:CRED_AGE_PATH
        if (-not $path) {
            return [pscustomobject]@{ Available = $false; Path = $null; Detail = "'age' was not found on PATH." }
        }
        $keygen = Resolve-CredExecutable -Name 'age-keygen' -OverridePath $env:CRED_AGE_KEYGEN_PATH
        if (-not $keygen) {
            return [pscustomobject]@{ Available = $false; Path = $path; Detail = "'age' found but 'age-keygen' was not." }
        }
        [pscustomobject]@{ Available = $true; Path = $path; Detail = 'age and age-keygen found.' }
    }

    NewIdentity = {
        param([string]$Path)

        $keygen = Resolve-CredExecutable -Name 'age-keygen' -OverridePath $env:CRED_AGE_KEYGEN_PATH
        $dir = Split-Path -Parent $Path
        if ($dir) { $null = New-CredDirectory -Path $dir }

        # age-keygen writes the key to stdout; we place it ourselves so that the
        # file is created with restrictive permissions from the start.
        $r = Invoke-CredProcess -FilePath $keygen -ArgumentList @()
        if ($r.ExitCode -ne 0) {
            throw (New-CredErrorRecord -Code 'General' `
                -Message "age-keygen failed: $($r.StdErr)" -Next "Run 'cred doctor'.")
        }
        $text = [System.Text.Encoding]::UTF8.GetString($r.StdOut)

        # This is the private key in the clear, so it goes through the writer
        # that restricts the staged file before publishing it.
        Write-CredPrivateFileText -Path $Path -Text $text

        $recipient = ($text -split "`r?`n" | Where-Object { $_ -match '^age1' } | Select-Object -First 1)
        if (-not $recipient) {
            $recipient = ($text -split "`r?`n" |
                Where-Object { $_ -match '^#\s*public key:\s*(\S+)' } |
                ForEach-Object { $Matches[1] } | Select-Object -First 1)
        }
        [pscustomobject]@{ Path = $Path; Recipient = $recipient }
    }

    GetRecipient = {
        param([object]$Config)

        $identity = Get-CredAgeIdentityPath -Config $Config
        if (-not (Test-Path -LiteralPath $identity -PathType Leaf)) {
            throw (New-CredErrorRecord -Code 'NoIdentity' `
                -Message "No age identity found at '$identity'." `
                -Next @("Create one with: cred keygen",
                        "Or point at an existing key: `$env:CRED_IDENTITY_FILE = 'C:\path\to\key.txt'"))
        }
        $keygen = Resolve-CredExecutable -Name 'age-keygen' -OverridePath $env:CRED_AGE_KEYGEN_PATH
        $r = if (Test-CredIdentityIsWrapped -Path $identity) {
            # age-keygen -y reads the identity from stdin when given no INPUT.
            $text  = Get-CredIdentityText -Path $identity
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
            try   { Invoke-CredProcess -FilePath $keygen -ArgumentList @('-y') -InputBytes $bytes }
            finally { [array]::Clear($bytes, 0, $bytes.Length) }
        }
        else {
            Invoke-CredProcess -FilePath $keygen -ArgumentList @('-y', $identity)
        }
        if ($r.ExitCode -ne 0) {
            throw (New-CredErrorRecord -Code 'NoIdentity' `
                -Message "Could not read the age identity at '$identity': $($r.StdErr)" `
                -Next @("Check the file is an age key file (it starts with 'AGE-SECRET-KEY-').",
                        "Regenerate with: cred keygen --force"))
        }
        ([System.Text.Encoding]::UTF8.GetString($r.StdOut).Trim() -split "`r?`n")[0]
    }

    Encrypt = {
        param([byte[]]$PlainBytes, [object]$Config)

        $age = Resolve-CredExecutable -Name 'age' -OverridePath $env:CRED_AGE_PATH
        $recipients = @($Config.recipients)
        if (-not $recipients -or $recipients.Count -eq 0) {
            throw (New-CredErrorRecord -Code 'General' `
                -Message 'This project has no recipients, so nothing could decrypt the store.' `
                -Next "Add your key with: cred recipients add (cred keygen --show)")
        }
        $argv = @('--encrypt', '--armor')
        foreach ($r in $recipients) { $argv += @('-r', [string]$r) }

        $res = Invoke-CredProcess -FilePath $age -ArgumentList $argv -InputBytes $PlainBytes
        if ($res.ExitCode -ne 0) {
            throw (New-CredErrorRecord -Code 'General' `
                -Message "age could not encrypt the store: $($res.StdErr)" `
                -Next @("Check that every recipient in .creds/config.json is a valid age public key (age1...).",
                        "List them with: cred recipients"))
        }
        return $res.StdOut
    }

    Decrypt = {
        param([byte[]]$CipherBytes, [string]$CipherPath, [object]$Config)

        $identity = Get-CredAgeIdentityPath -Config $Config

        if (-not (Test-Path -LiteralPath $identity -PathType Leaf)) {
            throw (New-CredErrorRecord -Code 'NoIdentity' `
                -Message "No age identity at '$identity', so the store cannot be opened." `
                -Next @("If this is a new machine, restore your key file to that path.",
                        "If this is a new setup, run: cred keygen",
                        "To use a key from elsewhere: `$env:CRED_IDENTITY_FILE = '<path>'"))
        }

        $res = Invoke-CredAge -IdentityPath $identity -BaseArguments @('--decrypt') `
                              -CipherBytes $CipherBytes -CipherPath $CipherPath
        if ($res.ExitCode -ne 0) {
            $detail = $res.StdErr
            $next = if ($detail -match 'no identity matched|incorrect|no identities') {
                @("Your key is not a recipient of this store.",
                  "Ask someone who can already read it to run: cred recipients add <your-public-key>",
                  "Print your public key with: cred keygen --show")
            } else {
                @("The store may be damaged. Restore .creds/$([System.IO.Path]::GetFileName($CipherPath)) from git:",
                  "  git checkout HEAD -- .creds/")
            }
            throw (New-CredErrorRecord -Code 'DecryptFailed' `
                -Message "age could not decrypt the store: $detail" -Next $next)
        }
        return $res.StdOut
    }
}

Register-CredProviderInternal -Provider $script:CredAgeProvider
