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
      GetRecipient   [scriptblock] () -> [string] this machine's public key
      Encrypt        [scriptblock] ($PlainBytes, $Config) -> [byte[]]
      Decrypt        [scriptblock] ($CipherBytes, $CipherPath, $Config) -> [byte[]]

    Providers must never write plaintext to disk and never accept secret
    material as a command-line argument.
#>

$script:CredProviders = @{}

function Register-CredProviderInternal {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Provider)
    $script:CredProviders[$Provider.Name] = $Provider
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
    return (Join-Path (Get-CredHomeDirectory) 'identity.txt')
}

$script:CredAgeProvider = [pscustomobject]@{
    Name          = 'age'
    Summary       = 'age (X25519, RFC 9180-style HPKE-ish envelope, authenticated ChaCha20-Poly1305)'
    StoreFileName = 'store.age'
    InstallHint   = "Install age:  winget install FiloSottile.age   (or: brew install age / apt install age)"

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

        # The directory is already restricted to us, so the temp file this
        # writes through is never world-readable even for an instant.
        Set-CredFileText -Path $Path -Text $text
        Protect-CredPath -Path $Path

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
        $r = Invoke-CredProcess -FilePath $keygen -ArgumentList @('-y', $identity)
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

        $age      = Resolve-CredExecutable -Name 'age' -OverridePath $env:CRED_AGE_PATH
        $identity = Get-CredAgeIdentityPath -Config $Config

        if (-not (Test-Path -LiteralPath $identity -PathType Leaf)) {
            throw (New-CredErrorRecord -Code 'NoIdentity' `
                -Message "No age identity at '$identity', so the store cannot be opened." `
                -Next @("If this is a new machine, restore your key file to that path.",
                        "If this is a new setup, run: cred keygen",
                        "To use a key from elsewhere: `$env:CRED_IDENTITY_FILE = '<path>'"))
        }

        $res = Invoke-CredProcess -FilePath $age `
                                  -ArgumentList @('--decrypt', '-i', $identity) `
                                  -InputBytes $CipherBytes
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

# ---------------------------------------------------------------- gpg --------
# Second implementation of the same contract. It exists to prove the seam is
# real and to serve people already invested in GnuPG keyrings.

$script:CredGpgProvider = [pscustomobject]@{
    Name          = 'gpg'
    Summary       = 'GnuPG public-key encryption against your existing keyring'
    StoreFileName = 'store.asc'
    InstallHint   = "Install GnuPG:  winget install GnuPG.GnuPG   (or: apt install gnupg)"

    Test = {
        $path = Resolve-CredExecutable -Name 'gpg' -OverridePath $env:CRED_GPG_PATH
        if (-not $path) {
            return [pscustomobject]@{ Available = $false; Path = $null; Detail = "'gpg' was not found on PATH." }
        }
        [pscustomobject]@{ Available = $true; Path = $path; Detail = 'gpg found.' }
    }

    NewIdentity = {
        param([string]$Path)
        throw (New-CredErrorRecord -Code 'Usage' `
            -Message 'The gpg provider uses your existing GnuPG keyring; it does not create keys.' `
            -Next @("Create a key with: gpg --full-generate-key",
                    "Then: cred recipients add <your-fingerprint-or-email>"))
    }

    GetRecipient = {
        param([object]$Config)
        $gpg = Resolve-CredExecutable -Name 'gpg' -OverridePath $env:CRED_GPG_PATH
        $r = Invoke-CredProcess -FilePath $gpg -ArgumentList @('--list-secret-keys', '--with-colons')
        $fpr = ([System.Text.Encoding]::UTF8.GetString($r.StdOut) -split "`r?`n" |
                Where-Object { $_ -like 'fpr:*' } |
                ForEach-Object { ($_ -split ':')[9] } |
                Select-Object -First 1)
        if (-not $fpr) {
            throw (New-CredErrorRecord -Code 'NoIdentity' `
                -Message 'No GnuPG secret key was found in your keyring.' `
                -Next "Create one with: gpg --full-generate-key")
        }
        $fpr
    }

    Encrypt = {
        param([byte[]]$PlainBytes, [object]$Config)
        $gpg = Resolve-CredExecutable -Name 'gpg' -OverridePath $env:CRED_GPG_PATH
        $recipients = @($Config.recipients)
        if (-not $recipients -or $recipients.Count -eq 0) {
            throw (New-CredErrorRecord -Code 'General' `
                -Message 'This project has no recipients, so nothing could decrypt the store.' `
                -Next "Add one with: cred recipients add <fingerprint>")
        }
        $argv = @('--batch', '--yes', '--armor', '--trust-model', 'always', '--encrypt')
        foreach ($r in $recipients) { $argv += @('-r', [string]$r) }

        $res = Invoke-CredProcess -FilePath $gpg -ArgumentList $argv -InputBytes $PlainBytes
        if ($res.ExitCode -ne 0) {
            throw (New-CredErrorRecord -Code 'General' `
                -Message "gpg could not encrypt the store: $($res.StdErr)" `
                -Next @("Check every recipient is in your keyring: gpg --list-keys",
                        "List configured recipients with: cred recipients"))
        }
        return $res.StdOut
    }

    Decrypt = {
        param([byte[]]$CipherBytes, [string]$CipherPath, [object]$Config)
        $gpg = Resolve-CredExecutable -Name 'gpg' -OverridePath $env:CRED_GPG_PATH
        $res = Invoke-CredProcess -FilePath $gpg `
                                  -ArgumentList @('--batch', '--yes', '--quiet', '--decrypt') `
                                  -InputBytes $CipherBytes
        if ($res.ExitCode -ne 0) {
            throw (New-CredErrorRecord -Code 'DecryptFailed' `
                -Message "gpg could not decrypt the store: $($res.StdErr)" `
                -Next @("Confirm you hold a secret key for one of the recipients: gpg --list-secret-keys",
                        "If the passphrase prompt was skipped, run gpg once interactively to unlock the agent."))
        }
        return $res.StdOut
    }
}

Register-CredProviderInternal -Provider $script:CredAgeProvider
Register-CredProviderInternal -Provider $script:CredGpgProvider
