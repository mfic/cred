#requires -Version 5.1

function Initialize-CredProject {
    <#
        .SYNOPSIS
        Create a credential store in a repository.

        .DESCRIPTION
        Writes .creds/config.json (plaintext, commit it), creates an empty
        encrypted .creds/store.age (commit it too), adds a .creds/.gitignore
        for the lock file, and registers the project by name so you can reach
        it from anywhere with `cred get <project>/<key>`.

        Generates your personal key on first use if you do not have one.

        .EXAMPLE
        Initialize-CredProject
        Set up the repository in the current directory.

        .EXAMPLE
        Initialize-CredProject -Project acme-api -Provider gpg
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [string]$Project,
        [string]$Path,
        [ValidateNotNullOrEmpty()][string]$Provider = 'age',
        [string[]]$Recipient,
        [switch]$Force
    )

    if (-not $Path) { $Path = (Get-Location).ProviderPath }
    $root = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath

    if (-not $Project) {
        $Project = Split-Path -Leaf $root
    }
    if (-not (Test-CredKeyName $Project)) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $Project `
            -Message "'$Project' is not a usable project name." `
            -Next "Use letters, digits, dot, dash or underscore, e.g. 'acme-api'.")
    }

    $providerObj = Get-CredProviderInternal -Name $Provider
    $null        = Assert-CredProviderAvailable -Provider $providerObj

    $credsDir   = Join-Path $root $script:CredDirName
    $configPath = Join-Path $credsDir $script:CredConfigFileName

    if ((Test-Path -LiteralPath $configPath) -and -not $Force) {
        throw (New-CredErrorRecord -Code 'Usage' -Target $configPath `
            -Message "'$root' already has a credential store." `
            -Next @("Add a credential:  cred add $Project/<key>",
                    "See what is there: cred list $Project",
                    "Start over:        cred init --force"))
    }

    if (-not $PSCmdlet.ShouldProcess($root, 'Initialize credential store')) { return }

    # Recipients: whoever was named, else this machine's own public key.
    $recipients = @($Recipient)
    if (-not $recipients -or $recipients.Count -eq 0) {
        if ($Provider -eq 'age') {
            $identityPath = Get-CredAgeIdentityPath -Config $null
            if (-not (Test-Path -LiteralPath $identityPath -PathType Leaf)) {
                Write-Verbose "No identity at '$identityPath'; creating one."
                $null = New-CredIdentity
            }
        }
        $recipients = @(& $providerObj.GetRecipient $null)
    }

    $null = New-Item -ItemType Directory -Path $credsDir -Force

    $config = [ordered]@{
        version     = $script:CredConfigVersion
        project     = $Project
        provider    = $Provider
        store       = $providerObj.StoreFileName
        recipients  = $recipients
        credentials = [ordered]@{}
    }

    $ctx = [pscustomobject]@{
        Name       = $Project
        Root       = $root
        CredsDir   = $credsDir
        ConfigPath = $configPath
        StorePath  = (Join-Path $credsDir $config.store)
        Config     = $config
        Exists     = $true
    }

    Write-CredConfig -Path $configPath -Config $config
    $lock = Lock-CredStore -CredsDir $credsDir
    try { Write-CredStoreValues -Project $ctx -Values ([ordered]@{}) }
    finally { $lock.Dispose() }

    Set-CredFileText -Path (Join-Path $credsDir '.gitignore') -Text @"
# Managed by cred. The encrypted store and the config are meant to be
# committed; only these transient files are not.
.lock
*.tmp*
"@

    Register-CredProjectPath -Name $Project -Path $root

    Write-Verbose "Initialized '$Project' at '$root'."
    return [pscustomobject]@{
        Project    = $Project
        Root       = $root
        Provider   = $Provider
        Store      = $ctx.StorePath
        Recipients = $recipients
    }
}
