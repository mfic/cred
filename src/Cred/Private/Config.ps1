#requires -Version 5.1
<#
    Config.ps1 -- locating projects and reading/writing the plaintext part of
    a project's credential definition.

    Two files live in <repo>/.creds/ and both are meant to be committed:

      config.json   plaintext.  Declares which credentials exist, what they are
                                for, and which environment variables they map
                                to. No values, no usernames.
      store.age     ciphertext. The values.

    The key that opens store.age lives in the user's config directory and is
    never inside the repo.
#>

$script:CredConfigVersion  = 1
$script:CredDirName        = '.creds'
$script:CredConfigFileName = 'config.json'

function Get-CredRegistryPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path (Get-CredHomeDirectory) 'projects.json')
}

function Read-CredRegistry {
    [CmdletBinding()]
    param()
    $path = Get-CredRegistryPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [ordered]@{ version = $script:CredConfigVersion; projects = [ordered]@{} }
    }
    try {
        $reg = ConvertFrom-CredJson (Get-CredFileText -Path $path)
        if (-not $reg.projects) { $reg.projects = [ordered]@{} }
        return $reg
    }
    catch {
        throw (New-CredErrorRecord -Code 'StoreCorrupt' `
            -Message "The project registry at '$path' is not valid JSON." `
            -Next @("Inspect it, or delete it and re-run 'cred init' in each project.") `
            -InnerException $_.Exception)
    }
}

function Write-CredRegistry {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Registry)
    $path = Get-CredRegistryPath
    $null = New-CredDirectory -Path (Split-Path -Parent $path)
    Set-CredFileText -Path $path -Text (ConvertTo-CredJson $Registry)
}

function Register-CredProjectPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path
    )
    $reg = Read-CredRegistry
    $reg.projects[$Name] = [ordered]@{ path = (Resolve-Path -LiteralPath $Path).ProviderPath }
    Write-CredRegistry -Registry $reg
}

function Find-CredProjectRoot {
    <#
        .SYNOPSIS
        Walk up from StartPath looking for a .creds/config.json.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$StartPath)

    if (-not $StartPath) { $StartPath = (Get-Location).ProviderPath }
    $dir = try { (Resolve-Path -LiteralPath $StartPath -ErrorAction Stop).ProviderPath } catch { $null }
    if (-not $dir) { return $null }
    if (Test-Path -LiteralPath $dir -PathType Leaf) { $dir = Split-Path -Parent $dir }

    while ($dir) {
        if (Test-Path -LiteralPath (Join-Path (Join-Path $dir $script:CredDirName) $script:CredConfigFileName) -PathType Leaf) {
            return $dir
        }
        $parent = Split-Path -Parent $dir
        if ($parent -eq $dir -or -not $parent) { return $null }
        $dir = $parent
    }
    return $null
}

function Split-CredReference {
    <#
        .SYNOPSIS
        Parse "project/key", "key", or "project/" into its parts.

        Credential keys may not contain '/', so the split is unambiguous.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Reference)

    if ($Reference -match '^(?<p>[^/]*)/(?<k>.*)$') {
        return [pscustomobject]@{
            Project = if ($Matches['p']) { $Matches['p'] } else { $null }
            Key     = if ($Matches['k']) { $Matches['k'] } else { $null }
        }
    }
    return [pscustomobject]@{ Project = $null; Key = $Reference }
}

function Test-CredKeyName {
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Name)
    return ($Name -match '^[A-Za-z0-9][A-Za-z0-9._-]*$')
}

function Resolve-CredProject {
    <#
        .SYNOPSIS
        Turn a project name, a path, or "nothing" into a project context.

        Resolution order:
          1. -Path, if given
          2. -Name, looked up in the user's project registry
          3. $env:CRED_PROJECT (a name or a path)
          4. the nearest .creds/config.json at or above the current directory
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Name,
        [string]$Path,
        [switch]$AllowMissing
    )

    $root = $null
    $how  = ''

    if ($Path) {
        $root = Find-CredProjectRoot -StartPath $Path
        if (-not $root -and (Test-Path -LiteralPath $Path -PathType Container)) {
            $root = (Resolve-Path -LiteralPath $Path).ProviderPath
        }
        $how = "path '$Path'"
    }
    elseif ($Name) {
        $reg = Read-CredRegistry
        if ($reg.projects.Contains($Name)) {
            $candidate = $reg.projects[$Name].path
            if (Test-Path -LiteralPath $candidate -PathType Container) {
                $root = Find-CredProjectRoot -StartPath $candidate
                if (-not $root) { $root = $candidate }
            }
            else {
                throw (New-CredErrorRecord -Code 'NoProject' -Category ObjectNotFound -Target $Name `
                    -Message "Project '$Name' is registered at '$candidate', but that directory no longer exists." `
                    -Next @("Re-register it from its new location: cd <new-location>; cred init",
                            "Or forget it: cred project rm $Name"))
            }
        }
        elseif (Test-Path -LiteralPath $Name -PathType Container) {
            $root = Find-CredProjectRoot -StartPath $Name
        }
        if (-not $root) {
            $known = @($reg.projects.Keys) | Sort-Object
            throw (New-CredErrorRecord -Code 'NoProject' -Category ObjectNotFound -Target $Name `
                -Message "No project named '$Name'." `
                -Next @(
                    if ($known) { "Known projects: $($known -join ', ')" } else { "You have no projects yet." }
                    "List them with: cred project list"
                    "Create this one: cd <repo>; cred init --project $Name"))
        }
        $how = "name '$Name'"
    }
    else {
        if ($env:CRED_PROJECT) {
            return Resolve-CredProject -Name $env:CRED_PROJECT -AllowMissing:$AllowMissing
        }
        $root = Find-CredProjectRoot
        $how  = "current directory"
    }

    if (-not $root) {
        throw (New-CredErrorRecord -Code 'NoProject' -Category ObjectNotFound `
            -Message "No credential store found for the $how." `
            -Next @("Create one here:  cred init",
                    "Or name a project: cred <command> <project>/<key>",
                    "Or point at one:   `$env:CRED_PROJECT = '<project-name-or-path>'"))
    }

    $credsDir   = Join-Path $root $script:CredDirName
    $configPath = Join-Path $credsDir $script:CredConfigFileName

    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        if ($AllowMissing) {
            return [pscustomobject]@{
                Name = $Name; Root = $root; CredsDir = $credsDir
                ConfigPath = $configPath; StorePath = $null; Config = $null; Exists = $false
            }
        }
        throw (New-CredErrorRecord -Code 'NoProject' -Category ObjectNotFound `
            -Message "'$root' has no .creds/config.json." `
            -Next "Create one with: cd '$root'; cred init")
    }

    $config = Read-CredConfig -Path $configPath
    return [pscustomobject]@{
        Name       = $config.project
        Root       = $root
        CredsDir   = $credsDir
        ConfigPath = $configPath
        StorePath  = (Join-Path $credsDir $config.store)
        Config     = $config
        Exists     = $true
    }
}

function Read-CredConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try { $cfg = ConvertFrom-CredJson (Get-CredFileText -Path $Path) }
    catch {
        throw (New-CredErrorRecord -Code 'StoreCorrupt' -Target $Path `
            -Message "'$Path' is not valid JSON." `
            -Next @("Fix the syntax, or restore it: git checkout HEAD -- .creds/config.json") `
            -InnerException $_.Exception)
    }

    if (-not $cfg)          { $cfg = [ordered]@{} }
    if (-not $cfg.version)  { $cfg.version = $script:CredConfigVersion }
    if ($cfg.version -gt $script:CredConfigVersion) {
        throw (New-CredErrorRecord -Code 'StoreCorrupt' -Target $Path `
            -Message "'$Path' was written by a newer version of cred (config version $($cfg.version))." `
            -Next "Update cred, then try again.")
    }
    if (-not $cfg.provider)    { $cfg.provider = 'age' }
    # Validate the backend name here rather than at first use, so a typo in
    # config.json fails on `cred list` instead of hours later on `cred get`.
    $null = Get-CredProviderInternal -Name $cfg.provider
    if (-not $cfg.project)     { $cfg.project = Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $Path)) }
    if (-not $cfg.store)       { $cfg.store = (Get-CredProviderInternal -Name $cfg.provider).StoreFileName }
    if (-not $cfg.recipients)  { $cfg.recipients = @() }
    else { $cfg.recipients = @($cfg.recipients) }
    if (-not $cfg.credentials) { $cfg.credentials = [ordered]@{} }
    return $cfg
}

function Write-CredConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Config
    )
    # Force arrays to stay arrays through a single-element round trip.
    $Config.recipients = @($Config.recipients)
    Set-CredFileText -Path $Path -Text (ConvertTo-CredJson $Config)
}

function New-CredDefinition {
    <#
        .SYNOPSIS
        The plaintext metadata for one credential.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [ValidateSet('secret', 'userpass')][string]$Type = 'secret',
        [string]$Description,
        [hashtable]$Env
    )

    $slug = ($Key -replace '[^A-Za-z0-9]', '_').ToUpperInvariant()
    $def = [ordered]@{ type = $Type }
    $def.env = if ($Type -eq 'userpass') {
        [ordered]@{
            user   = if ($Env -and $Env.user)   { $Env.user }   else { "${slug}_USER" }
            secret = if ($Env -and $Env.secret) { $Env.secret } else { "${slug}_PASSWORD" }
        }
    }
    else {
        [ordered]@{ secret = if ($Env -and $Env.secret) { $Env.secret } else { $slug } }
    }
    if ($Description) { $def.description = $Description }
    return $def
}
