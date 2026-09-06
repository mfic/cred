#requires -Version 5.1

function Test-CredHealth {
    <#
        .SYNOPSIS
        Check that everything cred needs is in place, and say how to fix what
        is not.

        .DESCRIPTION
        Emits one row per check with Status of Ok, Warn or Fail and, when
        something is wrong, a Fix you can run. Checks the backend binaries, your
        key and its permissions, and -- if run inside a project -- that project's
        config, store, recipients and git hygiene.

        .EXAMPLE
        Test-CredHealth

        .EXAMPLE
        Test-CredHealth -Project acme-api | Format-Table
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Project,
        [string]$Path
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    function Add-Row([string]$Check, [string]$Status, [string]$Detail, [string]$Fix = '') {
        # A fix is only advice when something is actually wrong.
        if ($Status -eq 'Ok') { $Fix = '' }
        $rows.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail; Fix = $Fix })
    }

    Add-Row 'powershell' 'Ok' "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"

    foreach ($name in (@($script:CredProviders.Keys) | Sort-Object)) {
        $p = $script:CredProviders[$name]
        $s = & $p.Test
        if ($s.Available) { Add-Row "provider:$name" 'Ok' $s.Detail }
        else              { Add-Row "provider:$name" 'Warn' $s.Detail $p.InstallHint }
    }

    $credHome = Get-CredHomeDirectory
    Add-Row 'cred home' $(if (Test-Path -LiteralPath $credHome) { 'Ok' } else { 'Warn' }) $credHome 'Run: cred init'

    $identity = Get-CredIdentityPath -Config $null
    if (Test-Path -LiteralPath $identity -PathType Leaf) {
        Add-Row 'identity' 'Ok' $identity
        if (Test-CredPathIsPrivate -Path $identity) {
            Add-Row 'identity permissions' 'Ok' 'Readable only by you.'
        }
        else {
            Add-Row 'identity permissions' 'Warn' 'Other principals can read your key file.' `
                    "Run: cred doctor --repair"
        }
        $inRepo = $false
        try {
            $root = Find-CredProjectRoot -StartPath (Split-Path -Parent $identity)
            $inRepo = [bool]$root
        } catch { $inRepo = $false }
        if ($inRepo) {
            Add-Row 'identity location' 'Fail' 'Your secret key is inside a repository.' `
                    "Move it out of the repo and set `$env:CRED_IDENTITY_FILE to the new path."
        }
    }
    else {
        Add-Row 'identity' 'Warn' "No key at '$identity'." 'Run: cred keygen'
    }

    # Project-specific checks, only if we can find a project.
    $ctx = try { Resolve-CredProject -Name $Project -Path $Path } catch { $null }
    if (-not $ctx) {
        Add-Row 'project' 'Warn' 'Not inside a project (and none named).' 'Run: cred init'
        return $rows
    }

    Add-Row 'project' 'Ok' "$($ctx.Name) at $($ctx.Root)"

    # A project resolves by walking up from the cwd, so a healthy store can be
    # entirely absent from the registry -- fine from inside the directory,
    # invisible by name from anywhere else. Doctor used to report that as Ok.
    $entry = try { (Read-CredRegistry).projects[$ctx.Name] } catch { $null }
    if ($entry -and $entry.path -eq $ctx.Root) {
        Add-Row 'registry' 'Ok' "Registered as '$($ctx.Name)'."
    }
    elseif ($entry) {
        Add-Row 'registry' 'Warn' "'$($ctx.Name)' is registered at '$($entry.path)', not here." `
                "Point it here: cred project add '$($ctx.Root)'"
    }
    else {
        Add-Row 'registry' 'Warn' "'$($ctx.Name)' is not registered, so 'cred $($ctx.Name)/<key>' only works from inside this directory." `
                "Register it: cred project add '$($ctx.Root)'"
    }

    if (Test-Path -LiteralPath $ctx.StorePath -PathType Leaf) {
        Add-Row 'store' 'Ok' $ctx.StorePath
        try {
            $values = Read-CredStoreValues -Project $ctx
            Add-Row 'decrypt' 'Ok' "$($values.Count) credential(s) readable."
        }
        catch {
            Add-Row 'decrypt' 'Fail' $_.Exception.Message.Split([Environment]::NewLine)[0] `
                    'See: cred recipients'
        }
    }
    else {
        Add-Row 'store' 'Warn' "No store at '$($ctx.StorePath)'." "Run: cred add $($ctx.Name)/<key>"
    }

    $mine = try { & (Get-CredProviderInternal -Name $ctx.Config.provider).GetRecipient $ctx.Config } catch { $null }
    if ($mine -and @($ctx.Config.recipients) -contains $mine) {
        Add-Row 'recipients' 'Ok' "$(@($ctx.Config.recipients).Count) recipient(s); you are one."
    }
    elseif ($mine) {
        Add-Row 'recipients' 'Fail' 'Your key is not a recipient of this project.' `
                "Ask a current recipient to run: cred recipients add $mine"
    }
    else {
        Add-Row 'recipients' 'Warn' "$(@($ctx.Config.recipients).Count) recipient(s); could not determine yours." 'Run: cred keygen'
    }

    # Git hygiene: the store and config should be tracked; nothing else should.
    if (Test-Path -LiteralPath (Join-Path $ctx.Root '.git')) {
        & git -C $ctx.Root check-ignore -q '.creds/config.json' 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Add-Row 'git' 'Warn' '.creds/config.json is gitignored, so it will not travel with the code.' `
                    "Remove '.creds' from .gitignore -- the store is encrypted and meant to be committed."
        }
        else {
            Add-Row 'git' 'Ok' '.creds is committable.'
        }
    }

    return $rows
}

function Repair-CredHealth {
    <#
        .SYNOPSIS
        Re-apply restrictive permissions to the cred home directory and key.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $credHome = Get-CredHomeDirectory
    if ($PSCmdlet.ShouldProcess($credHome, 'Restrict permissions')) {
        $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream
        $null = New-CredDirectory -Path $credHome
        # Say what could not be fixed. Protect-CredPath used to swallow every
        # failure, so --repair reported success no matter what it achieved.
        $failed = [System.Collections.Generic.List[string]]::new()
        if (-not (Protect-CredPath -Path $credHome)) { $failed.Add($credHome) }
        foreach ($f in @(Get-ChildItem -LiteralPath $credHome -File -ErrorAction SilentlyContinue)) {
            if (-not (Protect-CredPath -Path $f.FullName)) { $failed.Add($f.FullName) }
        }
        if ($failed.Count -gt 0) {
            Write-Warning "Could not tighten permissions on $($failed.Count) path(s) under '$credHome'."
        }
    }
    return (Test-CredHealth)
}
