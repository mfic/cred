#requires -Version 5.1

function Set-CredMetadata {
    <#
        .SYNOPSIS
        Edit one credential's declaration without touching its value.

        .DESCRIPTION
        Set-Cred could always write a description, but only by writing a
        secret along with it: the entry it builds is the whole entry and not a
        patch, so fixing a typo in a description meant re-supplying the
        password. That is a bad trade twice over -- it needs the key for a
        change that is not secret, and a mistyped re-entry silently replaces
        the credential with whatever was typed, which nothing afterwards can
        tell from a deliberate rotation.

        So this is the writer for the half of a credential that is not secret,
        and it goes through Update-CredProjectConfig: the store is never
        opened. It therefore works on a machine with no key, and for someone
        who is not one of the project's recipients.

        What it will not do is edit the type, the recorded filename, or the
        key itself. Those describe what is in the store, and changing one here
        would make the declaration disagree with the value it declares --
        `cred doctor`'s job is to find that, not this function's to create it.

        Peer of set_metadata in python/cred_store.py.

        .EXAMPLE
        Set-CredMetadata wat/dongleserver -Description 'WAT - Dongleserver (10.141.30.61)'
        Record what the credential is for. The password is not read, not
        prompted for, and not rewritten.

        .EXAMPLE
        Set-CredMetadata acme-api/db -Env @{ secret = 'PGPASSWORD' }
        Rename the variable `cred exec` injects, without a round trip through
        the secret.

        .EXAMPLE
        Set-CredMetadata acme-api/db -ClearDescription
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [string]$Description,
        [switch]$ClearDescription,
        [hashtable]$Env,
        [string]$Project,
        [string]$Path
    )

    $ref = Split-CredReference -Reference $Name
    $key = $ref.Key
    if ($ref.Project -and -not $Project) { $Project = $ref.Project }

    if (-not (Test-CredKeyName $key)) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $Name `
            -Message "'$Name' does not name a credential." `
            -Next 'Use: cred meta <project>/<key> --desc <text>')
    }

    $hasDescription = $PSBoundParameters.ContainsKey('Description')
    $envSecret = if ($Env -and $Env.ContainsKey('secret')) { $Env['secret'] } else { $null }
    $envUser   = if ($Env -and $Env.ContainsKey('user'))   { $Env['user'] }   else { $null }

    if ($hasDescription -and $ClearDescription) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $Name `
            -Message '--desc and --clear-desc ask for opposite things.' `
            -Next 'Pass one or the other.')
    }

    $ctx = Resolve-CredProject -Name $Project -Path $Path

    if (-not $hasDescription -and -not $ClearDescription -and
        $null -eq $envSecret -and $null -eq $envUser) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $Name `
            -Message "Nothing to change on '$($ctx.Name)/$key'." `
            -Next @('Say what to set: --desc <text>, --clear-desc, --env <NAME> or --env-user <NAME>.',
                    "See what it holds now: cred list $($ctx.Name)"))
    }

    if (-not $PSCmdlet.ShouldProcess("$($ctx.Name)/$key", 'Set credential metadata')) { return }
    $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream

    # Scriptblocks run in a child scope; a hashtable is the simplest way to get
    # values back out of one.
    $state = @{ Kind = ''; Changed = [System.Collections.Generic.List[object]]::new() }
    Update-CredProjectConfig -Project $ctx -Mutate {
        param($config, $project)

        $defs = $config.credentials
        if (-not $defs.Contains($key)) {
            throw (New-CredErrorRecord -Code 'NoCredential' -Category ObjectNotFound -Target $key `
                -Message "'$($project.Name)/$key' is not declared in .creds/config.json." `
                -Next @("See what is: cred list $($project.Name)",
                        "Create it: cred add $($project.Name)/$key"))
        }

        $def  = $defs[$key]
        $kind = if ($def.Contains('type') -and $def.type) { [string]$def.type } else { 'secret' }
        $state.Kind = $kind

        # A file credential has no environment representation at all -- see
        # Set-Cred, which empties the map for exactly that reason. Naming a
        # variable for one would be a declaration `cred exec` then ignores.
        if ($kind -eq 'file' -and ($null -ne $envSecret -or $null -ne $envUser)) {
            throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $key `
                -Message "'$($project.Name)/$key' is a file credential, so it has no environment variable." `
                -Next @("A file is read back with: cred get $($project.Name)/$key --out <path>",
                        'Only --desc and --clear-desc apply to it.'))
        }
        if ($kind -ne 'userpass' -and $null -ne $envUser) {
            throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $key `
                -Message "'$($project.Name)/$key' is a $kind, so it has no username half." `
                -Next @('--env-user applies to a userpass credential.',
                        "Make it one: cred add $($project.Name)/$key --user <name>"))
        }

        if ($null -ne $envSecret) {
            if (-not $def.Contains('env')) { $def.env = [ordered]@{} }
            $def.env.secret = Assert-CredEnvName -Name $envSecret -Option '--env'
            $state.Changed.Add(@('env.secret', $def.env.secret))
        }
        if ($null -ne $envUser) {
            if (-not $def.Contains('env')) { $def.env = [ordered]@{} }
            $def.env.user = Assert-CredEnvName -Name $envUser -Option '--env-user'
            $state.Changed.Add(@('env.user', $def.env.user))
        }
        if ($hasDescription) {
            $def.description = $Description
            $state.Changed.Add(@('description', $Description))
        }
        if ($ClearDescription) {
            # Idempotent: clearing what is already absent is not an error, it
            # is the state being asked for.
            if ($def.Contains('description')) { $def.Remove('description') }
            $state.Changed.Add(@('description', ''))
        }
    }

    return [pscustomobject]@{
        Project = $ctx.Name
        Key     = $key
        Kind    = $state.Kind
        Changed = @($state.Changed)
    }
}
