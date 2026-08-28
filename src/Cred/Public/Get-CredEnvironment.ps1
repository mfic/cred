#requires -Version 5.1

function Get-CredEnvironment {
    <#
        .SYNOPSIS
        Return a project's credentials as an environment-variable hashtable.

        .DESCRIPTION
        Maps every credential to the environment-variable names declared in
        .creds/config.json. This is what `cred exec` injects, exposed as a plain
        hashtable so PowerShell scripts can use it directly.

        The store is decrypted once, in memory.

        .EXAMPLE
        $env = Get-CredEnvironment acme-api
        $env.DB_PASSWORD

        .EXAMPLE
        Get-CredEnvironment acme-api -Only db, stripe
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Position = 0)][string]$Project,
        [string[]]$Only,
        [string[]]$Exclude,
        [string]$Path,
        [string]$Prefix
    )

    return (Get-CredEnvironmentReport -Project $Project -Only $Only -Exclude $Exclude `
                                      -Path $Path -Prefix $Prefix).Variables
}

function Get-CredEnvironmentReport {
    <#
        .SYNOPSIS
        The variables to inject, and the file credentials deliberately left out.

        .DESCRIPTION
        Both answers from one decryption. `cred env` and `cred exec` have to
        tell the user what they skipped, and asking Get-CredEnvironment for the
        variables and then opening the store again for the rest would decrypt
        twice -- so this is the function they call, and Get-CredEnvironment is
        the convenience wrapper for the common case.

        It also spares the CLI from opening the store itself, which is not a
        script's job. Peer of environment_and_skipped in cred_store.py.

        .EXAMPLE
        $r = Get-CredEnvironmentReport acme-api
        $r.Variables.DB_PASSWORD
        $r.Skipped   # file credentials, which map to no variable
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Project,
        [string[]]$Only,
        [string[]]$Exclude,
        [string]$Path,
        [string]$Prefix
    )

    $store = Open-CredStore -Project $Project -Path $Path
    return (Get-CredStoreEnvironment -Store $store -Only $Only -Exclude $Exclude -Prefix $Prefix)
}
