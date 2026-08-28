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

    # A caller that also needs to know which file credentials were left out
    # opens the store itself -- Open-CredStore plus Get-CredStoreEnvironment
    # gives both from one decryption. That used to be a [ref] parameter here.
    $store = Open-CredStore -Project $Project -Path $Path
    return (Get-CredStoreEnvironment -Store $store -Only $Only -Exclude $Exclude -Prefix $Prefix).Variables
}
