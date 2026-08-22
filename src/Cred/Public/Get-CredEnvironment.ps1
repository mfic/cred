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

    $ctx    = Resolve-CredProject -Name $Project -Path $Path
    $values = Read-CredStoreValues -Project $ctx
    $defs   = $ctx.Config.credentials

    if ($Only) {
        $missing = @($Only | Where-Object { -not $values.Contains($_) })
        if ($missing) {
            $known = @($values.Keys) | Sort-Object
            throw (New-CredErrorRecord -Code 'NoCredential' -Category ObjectNotFound -Target $missing[0] `
                -Message "Project '$($ctx.Name)' has no credential named '$($missing -join "', '")'." `
                -Next @(if ($known) { "It has: $($known -join ', ')" } else { "It has no credentials yet." }
                        "Add one with: cred add $($ctx.Name)/$($missing[0])"))
        }
    }

    $result = @{}
    foreach ($key in @($values.Keys)) {
        if ($Only    -and $key -notin $Only)  { continue }
        if ($Exclude -and $key -in  $Exclude) { continue }

        $entry = $values[$key]
        $def   = if ($defs.Contains($key)) {
            $defs[$key]
        }
        else {
            # A value with no declaration (hand-edited config, or written by an
            # older version): fall back to the default naming convention.
            New-CredDefinition -Key $key -Type $(if ($entry.Contains('user')) { 'userpass' } else { 'secret' })
        }

        foreach ($field in @($entry.Keys)) {
            $name = if ($def.env -and $def.env.Contains($field)) {
                [string]$def.env[$field]
            }
            else {
                $slug = ($key -replace '[^A-Za-z0-9]', '_').ToUpperInvariant()
                if ($field -eq 'secret') { $slug } else { "${slug}_$($field.ToUpperInvariant())" }
            }
            if ($Prefix) { $name = "$Prefix$name" }
            if ($result.ContainsKey($name)) {
                Write-Warning "Two credentials in '$($ctx.Name)' both map to `$env:$name; '$key' wins. Give one of them a distinct 'env' name in .creds/config.json."
            }
            $result[$name] = [string]$entry[$field]
        }
    }
    return $result
}
