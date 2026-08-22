#requires -Version 5.1

function Set-Cred {
    <#
        .SYNOPSIS
        Add or replace one credential.

        .DESCRIPTION
        Writes the value into the project's encrypted store and, if the
        credential is new, records its plaintext definition (type, description,
        environment-variable names) in .creds/config.json.

        With no -Secret the value is prompted for without echo, so it never
        reaches your shell history or the process list.

        .EXAMPLE
        Set-Cred acme-api/stripe
        Prompt for a value and store it.

        .EXAMPLE
        Set-Cred acme-api/db -User svc_acme -Description 'Postgres, prod'
        Store a username/password pair; the password is prompted for.

        .EXAMPLE
        Get-Content token.txt | Set-Cred acme-api/gh -FromStdin

        .EXAMPLE
        Set-Cred acme-api/db -Credential (Import-Clixml old-db.xml)
        Take the username and the password together from an existing
        PSCredential -- the usual shape of a migration.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [Parameter(Position = 1)][object]$Secret,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$User,
        [string]$Description,
        [hashtable]$Env,
        [switch]$FromStdin,
        [switch]$AllowEmpty,
        [string]$Project,
        [string]$Path
    )

    $ref = Split-CredReference -Reference $Name
    $key = $ref.Key
    if ($ref.Project -and -not $Project) { $Project = $ref.Project }

    if (-not $key) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $Name `
            -Message 'No credential name was given.' `
            -Next "Use: cred add <project>/<key>   e.g. cred add acme-api/stripe")
    }
    if (-not (Test-CredKeyName $key)) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $key `
            -Message "'$key' is not a usable credential name." `
            -Next "Use letters, digits, dot, dash or underscore, e.g. 'db' or 'stripe.live'.")
    }

    # A PSCredential carries both halves, so it fills in -User as well. That is
    # the whole point: importing one should not need two parameters.
    if ($Credential) {
        if (-not $User) { $User = $Credential.UserName }
        if ($null -eq $Secret) { $Secret = $Credential.GetNetworkCredential().Password }
    }

    $ctx = Resolve-CredProject -Name $Project -Path $Path

    $prompt = if ($User) { "Password for '$User' ($($ctx.Name)/$key)" } else { "Secret for $($ctx.Name)/$key" }
    $plain  = Resolve-CredSecretInput -Value $Secret -Prompt $prompt -FromStdin:$FromStdin -AllowEmpty:$AllowEmpty

    if (-not $PSCmdlet.ShouldProcess("$($ctx.Name)/$key", 'Set credential')) { return }

    # Scriptblocks run in a child scope; a hashtable is the simplest way to
    # get a value back out of one.
    $state = @{ Created = $false }
    Update-CredStoreValues -Project $ctx -Mutate {
        param($values, $project)

        $existing = if ($values.Contains($key)) { $values[$key] } else { $null }
        $state.Created = -not $existing

        $type = if ($User) { 'userpass' }
                elseif ($existing -and $existing.Contains('user')) { 'userpass' }
                else { 'secret' }

        $entry = [ordered]@{}
        if ($type -eq 'userpass') {
            $entry.user = if ($User) { $User }
                          elseif ($existing) { $existing.user }
                          else { '' }
        }
        $entry.secret = $plain
        $values[$key] = $entry

        # Keep the plaintext definition in step.
        $defs = $project.Config.credentials
        if (-not $defs.Contains($key)) {
            $defs[$key] = New-CredDefinition -Key $key -Type $type -Description $Description -Env $Env
        }
        else {
            $def = $defs[$key]
            $def.type = $type
            if ($Description) { $def.description = $Description }
            if ($type -eq 'userpass' -and -not $def.env.Contains('user')) {
                $slug = ($key -replace '[^A-Za-z0-9]', '_').ToUpperInvariant()
                $def.env.user = "${slug}_USER"
            }
            if ($Env) {
                foreach ($k in $Env.Keys) { $def.env[[string]$k] = [string]$Env[$k] }
            }
        }
        return $values
    }

    return [pscustomobject]@{
        Project = $ctx.Name
        Key     = $key
        Type    = $ctx.Config.credentials[$key].type
        Created = $state.Created
        Store   = $ctx.StorePath
    }
}
