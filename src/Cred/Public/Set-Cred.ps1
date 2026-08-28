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

        .EXAMPLE
        Set-Cred acme-api/ssl-key -File .\server.key -Description 'TLS private key'
        Store a file's exact bytes. It is not injected by `cred exec`; read it
        back with Export-CredFile or `cred get acme-api/ssl-key --out <path>`.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [Parameter(Position = 1)][object]$Secret,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$User,
        [string]$File,
        [string]$FileName,
        [string]$Description,
        [hashtable]$Env,
        [switch]$FromStdin,
        [switch]$AllowEmpty,
        [switch]$Force,
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

    if ($File -and $User) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $File `
            -Message '-File and -User cannot be combined.' `
            -Next @('A file credential is one blob of content; it has no username.',
                    'If you need both, store them as two credentials.'))
    }

    # A PSCredential carries both halves, so it fills in -User as well. That is
    # the whole point: importing one should not need two parameters.
    if ($Credential) {
        if (-not $User) { $User = $Credential.UserName }
        if ($null -eq $Secret) { $Secret = $Credential.GetNetworkCredential().Password }
    }

    $ctx = Resolve-CredProject -Name $Project -Path $Path

    $encoding  = $null
    $storeName = ''
    $byteCount = 0
    if ($File) {
        $bytes     = Read-CredImportFile -Path $File -Force:$Force
        $byteCount = $bytes.Length
        # Byte-exact: no newline stripping, no line-ending translation. A PEM
        # that round-trips through Export-CredFile must be the same file.
        $encoded   = ConvertTo-CredFileContent -Bytes $bytes
        $plain     = $encoded.Text
        $encoding  = $encoded.Encoding
        $storeName = if ($FileName) { $FileName } else { Split-Path -Leaf $File }
        if (-not $AllowEmpty -and $byteCount -eq 0) {
            throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $File `
                -Message 'The file is empty.' `
                -Next 'Provide a value, or pass -AllowEmpty / --allow-empty.')
        }
    }
    else {
        $prompt = if ($User) { "Password for '$User' ($($ctx.Name)/$key)" } else { "Secret for $($ctx.Name)/$key" }
        $plain  = Resolve-CredSecretInput -Value $Secret -Prompt $prompt -FromStdin:$FromStdin -AllowEmpty:$AllowEmpty
    }

    if (-not $PSCmdlet.ShouldProcess("$($ctx.Name)/$key", 'Set credential')) { return }
    $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream

    # Scriptblocks run in a child scope; a hashtable is the simplest way to
    # get a value back out of one.
    $state = @{ Created = $false }
    Update-CredStoreValues -Project $ctx -Mutate {
        param($values, $project)

        $existing = if ($values.Contains($key)) { $values[$key] } else { $null }
        $state.Created = -not $existing

        $type = if ($File) { 'file' }
                elseif ($User) { 'userpass' }
                elseif ($existing -and $existing.Contains('user')) { 'userpass' }
                else { 'secret' }

        $entry = [ordered]@{}
        if ($type -eq 'userpass') {
            $entry.user = if ($User) { $User }
                          elseif ($existing) { $existing.user }
                          else { '' }
        }
        $entry.secret = $plain
        if ($encoding) { $entry.encoding = $encoding }
        $values[$key] = $entry

        # Keep the plaintext definition in step.
        $defs = $project.Config.credentials
        if (-not $defs.Contains($key)) {
            $defs[$key] = New-CredDefinition -Key $key -Type $type -Description $Description `
                                             -Env $Env -FileName $storeName
        }
        else {
            $def = $defs[$key]
            $def.type = $type
            if ($Description) { $def.description = $Description }
            if ($type -eq 'file') {
                # The leftovers of a previous type would be a lie in a
                # committed, readable file.
                $def.env = Get-CredEnvNames -Key $key -Kind 'file'
                $def.filename = $storeName
            }
            else {
                if ($def.Contains('filename')) { $def.Remove('filename') }
                # Promoting a secret to a userpass needs the 'user' name the
                # convention would have given it. Get-CredEnvNames is that
                # convention; a third inline copy of the slug rule is not.
                if ($type -eq 'userpass' -and -not $def.env.Contains('user')) {
                    $def.env.user = (Get-CredEnvNames -Key $key -Kind 'userpass')['user']
                }
                if ($Env) {
                    foreach ($k in $Env.Keys) { $def.env[[string]$k] = [string]$Env[$k] }
                }
            }
        }
        return $values
    }

    return [pscustomobject]@{
        Project   = $ctx.Name
        Key       = $key
        Type      = $ctx.Config.credentials[$key].type
        Created   = $state.Created
        Store     = $ctx.StorePath
        FileName  = $storeName
        ByteCount = $byteCount
        Encoding  = $encoding
    }
}
