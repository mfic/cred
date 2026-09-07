#requires -Version 5.1

function Import-Cred {
    <#
        .SYNOPSIS
        Bring existing PSCredentials into a store.

        .DESCRIPTION
        Accepts PSCredential objects on the pipeline, or a path to the files
        PowerShell normally keeps them in:

          *.xml / *.clixml   Export-Clixml of a PSCredential or a SecureString
          *.txt / *.cred     ConvertFrom-SecureString output (DPAPI hex)

        Point it at a folder and every matching file becomes a credential named
        after the file. Use -WhatIf first to see what it would do.

        Timing matters: both formats above are DPAPI-protected and only open for
        the Windows account that wrote them. Import on that account, on that
        machine, before you migrate anywhere.

        .EXAMPLE
        Import-Cred -Path C:\old\creds -Project acme-api -WhatIf

        .EXAMPLE
        Import-Cred -Path C:\old\creds\db.xml -Project acme-api -Name db

        .EXAMPLE
        Get-Credential svc_acme | Import-Cred -Project acme-api -Name db
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Path')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path', Position = 0)]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Pipeline', ValueFromPipeline)]
        [System.Management.Automation.PSCredential]$Credential,

        [string]$Name,
        [string]$Project,
        [string]$ProjectPath,
        [string]$Description,
        [switch]$Force
    )

    begin {
        $ctx     = Resolve-CredProject -Name $Project -Path $ProjectPath
        $results = [System.Collections.Generic.List[object]]::new()

        function Add-One {
            param([string]$Key, [string]$User, [string]$Secret, [string]$Source)

            if (-not (Test-CredKeyName $Key)) {
                $clean = ($Key -replace '[^A-Za-z0-9._-]', '-') -replace '^[^A-Za-z0-9]+', ''
                if (-not (Test-CredKeyName $clean)) {
                    throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $Key `
                        -Message "Cannot derive a usable credential name from '$Source'." `
                        -Next "Import it on its own and name it: cred import '$Source' --name <key>")
                }
                Write-Verbose "Renamed '$Key' to '$clean'."
                $Key = $clean
            }

            $exists = $ctx.Config.credentials.Contains($Key)
            if ($exists -and -not $Force) {
                Write-Warning "Skipping '$Key': it already exists. Pass -Force to overwrite."
                $results.Add([pscustomobject]@{ Key = $Key; Source = $Source; Action = 'skipped' })
                return
            }

            if ($PSCmdlet.ShouldProcess("$($ctx.Name)/$Key", "Import from $Source")) {
                $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream
                $splat = @{ Name = $Key; Secret = $Secret; Path = $ctx.Root; Confirm = $false }
                if ($User)        { $splat.User = $User }
                if ($Description) { $splat.Description = $Description }
                $r = Set-Cred @splat
                $results.Add([pscustomobject]@{
                    Key = $Key; Source = $Source
                    Action = if ($r.Created) { 'imported' } else { 'replaced' }
                    Type = $r.Type
                })
            }
            else {
                $results.Add([pscustomobject]@{ Key = $Key; Source = $Source; Action = 'would import' })
            }
        }

        function Read-CredentialFile {
            <#
                Returns @{ User; Secret } or $null if the file is not a
                credential we recognise.
            #>
            param([string]$File)

            $ext = [System.IO.Path]::GetExtension($File).ToLowerInvariant()

            if ($ext -in '.xml', '.clixml') {
                $obj = Import-Clixml -LiteralPath $File
                if ($obj -is [System.Management.Automation.PSCredential]) {
                    return @{ User = $obj.UserName; Secret = $obj.GetNetworkCredential().Password }
                }
                if ($obj -is [System.Security.SecureString]) {
                    return @{ User = $null; Secret = (ConvertFrom-CredSecureString -SecureString $obj) }
                }
                Write-Warning "Skipping '$File': it holds a $($obj.GetType().Name), not a credential."
                return $null
            }

            # ConvertFrom-SecureString output: DPAPI over the UTF-16 bytes, hex
            # encoded. Unprotected directly rather than via the Security module,
            # which does not autoload on every 5.1 host.
            $text = (Get-CredFileText -Path $File).Trim()
            if ($text -notmatch '^[0-9a-fA-F]+$' -or $text.Length -lt 32) {
                Write-Warning "Skipping '$File': not a recognised credential file."
                return $null
            }
            $bytes = [byte[]]::new($text.Length / 2)
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $bytes[$i] = [Convert]::ToByte($text.Substring($i * 2, 2), 16)
            }
            $plain = Unprotect-CredSecretBytes -Bytes $bytes
            try   { return @{ User = $null; Secret = [System.Text.Encoding]::Unicode.GetString($plain) } }
            finally { [array]::Clear($plain, 0, $plain.Length) }
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Pipeline') {
            $key = if ($Name) { $Name } else { $Credential.UserName }
            Add-One -Key $key -User $Credential.UserName `
                    -Secret $Credential.GetNetworkCredential().Password -Source 'pipeline'
            return
        }

        if (-not (Test-Path -LiteralPath $Path)) {
            throw (New-CredErrorRecord -Code 'Usage' -Category ObjectNotFound -Target $Path `
                -Message "'$Path' does not exist." `
                -Next "Point at a credential file or a folder of them.")
        }

        $files = if (Test-Path -LiteralPath $Path -PathType Container) {
            @(Get-ChildItem -LiteralPath $Path -File |
              Where-Object { $_.Extension -in '.xml', '.clixml', '.txt', '.cred' } |
              Sort-Object Name)
        }
        else {
            @(Get-Item -LiteralPath $Path)
        }

        if ($files.Count -eq 0) {
            Write-Warning "No credential files found in '$Path' (looking for *.xml, *.clixml, *.txt, *.cred)."
            return
        }

        foreach ($f in $files) {
            $parsed = try { Read-CredentialFile -File $f.FullName }
                      catch {
                          Write-Warning "Skipping '$($f.Name)': $($_.Exception.Message.Split([Environment]::NewLine)[0])"
                          $null
                      }
            if (-not $parsed) { continue }

            # 'db.cred.xml' -> 'db'
            $key = if ($Name -and $files.Count -eq 1) { $Name }
                   else { [System.IO.Path]::GetFileNameWithoutExtension($f.Name) -replace '\.cred$', '' }

            Add-One -Key $key -User $parsed.User -Secret $parsed.Secret -Source $f.Name
        }
    }

    end { return $results }
}

function Export-Cred {
    <#
        .SYNOPSIS
        Write credentials back out as PSCredential files, for tools that still
        want them.

        .DESCRIPTION
        Produces Export-Clixml files, one per credential. On Windows those are
        DPAPI-protected and readable only by you on this machine; everywhere
        else Export-Clixml writes the secret in PLAIN TEXT, so this refuses to
        run off Windows unless you pass -Force and mean it.

        This is an escape hatch for migration and interop. Everyday use should
        go through cred exec or Get-CredCredential, which put nothing on disk.

        .EXAMPLE
        Export-Cred -Path C:\handoff -Project acme-api -WhatIf

        .EXAMPLE
        Export-Cred -Path C:\handoff -Project acme-api -Only db
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [string]$Project,
        [string]$ProjectPath,
        [string[]]$Only,
        [switch]$Force
    )

    if (-not (Test-CredClixmlProtectsSecrets) -and -not $Force) {
        throw (New-CredErrorRecord -Code 'Usage' `
            -Message 'Off Windows, Export-Clixml writes secrets in plain text.' `
            -Next @("Use Get-CredCredential in-process instead, or",
                    "pass -Force if you genuinely want plaintext files on disk."))
    }

    $ctx    = Resolve-CredProject -Name $Project -Path $ProjectPath
    $values = Read-CredStoreValues -Project $ctx
    $null   = New-CredDirectory -Path $Path

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($key in @($values.Keys)) {
        if ($Only -and $key -notin $Only) { continue }

        $entry = $values[$key]
        $def   = if ($ctx.Config.credentials.Contains($key)) { $ctx.Config.credentials[$key] } else { $null }

        # A file credential has no PSCredential shape, so it goes back out as
        # the file it came in as -- which is what anyone exporting one wants.
        if ((Get-CredEntryKind -Entry $entry -Definition $def) -eq 'file') {
            $leaf = if ($def -and $def.Contains('filename') -and $def.filename) { $def.filename } else { $key }
            $fileTarget = Join-Path $Path $leaf
            if ($PSCmdlet.ShouldProcess($fileTarget, "Export $($ctx.Name)/$key")) {
                $ConfirmPreference = 'None'
                Write-CredPrivateFile -Path $fileTarget -Bytes (ConvertFrom-CredFileContent -Entry $entry)
                $out.Add([pscustomobject]@{ Key = $key; UserName = '-'; File = $fileTarget })
            }
            continue
        }

        $user  = if ($entry.Contains('user') -and $entry['user']) { [string]$entry['user'] } else { $key }
        $file  = Join-Path $Path "$key.cred.xml"

        if ($PSCmdlet.ShouldProcess($file, "Export $($ctx.Name)/$key")) {
            $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream
            $cred = [System.Management.Automation.PSCredential]::new(
                        $user, (ConvertTo-CredSecureString -PlainText ([string]$entry['secret'])))
            $cred | Export-Clixml -LiteralPath $file
            $null = Protect-CredPath -Path $file
            $out.Add([pscustomobject]@{ Key = $key; UserName = $user; File = $file })
        }
    }

    if ($out.Count -gt 0) {
        Write-Warning "$($out.Count) credential file(s) written to '$Path'. Delete them once the migration is done."
    }
    return $out
}
