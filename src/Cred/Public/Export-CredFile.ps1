#requires -Version 5.1

function Export-CredFile {
    <#
        .SYNOPSIS
        Write one credential to a file on disk.

        .DESCRIPTION
        The counterpart to `Set-Cred -File`. A private key is useless to
        openssl or nginx as a string in a pipeline, so this is the one path in
        cred that deliberately puts plaintext on disk. The file is created with
        permissions granting only you, and the caller is told what happened.

        Everything else in cred keeps plaintext off disk. Delete the file when
        the tool that needed it is done.

        A file credential comes back as its exact original bytes. Any other
        credential is written as UTF-8 text with no trailing newline.

        .EXAMPLE
        Export-CredFile acme-api/ssl-key -OutFile D:\tmp\server.key

        .EXAMPLE
        Export-CredFile acme-api/ssl-key -OutFile D:\tmp
        Write it into a directory under the filename it was imported with.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [Parameter(Mandatory, Position = 1)][string]$OutFile,
        [ValidateSet('secret', 'user')][string]$Field = 'secret',
        [switch]$Force,
        [string]$Project,
        [string]$Path
    )

    $ref = Split-CredReference -Reference $Name
    $key = $ref.Key
    if ($ref.Project -and -not $Project) { $Project = $ref.Project }

    $store = Open-CredStore -Project $Project -Path $Path
    $ctx   = $store.Context
    $null  = Get-CredEntryOrThrow -Project $ctx -Key $key -Values $store.Values
    $view  = $store.Entries[$key]

    $target = $OutFile
    if (Test-Path -LiteralPath $target -PathType Container) {
        $leaf = if ($view.FileName) { $view.FileName } else { $key }
        $target = Join-Path $target $leaf
    }
    if ((Test-Path -LiteralPath $target) -and -not $Force) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $target `
            -Message "'$target' already exists." `
            -Next @('Overwriting a key file is not something to do by accident.',
                    'Pass -Force / --force if that is what you mean.'))
    }

    $bytes = Get-CredEntryBytes -Projection $view -Field $Field -ProjectName $ctx.Name

    if (-not $PSCmdlet.ShouldProcess($target, 'Write credential to file')) { return }
    $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream
    Write-CredPrivateFile -Path $target -Bytes $bytes

    return [pscustomobject]@{
        Project   = $ctx.Name
        Key       = $key
        File      = (Resolve-Path -LiteralPath $target).ProviderPath
        ByteCount = $bytes.Length
    }
}
