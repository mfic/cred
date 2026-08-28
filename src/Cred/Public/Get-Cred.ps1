#requires -Version 5.1

function Get-Cred {
    <#
        .SYNOPSIS
        Read one credential value.

        .DESCRIPTION
        Returns the secret as a [string] by default so it pipes cleanly, or as
        a [SecureString] with -AsSecureString.

        .EXAMPLE
        Get-Cred acme-api/stripe

        .EXAMPLE
        Get-Cred acme-api/db -Field user

        .EXAMPLE
        Invoke-RestMethod $url -Headers @{ Authorization = "Bearer $(Get-Cred acme-api/gh)" }
    #>
    [CmdletBinding()]
    [OutputType([string], [System.Security.SecureString], [byte[]])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [ValidateSet('secret', 'user')][string]$Field = 'secret',
        [switch]$AsSecureString,
        # Exact bytes rather than a [string]. This is how a file credential is
        # read without a lossy trip through text, and it is what the CLI uses.
        [switch]$AsBytes,
        [string]$Project,
        [string]$Path
    )

    $ref = Split-CredReference -Reference $Name
    $key = $ref.Key
    if ($ref.Project -and -not $Project) { $Project = $ref.Project }

    # One decryption, already resolved. A caller who needs the kind as well as
    # the value calls Open-CredStore rather than passing a [ref] in here.
    $store = Open-CredStore -Project $Project -Path $Path
    $ctx   = $store.Context
    $null  = Get-CredEntryOrThrow -Project $ctx -Key $key -Values $store.Values
    $view  = $store.Entries[$key]

    # Exact bytes are the same question for every kind, so they are one call.
    if ($AsBytes) { return (Get-CredEntryBytes -Projection $view -Field $Field -ProjectName $ctx.Name) }

    if ($view.Kind -eq 'file') {
        # Binary has no faithful [string] form; handing back a mangled one
        # would look like it worked.
        if ($view.IsBinary) {
            throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $key `
                -Message "'$($ctx.Name)/$key' holds binary content, which is not a string." `
                -Next @("Write it to a file: Export-CredFile $($ctx.Name)/$key -OutFile <path>",
                        "Or from the CLI:    cred get $($ctx.Name)/$key --out <path>"))
        }
        $text = [string]$view.Fields['secret']
        if ($AsSecureString) { return (ConvertTo-CredSecureString -PlainText $text) }
        return $text
    }

    if (-not $view.Fields.Contains($Field)) {
        throw (New-CredErrorRecord -Code 'NoCredential' -Category ObjectNotFound -Target $Field `
            -Message "'$($ctx.Name)/$key' has no '$Field' field." `
            -Next @("It is a '$($view.Kind)' credential with: $(@($view.Fields.Keys) -join ', ')",
                    "To give it a username: cred add $($ctx.Name)/$key --user <name>"))
    }

    $value = [string]$view.Fields[$Field]
    if ($AsSecureString) { return (ConvertTo-CredSecureString -PlainText $value) }
    return $value
}
