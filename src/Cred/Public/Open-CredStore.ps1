#requires -Version 5.1

function Open-CredStore {
    <#
        .SYNOPSIS
        Decrypt a project's store once and get every credential back resolved.

        .DESCRIPTION
        The read path in one call. Resolving the project, decrypting the store,
        matching each value against its declaration in config.json and working
        out what kind of credential it is all happen here, and the result
        carries the answers.

        Every other read path in the module goes through this, so a caller that
        wants several credentials -- or wants a value and its kind -- decrypts
        once rather than once per question.

        .Entries is keyed by credential name and covers the union of what is
        stored and what is declared. Each value has Kind ('secret', 'userpass'
        or 'file'), Fields, EnvVars, FileName, IsBinary and Display.

        .EXAMPLE
        $store = Open-CredStore acme-api
        $store.Entries['db'].Kind

        .EXAMPLE
        $store = Open-CredStore acme-api
        $store.Entries.Keys | Where-Object { $store.Entries[$_].Kind -eq 'file' }
        Find the credentials `cred exec` will not inject.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Project,
        [string]$Path
    )

    $ctx    = Resolve-CredProject -Name $Project -Path $Path
    $values = Read-CredStoreValues -Project $ctx
    return New-CredStoreView -Context $ctx -Values $values
}
