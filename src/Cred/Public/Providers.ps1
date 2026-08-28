#requires -Version 5.1

function Get-CredProvider {
    <#
        .SYNOPSIS
        List the encryption backends cred knows about and whether they work
        right now.

        .EXAMPLE
        Get-CredProvider | Format-Table Name, Available, Detail
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Position = 0)][string]$Name)

    foreach ($n in (@($script:CredProviders.Keys) | Sort-Object)) {
        if ($Name -and $n -ne $Name) { continue }
        $p = $script:CredProviders[$n]
        $s = & $p.Test
        [pscustomobject]@{
            Name        = $n
            Summary     = $p.Summary
            StoreFile   = $p.StoreFileName
            Available   = $s.Available
            Detail      = $s.Detail
            InstallHint = $p.InstallHint
        }
    }
}

function Register-CredProvider {
    <#
        .SYNOPSIS
        Add or replace an encryption backend.

        .DESCRIPTION
        A provider is a PSCustomObject. These members are required:

          Name          [string]
          Summary       [string]
          StoreFileName [string]
          InstallHint   [string]
          Test          [scriptblock] ()                                   -> @{Available;Path;Detail}
          NewIdentity   [scriptblock] ($Path)                              -> @{Path;Recipient}
          GetRecipient  [scriptblock] ($Config)                            -> [string]
          Encrypt       [scriptblock] ($PlainBytes, $Config)               -> [byte[]]
          Decrypt       [scriptblock] ($CipherBytes, $CipherPath, $Config) -> [byte[]]

        These are optional, and describe the *key* rather than the store:

          IdentityPath     [scriptblock] ($Config) -> [string] or $null
          SupportsKeystore [bool]

        The key half used to sit outside this contract entirely, so the
        keystore commands reached past the seam into age and DPAPI directly and
        `cred key protect` silently operated on an age key file even for a
        project that used neither. A provider that says nothing here is taken to
        keep its keys somewhere cred does not manage -- a remote vault or KMS,
        say, where there is no local file to wrap.

        Encrypt and Decrypt must not write plaintext to disk and must not pass
        secret material as command-line arguments.

        .EXAMPLE
        Register-CredProvider -Provider $myProvider
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][pscustomobject]$Provider)

    $required = 'Name', 'Summary', 'StoreFileName', 'InstallHint',
                'Test', 'NewIdentity', 'GetRecipient', 'Encrypt', 'Decrypt'
    $missing = @($required | Where-Object { -not $Provider.PSObject.Properties[$_] })
    if ($missing) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument `
            -Message "The provider is missing: $($missing -join ', ')." `
            -Next "See the help for Register-CredProvider for the full contract.")
    }
    if ($PSCmdlet.ShouldProcess($Provider.Name, 'Register credential provider')) {
        $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream
        Register-CredProviderInternal -Provider $Provider
    }
}
