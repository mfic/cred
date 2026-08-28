#requires -Version 5.1

function Get-CredList {
    <#
        .SYNOPSIS
        List a project's credentials. Values are never included.

        .DESCRIPTION
        Reads .creds/config.json only, so it works without your key and without
        decrypting anything -- useful for onboarding ("what do I need?") and for
        letting an agent see the shape of a project's secrets without seeing the
        secrets. Pass -Verify to additionally decrypt and report which
        declarations actually have a value behind them.

        .EXAMPLE
        Get-CredList acme-api

        .EXAMPLE
        Get-CredList acme-api -Verify | Where-Object { -not $_.HasValue }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Project,
        [string]$Path,
        [switch]$Verify
    )

    $ctx  = Resolve-CredProject -Name $Project -Path $Path
    $defs = $ctx.Config.credentials

    $values = $null
    if ($Verify) { $values = Read-CredStoreValues -Project $ctx }

    # Union of declared credentials and (when verifying) stored ones, so a
    # value with no declaration still shows up rather than hiding.
    $keys = [System.Collections.Generic.List[string]]::new()
    foreach ($k in @($defs.Keys))                   { if (-not $keys.Contains($k)) { $keys.Add($k) } }
    if ($values) { foreach ($k in @($values.Keys))  { if (-not $keys.Contains($k)) { $keys.Add($k) } } }

    foreach ($key in ($keys | Sort-Object)) {
        $def = if ($defs.Contains($key)) { $defs[$key] } else { $null }

        # Ask the entry what it is rather than reading 'type' off the
        # declaration. Without a decrypted store there is no entry to ask, so
        # an empty one still lets the definition speak for itself -- and when
        # -Verify gave us the real entry, the store wins over a config.json
        # that has fallen behind it.
        $entry = if ($values -and $values.Contains($key)) { $values[$key] } else { [ordered]@{} }
        $view  = Resolve-CredEntry -Key $key -Entry $entry -Definition $def

        $row = [ordered]@{
            Project     = $ctx.Name
            Key         = $key
            Type        = $view.Kind
            Environment = $view.Display
            Description = if ($def -and $def.description) { $def.description } else { '' }
        }
        if ($Verify) {
            $row.HasValue = [bool]($values.Contains($key) -and $values[$key]['secret'])
            $row.Declared = [bool]$def
        }
        [pscustomobject]$row
    }
}

function Get-CredProject {
    <#
        .SYNOPSIS
        List the projects registered on this machine.

        .EXAMPLE
        Get-CredProject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Position = 0)][string]$Name)

    $reg = Read-CredRegistry
    foreach ($k in (@($reg.projects.Keys) | Sort-Object)) {
        if ($Name -and $k -ne $Name) { continue }
        $path = $reg.projects[$k].path
        [pscustomobject]@{
            Name      = $k
            Path      = $path
            Available = (Test-Path -LiteralPath (Join-Path (Join-Path $path '.creds') 'config.json') -PathType Leaf)
        }
    }
}

function Unregister-CredProject {
    <#
        .SYNOPSIS
        Forget a project's name-to-path mapping. Touches nothing in the repo.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory, Position = 0)][string]$Name)

    $reg = Read-CredRegistry
    if (-not $reg.projects.Contains($Name)) {
        throw (New-CredErrorRecord -Code 'NoProject' -Category ObjectNotFound -Target $Name `
            -Message "No project named '$Name' is registered." `
            -Next "See what is: cred project list")
    }
    if ($PSCmdlet.ShouldProcess($Name, 'Unregister project')) {
        $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream
        $reg.projects.Remove($Name)
        Write-CredRegistry -Registry $reg
    }
}
