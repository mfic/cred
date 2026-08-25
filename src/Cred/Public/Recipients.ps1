#requires -Version 5.1

function Get-CredRecipient {
    <#
        .SYNOPSIS
        List the public keys that can decrypt a project's store.

        .EXAMPLE
        Get-CredRecipient acme-api
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Project,
        [string]$Path
    )

    $ctx  = Resolve-CredProject -Name $Project -Path $Path
    $mine = try { & (Get-CredProviderInternal -Name $ctx.Config.provider).GetRecipient $ctx.Config } catch { $null }

    foreach ($r in @($ctx.Config.recipients)) {
        [pscustomobject]@{
            Project   = $ctx.Name
            Recipient = $r
            IsMe      = ($mine -and $r -eq $mine)
        }
    }
}

function Add-CredRecipient {
    <#
        .SYNOPSIS
        Grant a public key access to a project, re-encrypting the store.

        .DESCRIPTION
        You must be able to decrypt the store yourself to do this: cred reads
        the values, adds the recipient and writes the whole store back.

        .EXAMPLE
        Add-CredRecipient acme-api -Recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

        .EXAMPLE
        Add-CredRecipient acme-api -Recipient (New-CredIdentity -Show).Recipient
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string[]]$Recipient,
        [string]$Project,
        [string]$Path
    )

    $ctx = Resolve-CredProject -Name $Project -Path $Path

    foreach ($r in $Recipient) {
        if ($ctx.Config.provider -eq 'age' -and $r -notmatch '^(age1|ssh-(ed25519|rsa) )') {
            throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $r `
                -Message "'$r' does not look like an age recipient." `
                -Next @("age public keys start with 'age1'; SSH keys with 'ssh-ed25519 ' or 'ssh-rsa '.",
                        "Ask the other person for: cred keygen --show"))
        }
    }

    if (-not $PSCmdlet.ShouldProcess($ctx.Name, "Add recipient(s) and re-encrypt")) { return }
    $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream

    $state = @{ Added = @() }
    Update-CredStoreValues -Project $ctx -Mutate {
        param($values, $project)

        $current = [System.Collections.Generic.List[string]]::new()
        foreach ($x in @($project.Config.recipients)) { $current.Add([string]$x) }
        foreach ($r in $Recipient) {
            if (-not $current.Contains($r)) { $current.Add($r); $state.Added += $r }
        }
        $project.Config.recipients = $current.ToArray()
        return $values
    }

    return [pscustomobject]@{
        Project    = $ctx.Name
        Added      = $state.Added
        Recipients = @($ctx.Config.recipients)
    }
}

function Remove-CredRecipient {
    <#
        .SYNOPSIS
        Revoke a public key's access and re-encrypt the store without it.

        .NOTES
        Anyone who held that key can still read every older version of the
        store from git history. Treat revocation as a reason to rotate the
        secrets themselves, not as a substitute for it.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string[]]$Recipient,
        [string]$Project,
        [string]$Path
    )

    $ctx = Resolve-CredProject -Name $Project -Path $Path
    if (-not $PSCmdlet.ShouldProcess($ctx.Name, "Remove recipient(s) and re-encrypt")) { return }
    $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream

    $state = @{ Removed = @() }
    Update-CredStoreValues -Project $ctx -Mutate {
        param($values, $project)

        $current = [System.Collections.Generic.List[string]]::new()
        foreach ($x in @($project.Config.recipients)) { $current.Add([string]$x) }
        foreach ($r in $Recipient) {
            if ($current.Remove($r)) { $state.Removed += $r }
        }
        if ($current.Count -eq 0) {
            throw (New-CredErrorRecord -Code 'Usage' `
                -Message 'Removing that would leave the store with no recipients, so nobody could ever read it again.' `
                -Next @("Add a replacement first: cred recipients add <public-key>",
                        "Or delete the project's .creds directory outright."))
        }
        $project.Config.recipients = $current.ToArray()
        return $values
    }

    Write-Warning "Recipients removed. Anyone who held a removed key can still read this store from git history -- rotate the secrets themselves."
    return [pscustomobject]@{
        Project    = $ctx.Name
        Removed    = $state.Removed
        Recipients = @($ctx.Config.recipients)
    }
}
