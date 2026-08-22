#requires -Version 5.1

function Remove-Cred {
    <#
        .SYNOPSIS
        Delete a credential's value and its declaration.

        .EXAMPLE
        Remove-Cred acme-api/stripe

        .NOTES
        The old ciphertext stays in git history. If the secret was ever pushed
        anywhere, rotate it at the source as well -- deleting it here only stops
        it being handed out from now on.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [string]$Project,
        [string]$Path,
        [switch]$KeepDefinition
    )

    $ref = Split-CredReference -Reference $Name
    $key = $ref.Key
    if ($ref.Project -and -not $Project) { $Project = $ref.Project }

    $ctx = Resolve-CredProject -Name $Project -Path $Path

    if (-not $PSCmdlet.ShouldProcess("$($ctx.Name)/$key", 'Remove credential')) { return }

    $state = @{ Removed = $false }
    Update-CredStoreValues -Project $ctx -Mutate {
        param($values, $project)

        $null = Get-CredEntryOrThrow -Project $project -Key $key -Values $values
        $values.Remove($key)
        $state.Removed = $true

        if (-not $KeepDefinition -and $project.Config.credentials.Contains($key)) {
            $project.Config.credentials.Remove($key)
        }
        return $values
    }

    return [pscustomobject]@{ Project = $ctx.Name; Key = $key; Removed = $state.Removed }
}
