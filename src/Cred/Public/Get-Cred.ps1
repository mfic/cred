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
    [OutputType([string], [System.Security.SecureString])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [ValidateSet('secret', 'user')][string]$Field = 'secret',
        [switch]$AsSecureString,
        [string]$Project,
        [string]$Path
    )

    $ref = Split-CredReference -Reference $Name
    $key = $ref.Key
    if ($ref.Project -and -not $Project) { $Project = $ref.Project }

    $ctx    = Resolve-CredProject -Name $Project -Path $Path
    $values = Read-CredStoreValues -Project $ctx
    $entry  = Get-CredEntryOrThrow -Project $ctx -Key $key -Values $values

    if (-not $entry.Contains($Field)) {
        $type = if ($ctx.Config.credentials.Contains($key)) { $ctx.Config.credentials[$key].type } else { 'secret' }
        throw (New-CredErrorRecord -Code 'NoCredential' -Category ObjectNotFound -Target $Field `
            -Message "'$($ctx.Name)/$key' has no '$Field' field." `
            -Next @("It is a '$type' credential with: $(@($entry.Keys) -join ', ')",
                    "To give it a username: cred add $($ctx.Name)/$key --user <name>"))
    }

    $value = [string]$entry[$Field]
    if ($AsSecureString) { return (ConvertTo-CredSecureString -PlainText $value) }
    return $value
}

function Get-CredNearestKey {
    <#
        .SYNOPSIS
        Cheap "did you mean" suggestion (Levenshtein, distance <= 2).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Key, [string[]]$Candidates)

    if (-not $Candidates -or [string]::IsNullOrEmpty($Key)) { return $null }
    $best = $null; $bestScore = [int]::MaxValue

    foreach ($c in $Candidates) {
        $a = $Key.ToLowerInvariant(); $b = ([string]$c).ToLowerInvariant()
        if ($b.Length -eq 0) { continue }
        $prev = 0..$b.Length
        for ($i = 1; $i -le $a.Length; $i++) {
            $cur = @($i) + (1..$b.Length | ForEach-Object { 0 })
            for ($j = 1; $j -le $b.Length; $j++) {
                $cost = if ($a[$i - 1] -eq $b[$j - 1]) { 0 } else { 1 }
                $cur[$j] = [Math]::Min([Math]::Min($cur[$j - 1] + 1, $prev[$j] + 1), $prev[$j - 1] + $cost)
            }
            $prev = $cur
        }
        $d = $prev[$b.Length]
        if ($d -lt $bestScore) { $bestScore = $d; $best = $c }
    }
    if ($bestScore -le 2) { return $best }
    return $null
}
