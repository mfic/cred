#requires -Version 5.1

$script:CredBriefBegin = '<!-- cred:begin -->'
$script:CredBriefEnd   = '<!-- cred:end -->'

function Get-CredAgentBrief {
    <#
        .SYNOPSIS
        Produce a Markdown block that tells a Claude Code session which
        credentials this project has and how to use them without seeing them.

        .DESCRIPTION
        Lists credential names, types, descriptions and environment-variable
        names -- all of which already sit in plaintext in .creds/config.json --
        and never a value.

        The advice it gives the agent is deliberate: prefer `cred exec`, which
        hands the secret to a child process the agent cannot read, over
        `cred get`, which puts the secret in the agent's transcript. Use
        `cred get` only when the value genuinely has to be seen.

        .EXAMPLE
        Get-CredAgentBrief acme-api

        .EXAMPLE
        Get-CredAgentBrief acme-api | Set-Clipboard
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)][string]$Project,
        [string]$Path
    )

    $ctx  = Resolve-CredProject -Name $Project -Path $Path
    $list = @(Get-CredList -Project $ctx.Name -Path $ctx.Root)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('## Credentials')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("This repository's secrets live encrypted in ``.creds/`` and are handed out by the ``cred`` CLI. Never write a secret into a file, a commit, or your reply.")
    [void]$sb.AppendLine()

    if ($list.Count -eq 0) {
        [void]$sb.AppendLine("_No credentials are defined yet. Add one with_ ``cred add $($ctx.Name)/<key>``.")
    }
    else {
        [void]$sb.AppendLine('| Credential | Type | Environment variables | What it is |')
        [void]$sb.AppendLine('| --- | --- | --- | --- |')
        foreach ($c in $list) {
            $desc = if ($c.Description) { $c.Description } else { '' }
            [void]$sb.AppendLine("| ``$($ctx.Name)/$($c.Key)`` | $($c.Type) | ``$($c.Environment)`` | $desc |")
        }
    }

    [void]$sb.AppendLine()
    [void]$sb.AppendLine('**Preferred — run a command with the secrets injected.** The value never enters this conversation:')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine("cred exec $($ctx.Name) -- <command> [args]")
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('**Only when a value must actually be read** (and then treat the output as poison — do not echo it back):')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine("cred get $($ctx.Name)/<key>")
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('**To see what exists without decrypting anything:**')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine("cred list $($ctx.Name)")
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("If ``cred`` reports that it cannot decrypt, stop and tell the user: their key is missing or is not a recipient. Do not attempt to work around it.")

    return $sb.ToString()
}

function Update-CredAgentBrief {
    <#
        .SYNOPSIS
        Write or refresh the cred block in a project's CLAUDE.md.

        .DESCRIPTION
        The block is delimited by <!-- cred:begin --> / <!-- cred:end -->, so
        re-running this replaces it in place and leaves the rest of the file
        alone.

        .EXAMPLE
        Update-CredAgentBrief acme-api
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Project,
        [string]$Path,
        [string]$File
    )

    $ctx   = Resolve-CredProject -Name $Project -Path $Path
    $brief = Get-CredAgentBrief -Project $ctx.Name -Path $ctx.Root
    if (-not $File) { $File = Join-Path $ctx.Root 'CLAUDE.md' }

    $block = "$($script:CredBriefBegin)`n$brief$($script:CredBriefEnd)`n"

    $existing = if (Test-Path -LiteralPath $File -PathType Leaf) { Get-CredFileText -Path $File } else { '' }
    $pattern  = [regex]::Escape($script:CredBriefBegin) + '.*?' + [regex]::Escape($script:CredBriefEnd) + '\r?\n?'

    $rx = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $updated = if ($rx.IsMatch($existing)) {
        # '$' is a substitution character in Replace; the brief may contain one.
        $rx.Replace($existing, $block.Replace('$', '$$'))
    }
    elseif ($existing) {
        $existing.TrimEnd() + "`n`n" + $block
    }
    else {
        $block
    }

    if ($PSCmdlet.ShouldProcess($File, 'Update cred block')) {
        $ConfirmPreference = 'None'   # our gate is answered; don't leak -Confirm downstream
        Set-CredFileText -Path $File -Text $updated
    }
    return [pscustomobject]@{ Project = $ctx.Name; File = $File; Credentials = @(Get-CredList -Project $ctx.Name -Path $ctx.Root).Count }
}
