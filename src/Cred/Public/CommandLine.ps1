#requires -Version 5.1
<#
    CommandLine.ps1 -- turning argv into something a command can use.

    This lived in bin/cred-ps.ps1, which meant the fiddliest code in the
    repository had no direct test: a script's only interface is a process, so
    exercising the parser meant spawning pwsh, loading the module, finding a
    real store and a real key, and then asserting on stdout. Nothing did.

    Here it is callable, so a parsing question can be asked and answered
    without any of that. bin/cred-ps.ps1 keeps its job -- parse, call one
    module function, print, pick an exit code -- and ARCHITECTURE.md rule 1
    still holds: the CLI contains no behaviour.
#>

function Split-CredArgv {
    <#
        .SYNOPSIS
        Split an argument list at the first bare '--'.

        .DESCRIPTION
        Everything after the separator is a command to run verbatim and must
        not be parsed. Returns Head (before it) and Tail (after it); Tail is
        empty when there is no separator.

        .EXAMPLE
        $s = Split-CredArgv @('exec', 'acme-api', '--', 'npm', 'run', 'deploy')
        $s.Head   # exec, acme-api
        $s.Tail   # npm, run, deploy
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Position = 0)][AllowEmptyCollection()][string[]]$Argv = @())

    $idx = [Array]::IndexOf([string[]]$Argv, '--')
    if ($idx -lt 0) {
        return [pscustomobject]@{ Head = @($Argv); Tail = @() }
    }
    $head = [System.Collections.Generic.List[string]]::new()
    $tail = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Argv.Count; $i++) {
        if ($i -lt $idx)     { $head.Add([string]$Argv[$i]) }
        elseif ($i -gt $idx) { $tail.Add([string]$Argv[$i]) }
    }
    return [pscustomobject]@{ Head = $head.ToArray(); Tail = $tail.ToArray() }
}

function Read-CredOptions {
    <#
        .SYNOPSIS
        Parse '--flag', '--opt value', '--opt=value' and '-x' out of an
        argument list, leaving the positional arguments behind.

        .DESCRIPTION
        -Switches names the options that take no value; anything named there
        becomes $true rather than swallowing the next argument. An option that
        wants a value but is followed by another '--something', or by nothing
        at all, also becomes $true, so a missing value is visible to the caller
        rather than silently eating the next flag.

        Returns Options (a hashtable, keys lower-cased) and Positional.

        .EXAMPLE
        $p = Read-CredOptions @('acme-api/db', '--user', 'svc', '--stdin') -Switches @('stdin')
        $p.Options['user']   # svc
        $p.Options['stdin']  # True
        $p.Positional[0]     # acme-api/db

        .EXAMPLE
        $p = Read-CredOptions @('-n', 'acme-api/db') -Switches @('no-newline') -Short @{ n = 'no-newline' }
        $p.Options['no-newline']
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][AllowEmptyCollection()][string[]]$Argv = @(),
        [string[]]$Switches = @(),
        [hashtable]$Short = @{}
    )

    $opts = @{}
    $positional = [System.Collections.Generic.List[string]]::new()
    $i = 0
    while ($i -lt $Argv.Count) {
        $a = [string]$Argv[$i]

        if ($a -match '^--([A-Za-z][A-Za-z0-9-]*)(=(.*))?$') {
            $name   = $Matches[1].ToLowerInvariant()
            $inline = if ($Matches[2]) { $Matches[3] } else { $null }

            if ($name -in $Switches) {
                $opts[$name] = $true
            }
            elseif ($null -ne $inline) {
                $opts[$name] = $inline
            }
            elseif ($i + 1 -lt $Argv.Count -and [string]$Argv[$i + 1] -notlike '--*') {
                $opts[$name] = [string]$Argv[$i + 1]; $i++
            }
            else {
                $opts[$name] = $true
            }
        }
        elseif ($a -match '^-([A-Za-z])$' -and $Short.ContainsKey($Matches[1])) {
            $name = $Short[$Matches[1]]
            if ($name -in $Switches) { $opts[$name] = $true }
            elseif ($i + 1 -lt $Argv.Count) { $opts[$name] = [string]$Argv[$i + 1]; $i++ }
            else { $opts[$name] = $true }
        }
        else {
            $positional.Add($a)
        }
        $i++
    }
    return [pscustomobject]@{ Options = $opts; Positional = @($positional) }
}
