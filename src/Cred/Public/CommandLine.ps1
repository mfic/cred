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

        .EXAMPLE
        # -Known makes an unrecognised flag an error instead of a silent
        # no-op -- without it, a typo'd --partial on `cred get` would fall
        # through to printing the whole secret rather than refusing.
        Read-CredOptions @('x', '--bogus') -Known @('field')   # throws
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][AllowEmptyCollection()][string[]]$Argv = @(),
        [string[]]$Switches = @(),
        [hashtable]$Short = @{},
        [string[]]$Known
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
    if ($PSBoundParameters.ContainsKey('Known')) {
        $unknown = @($opts.Keys | Where-Object { $_ -notin $Known } | Sort-Object)
        if ($unknown.Count -gt 0) {
            throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $unknown[0] `
                -Message "Unknown option '--$($unknown[0])'." `
                -Next "Run 'cred help' to see what there is.")
        }
    }
    return [pscustomobject]@{ Options = $opts; Positional = @($positional) }
}

# What each verb accepts, in one table rather than transcribed at every call
# site in bin/cred-ps.ps1. `Known` is the point of it: Read-CredOptions refuses
# anything not listed, and it used to be passed at one of seventeen call sites,
# so a mistyped flag was silently ignored on the other sixteen -- for
# `cred list --verfiy` that meant quietly not verifying.
#
# It lives in the module for the reason at the top of this file: inside a
# script the table's only interface is a process. Peer of COMMANDS in
# python/cred.py, and the two must accept the same surface.
#
# Value  = options that take a value.  Switch = options that do not.
# Map    = option name -> the module parameter it becomes. Split marks the
#          comma-separated ones. Anything irregular stays in the CLI.

$script:CredProjectOptions = @('project', 'path')

$script:CredCommandSpecs = @{
    init       = @{ Switch = @('force', 'yes'); Short = @{ 'y' = 'yes' }
                    Value  = @('provider', 'recipient') }
    add        = @{ Switch = @('stdin', 'allow-empty', 'force')
                    Value  = @('user', 'value', 'file', 'filename', 'env',
                               'env-user', 'desc', 'description') }
    get        = @{ Switch = @('no-newline', 'force', 'check', 'stat')
                    Short  = @{ 'n' = 'no-newline' }
                    Value  = @('field', 'out', 'reveal') }
    list       = @{ Switch = @('json', 'verify') }
    exec       = @{ Value  = @('only', 'except', 'prefix') }
    rm         = @{ Switch = @('yes', 'keep-definition'); Short = @{ 'y' = 'yes' } }
    env        = @{ Value  = @('only', 'except', 'prefix', 'format') }
    recipients = @{ Switch = @('yes'); Short = @{ 'y' = 'yes' } }
    keygen     = @{ Switch = @('show', 'force', 'protect')
                    Value  = @('provider', 'path'); NoProject = $true }
    key        = @{ Switch = @('force')
                    Value  = @('backup', 'provider', 'path'); NoProject = $true }
    project    = @{ NoProject = $true }
    providers  = @{ NoProject = $true }
    doctor     = @{ Switch = @('repair') }
    claude     = @{ Switch = @('write'); Value = @('file') }
    import     = @{ Switch = @('force', 'dry-run'); Value = @('name', 'desc') }
    export     = @{ Switch = @('yes', 'force'); Short = @{ 'y' = 'yes' }
                    Value  = @('only') }
}

# The spellings that mean the same verb, so `cred set --bogus` is refused by
# the same table that refuses `cred add --bogus`.
$script:CredCommandAliases = @{
    'set' = 'add'; 'remove' = 'rm'; 'delete' = 'rm'; 'check' = 'doctor'
    'agent' = 'claude'; 'brief' = 'claude'; 'provider' = 'providers'
    'newkey' = 'keygen'
}

function Get-CredCommandSpec {
    <#
        .SYNOPSIS
        The switches, short forms and full option set one verb accepts.

        .DESCRIPTION
        Returns Switch, Short and Known. Known is every option the verb takes,
        switches and value options together, which is what Read-CredOptions
        needs to refuse a typo instead of ignoring it.

        Aliases resolve to their canonical verb. An unknown verb returns an
        empty spec rather than throwing: the dispatcher already has a better
        error for that, and this must not become a second place that decides
        what a command is.

        Peer of command_spec in python/cred.py.

        .EXAMPLE
        (Get-CredCommandSpec -Verb list).Known
        # json, verify, project, path
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory, Position = 0)][string]$Verb)

    $name = $Verb.ToLowerInvariant()
    if ($script:CredCommandAliases.ContainsKey($name)) {
        $name = $script:CredCommandAliases[$name]
    }
    $spec = if ($script:CredCommandSpecs.ContainsKey($name)) {
        $script:CredCommandSpecs[$name]
    } else { @{} }

    $switch = @(if ($spec.ContainsKey('Switch')) { $spec.Switch } else { @() })
    $value  = @(if ($spec.ContainsKey('Value'))  { $spec.Value }  else { @() })
    # Every verb that has a project takes --project and --path.
    if (-not $spec.ContainsKey('NoProject')) { $value += $script:CredProjectOptions }

    return [pscustomobject]@{
        Verb   = $name
        Switch = $switch
        Short  = @(if ($spec.ContainsKey('Short')) { $spec.Short } else { @{} })[0]
        Known  = @($switch + $value)
    }
}

function Read-CredCommandOptions {
    <#
        .SYNOPSIS
        Parse one verb's argv against its spec, refusing unknown options.

        .DESCRIPTION
        The one call every arm of the CLI dispatch makes. Wrapping
        Read-CredOptions rather than replacing it keeps the parser itself
        testable on its own, and keeps the spec out of the parser.

        Peer of parse_command in python/cred.py.

        .EXAMPLE
        $p = Read-CredCommandOptions -Verb list -Argv @('acme', '--verify')
        $p.Options.verify   # True
        $p.Positional[0]    # acme
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Verb,
        [Parameter(Position = 1)][AllowEmptyCollection()][string[]]$Argv = @()
    )

    $spec = Get-CredCommandSpec -Verb $Verb
    return (Read-CredOptions -Argv $Argv -Switches $spec.Switch `
                             -Short $spec.Short -Known $spec.Known)
}

# Option name -> the module parameter it becomes. One table, because the
# mapping is a naming rule and not per-verb glue: `--except` is -Exclude
# wherever it appears, and it was written out at every arm that took it.
#
# An option absent from here is one the CLI itself consumes -- how to print
# (--json, --format), which function to call (--repair, --write, --protect),
# how to read a value (--reveal, --check, --stat, --out, -n), or a question
# only the CLI may ask (--yes). Those stay in bin/cred-ps.ps1 on purpose:
# ARCHITECTURE.md keeps confirmation and output shape there.
$script:CredOptionParameters = @{
    'path'            = 'Path'
    'project'         = 'Project'
    'provider'        = 'Provider'
    'force'           = 'Force'
    'value'           = 'Secret'
    'file'            = 'File'
    'filename'        = 'FileName'
    'user'            = 'User'
    'desc'            = 'Description'
    'description'     = 'Description'
    'stdin'           = 'FromStdin'
    'allow-empty'     = 'AllowEmpty'
    'verify'          = 'Verify'
    'only'            = 'Only'
    'except'          = 'Exclude'
    'prefix'          = 'Prefix'
    'recipient'       = 'Recipient'
    'keep-definition' = 'KeepDefinition'
    'field'           = 'Field'
    'show'            = 'Show'
    'backup'          = 'Backup'
    'name'            = 'Name'
    'dry-run'         = 'WhatIf'
}

# Options whose value is a comma-separated list.
$script:CredSplitOptions = @('only', 'except', 'recipient')

function ConvertTo-CredCallArguments {
    <#
        .SYNOPSIS
        Turn parsed options into the hashtable a module function is splatted
        with.

        .DESCRIPTION
        Applies the one option-to-parameter table to whichever options this
        verb accepts. A switch becomes $true; a comma-separated option becomes
        an array; everything else is passed through.

        -Positional names the parameters the bare arguments become, in order,
        so `cred add acme/db hunter2` fills Name then Secret.

        -Exclude drops options this arm handles itself, and -Extra adds
        parameters the table cannot know about. Between them, an arm keeps only
        what is genuinely irregular instead of transcribing the whole map.

        This was 86 lines across the dispatch switch in bin/cred-ps.ps1, where
        nothing could assert against it. Peer of the same table in
        python/cred.py, which builds keyword arguments directly.

        .EXAMPLE
        $spec = Get-CredCommandSpec list
        $p    = Read-CredCommandOptions -Verb list -Argv @('acme', '--verify')
        ConvertTo-CredCallArguments -Spec $spec -Parsed $p -Positional 'Project'
        # @{ Project = 'acme'; Verify = $true }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][object]$Spec,
        [Parameter(Mandatory)][object]$Parsed,
        [string[]]$Positional = @(),
        [string[]]$Exclude = @(),
        [hashtable]$Extra = @{}
    )

    $call = @{}

    for ($i = 0; $i -lt $Positional.Count; $i++) {
        if ($Parsed.Positional.Count -gt $i) { $call[$Positional[$i]] = $Parsed.Positional[$i] }
    }

    foreach ($opt in $Spec.Known) {
        if ($opt -in $Exclude) { continue }
        if (-not $script:CredOptionParameters.ContainsKey($opt)) { continue }
        if (-not $Parsed.Options.ContainsKey($opt)) { continue }

        $value = $Parsed.Options[$opt]
        $param = $script:CredOptionParameters[$opt]

        if ($opt -in $Spec.Switch) { $call[$param] = $true }
        elseif ($opt -in $script:CredSplitOptions) { $call[$param] = ([string]$value) -split ',' }
        else { $call[$param] = $value }
    }

    foreach ($k in $Extra.Keys) { $call[$k] = $Extra[$k] }
    return $call
}
