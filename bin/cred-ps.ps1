#requires -Version 5.1
<#
    cred -- command-line front end for the Cred module.

    This file is deliberately thin: it parses argv, calls exactly one module
    function, prints, and picks an exit code. All behaviour lives in the module
    so that the PowerShell API and the CLI can never drift apart.

    Everything after a bare `--` is passed through untouched.
#>

# No param() block on purpose. A script with declared parameters lets the
# PowerShell binder eat the bare `--` that separates `cred exec <project>` from
# the command to run; a script with none receives argv verbatim in $args on both
# 5.1 and 7. Capture it immediately, before any function shadows $args.
$script:Argv = @($args)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

# Secrets are text, and text on Windows consoles defaults to an OEM code page
# that cannot represent most of Unicode. Pin every stream to UTF-8 (no BOM) so a
# password with an umlaut or an emoji survives the round trip -- and so that
# piping `cred get` into another program yields the exact bytes that went in.
try {
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [Console]::OutputEncoding = $utf8
    [Console]::InputEncoding  = $utf8
    $OutputEncoding = $utf8
}
catch {
    # Redirected or headless hosts may refuse; the module still round-trips
    # correctly because it works in bytes internally.
    Write-Verbose "Could not pin console encoding: $($_.Exception.Message)"
}

$moduleManifest = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Cred\Cred.psd1'
if (-not (Test-Path -LiteralPath $moduleManifest)) {
    $moduleManifest = 'Cred'   # installed on PSModulePath
}
Import-Module $moduleManifest -Force -ErrorAction Stop

# ---------------------------------------------------------------- argv -------

# Split-CredArgv and Read-CredOptions used to live here. A parser inside a script has
# no interface but a process, so the fiddliest code in the repo had no direct
# test. They are Split-CredArgv and Read-CredOptions in the module now.

function Get-Opt {
    param([hashtable]$Options, [string]$Name, $Default = $null)
    if ($Options.ContainsKey($Name)) { return $Options[$Name] }
    return $Default
}

# --------------------------------------------------------------- output ------

function Write-Line { param([string]$Text = '') [Console]::Out.WriteLine($Text) }

# An aside for the human, on stderr so it cannot pollute a pipe.
function Write-CredNote { param([string]$Text) [Console]::Error.WriteLine($Text) }

function Write-CredSecret {
    <#
        Writes to the real stdout handle rather than the PowerShell pipeline,
        so the value is not captured by Start-Transcript or by the host's
        output history. Redirection and piping still work normally.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Value, [switch]$NoNewline)
    if ($null -eq $Value) { $Value = '' }
    if ($NoNewline) { [Console]::Out.Write($Value) } else { [Console]::Out.Write($Value + [Environment]::NewLine) }
    [Console]::Out.Flush()
}

function Write-CredCliError {
    param([System.Management.Automation.ErrorRecord]$Record)
    $text = if ($Record.ErrorDetails) { $Record.ErrorDetails.Message } else { $Record.Exception.Message }
    foreach ($line in ($text -split "`r?`n")) {
        [Console]::Error.WriteLine("cred: $line")
    }
}

function Write-Table {
    param([object[]]$Rows, [string[]]$Property)
    if (-not $Rows -or $Rows.Count -eq 0) { return }
    $out = $Rows | Format-Table -Property $Property -AutoSize | Out-String
    [Console]::Out.Write($out.TrimEnd() + [Environment]::NewLine)
}

function Confirm-CredCliAction {
    <#
        Asks the one question a destructive command needs, and returns $true to
        proceed.

        Why the CLI prompts instead of letting the module's -Confirm do it:
        passing -Confirm to a cmdlet sets $ConfirmPreference = 'Low' for the
        whole call stack underneath it, so every SupportsShouldProcess cmdlet
        the module touches on the way -- writing config.json, deleting its own
        backup and temp files, scrubbing a variable -- stops and asks too. One
        `cred rm` became five prompts. The module functions are therefore always
        called with -Confirm:$false and the decision is made here.

        $RequireTty makes a non-interactive run an error rather than a silent
        yes, matching python/cred.py.
    #>
    param(
        [Parameter(Mandatory)][string]$Question,
        [switch]$Yes,
        [switch]$RequireTty
    )

    if ($Yes) { return $true }

    if ([Console]::IsInputRedirected) {
        if ($RequireTty) {
            throw (UsageError 'Refusing to act without confirmation.' 'Pass --yes to run non-interactively.')
        }
        return $true
    }

    [Console]::Out.Write("$Question [y/N] ")
    [Console]::Out.Flush()
    $answer = [Console]::In.ReadLine()
    if ($null -eq $answer) { return $false }
    return ($answer.Trim().ToLowerInvariant() -in @('y', 'yes'))
}

$script:CredCliVersion = (Get-Module Cred).Version.ToString()

$script:Usage = @'
cred - per-repository encrypted credentials

USAGE
  cred <command> [args] [options]

GETTING STARTED
  cred init [name]                 Set up .creds/ in this repo (commit it)
  cred add <project>/<key>         Add a credential; prompts, no echo
  cred get <project>/<key>         Print one secret to stdout
  cred exec <project> -- <cmd>     Run <cmd> with the secrets as env vars

COMMANDS
  init [name]                      Create a store here
      --provider <name>            Encryption backend (default: age)
      --recipient <key>            Recipient(s) instead of your own key
      --force                      Overwrite an existing store

  add|set <project>/<key>          Add or replace a credential
      --user <name>                Make it a username/password pair
      --value <secret>             Non-interactive (leaks to shell history)
      --stdin                      Read the value from stdin
      --file <path>                Store a file's exact bytes (PEM, cert, key)
      --filename <name>            Record a different name than the source
      --env <NAME>                 Environment variable name to map it to
      --desc <text>                What it is for
      --allow-empty                Permit an empty value

  get <project>/<key>              Print a secret
      --field <secret|user>        Which half of a userpass pair
      -n, --no-newline             Omit the trailing newline
      --out <path>                 Write to a file instead of stdout
      --force                      Allow --out to overwrite

  list [project]                   Show credential names (never values)
      --verify                     Also decrypt and flag missing values
      --json                       Machine-readable

  exec <project> -- <cmd> [args]   Run with secrets injected as env vars
      --only <a,b>                 Inject only these credentials
      --except <a,b>               Inject everything but these
      --prefix <P>                 Prefix every variable name

  rm <project>/<key>               Delete a credential
      --yes                        Skip the confirmation

  env [project]                    Print export lines for the current shell
      --format <powershell|posix>

  recipients [project]             Who can decrypt this project
  recipients add <key>...          Grant access and re-encrypt
  recipients rm <key>...           Revoke access and re-encrypt

  keygen                           Create this machine's key
      --show                       Print the public key instead
      --protect                    Wrap it with the OS keystore (DPAPI)
      --force                      Replace the existing key (backs it up)

  key                              Show where your key is and how it is held
  key protect                      Wrap it with the OS keystore (DPAPI)
      --backup <file>              Save the unwrapped key first (do this)
  key unprotect                    Unwrap it, before moving machine or account
      --provider <name>            Which backend's key (default: age)

  import <path>                    Import PSCredential files into a store
      --name <key>                 Name for a single file
      --desc <text>                Description for what is imported
      --force                      Overwrite credentials that already exist
      --dry-run                    Show what would happen, change nothing

  export <folder>                  Write credentials out as PSCredential files
      --only <a,b>                 Just these
      --yes                        Skip the confirmation

  project list                     Registered projects on this machine
  project rm <name>                Forget a project mapping

  providers                        Encryption backends and their status
  doctor [project]                 Check the setup and say how to fix it
      --repair                     Re-apply restrictive permissions

  claude [project]                 Markdown brief for a Claude Code session
      --write                      Write it into the repo's CLAUDE.md

  version | help

ENVIRONMENT
  CRED_HOME            Config directory (default %APPDATA%\cred, ~/.config/cred)
  CRED_IDENTITY_FILE   Path to the age key (default <CRED_HOME>/identity.txt)
  CRED_PROJECT         Default project when none is named
  CRED_AGE_PATH        Explicit path to the age binary

EXIT CODES
  0 ok   2 usage   3 not found   4 key/decrypt   5 backend missing
  6 corrupt store   7 locked   8 child command failed
'@

# ------------------------------------------------------------- dispatch ------

function Invoke-CredCli {
    param([string[]]$Argv)

    if ($Argv.Count -eq 0 -or $Argv[0] -in @('-h', '--help', 'help')) {
        Write-Line $script:Usage
        return 0
    }

    $split  = Split-CredArgv -Argv $Argv
    $head   = @($split.Head)
    $tail   = @($split.Tail)
    $verb   = ([string]$head[0]).ToLowerInvariant()
    $rest   = @(if ($head.Count -gt 1) { $head[1..($head.Count - 1)] } else { @() })

    switch ($verb) {

        { $_ -in 'version', '--version', '-v' } {
            Write-Line "cred $script:CredCliVersion  ($($PSVersionTable.PSEdition) PowerShell $($PSVersionTable.PSVersion))"
            return 0
        }

        'init' {
            $p = Read-CredOptions -Argv $rest -Switches @('force') -Short @{}
            $o = $p.Options
            $call = @{}
            if ($p.Positional.Count -gt 0) { $call.Project = $p.Positional[0] }
            if (Get-Opt $o 'project')      { $call.Project = Get-Opt $o 'project' }
            if (Get-Opt $o 'provider')     { $call.Provider = Get-Opt $o 'provider' }
            if (Get-Opt $o 'recipient')    { $call.Recipient = (Get-Opt $o 'recipient') -split ',' }
            if (Get-Opt $o 'path')         { $call.Path = Get-Opt $o 'path' }
            if (Get-Opt $o 'force')        { $call.Force = $true }

            $r = Initialize-CredProject @call
            Write-Line "Created $($r.Project) in $($r.Root)"
            Write-Line "  store      $($r.Store)"
            Write-Line "  provider   $($r.Provider)"
            Write-Line "  recipient  $($r.Recipients -join ', ')"
            Write-Line ''
            Write-Line "Commit .creds/ -- it is encrypted. Then: cred add $($r.Project)/<key>"
            return 0
        }

        { $_ -in 'add', 'set' } {
            $p = Read-CredOptions -Argv $rest -Switches @('stdin', 'allow-empty', 'force') -Short @{}
            $o = $p.Options
            if ($p.Positional.Count -lt 1) { throw (UsageError 'cred add <project>/<key> [--user <name>]') }

            $call = @{ Name = $p.Positional[0] }
            if ($p.Positional.Count -gt 1)  { $call.Secret = $p.Positional[1] }
            if (Get-Opt $o 'value')         { $call.Secret = Get-Opt $o 'value' }
            if (Get-Opt $o 'file')          { $call.File = Get-Opt $o 'file' }
            if (Get-Opt $o 'filename')      { $call.FileName = Get-Opt $o 'filename' }
            if (Get-Opt $o 'force')         { $call.Force = $true }
            if (Get-Opt $o 'user')          { $call.User = Get-Opt $o 'user' }
            if (Get-Opt $o 'desc')          { $call.Description = Get-Opt $o 'desc' }
            if (Get-Opt $o 'description')   { $call.Description = Get-Opt $o 'description' }
            if (Get-Opt $o 'env')           { $call.Env = @{ secret = Get-Opt $o 'env' } }
            if (Get-Opt $o 'env-user')      { $call.Env = (Merge-Env $call 'user' (Get-Opt $o 'env-user')) }
            if (Get-Opt $o 'path')          { $call.Path = Get-Opt $o 'path' }
            if (Get-Opt $o 'project')       { $call.Project = Get-Opt $o 'project' }
            if (Get-Opt $o 'stdin')         { $call.FromStdin = $true }
            if (Get-Opt $o 'allow-empty')   { $call.AllowEmpty = $true }

            $r = Set-Cred @call
            $what = if ($r.Created) { 'Added' } else { 'Updated' }
            Write-Line "$what $($r.Project)/$($r.Key) ($($r.Type))"
            if ($r.Type -eq 'file') {
                $how = if ($r.Encoding) { 'base64' } else { 'text' }
                Write-Line "  $($r.FileName), $($r.ByteCount) bytes, stored as $how"
                Write-Line "  Not injected by 'cred exec'. Read it back with: cred get $($r.Project)/$($r.Key) --out <path>"
            }
            return 0
        }

        'get' {
            $p = Read-CredOptions -Argv $rest -Switches @('no-newline', 'force') -Short @{ 'n' = 'no-newline' }
            $o = $p.Options
            if ($p.Positional.Count -lt 1) { throw (UsageError 'cred get <project>/<key>') }

            $call = @{ Name = $p.Positional[0] }
            if (Get-Opt $o 'path')    { $call.Path = Get-Opt $o 'path' }
            if (Get-Opt $o 'project') { $call.Project = Get-Opt $o 'project' }

            if (Get-Opt $o 'out') {
                $call.OutFile = Get-Opt $o 'out'
                if (Get-Opt $o 'field') { $call.Field = Get-Opt $o 'field' }
                if (Get-Opt $o 'force') { $call.Force = $true }
                $w = Export-CredFile @call
                Write-Line "Wrote $($w.File) ($($w.ByteCount) bytes), readable only by you."
                Write-Line 'This is plaintext on disk. Delete it when you are done.'
                return 0
            }

            if (Get-Opt $o 'field') { $call.Field = Get-Opt $o 'field' }

            # One call, one decryption: the bytes and what they are.
            $v = Read-CredValue @call

            if ($v.Kind -eq 'file') {
                # Exact bytes, and no trailing newline of ours: piping this to a
                # file must produce the file that went in, byte for byte.
                #
                # The guard keys off the stored 'encoding' marker, exactly as
                # python/cred.py does. Sniffing for a NUL byte instead meant a
                # base64-stored file with no NUL was blocked by one
                # implementation and printed by the other.
                if ($v.IsBinary -and -not [Console]::IsOutputRedirected) {
                    throw (UsageError "'$($p.Positional[0])' holds binary content. Writing it to a terminal would corrupt it. Write it to a file: cred get $($p.Positional[0]) --out <path>")
                }
                $stdout = [Console]::OpenStandardOutput()
                $stdout.Write($v.Bytes, 0, $v.Bytes.Length)
                $stdout.Flush()
                return 0
            }

            $value = [System.Text.UTF8Encoding]::new($false).GetString($v.Bytes)
            Write-CredSecret -Value $value -NoNewline:([bool](Get-Opt $o 'no-newline'))
            return 0
        }

        'list' {
            $p = Read-CredOptions -Argv $rest -Switches @('verify', 'json') -Short @{}
            $o = $p.Options
            $call = @{}
            if ($p.Positional.Count -gt 0) { $call.Project = $p.Positional[0] }
            if (Get-Opt $o 'path')         { $call.Path = Get-Opt $o 'path' }
            if (Get-Opt $o 'verify')       { $call.Verify = $true }

            $rows = @(Get-CredList @call)
            if (Get-Opt $o 'json') {
                Write-Line (($rows | ConvertTo-Json -Depth 6))
            }
            elseif ($rows.Count -eq 0) {
                $name = if ($call.ContainsKey('Project')) { $call.Project } else { '<project>' }
                Write-Line "No credentials defined. Add one with: cred add $name/<key>"
            }
            else {
                $cols = if (Get-Opt $o 'verify') {
                    @('Key', 'Type', 'HasValue', 'Environment', 'Description')
                } else {
                    @('Key', 'Type', 'Environment', 'Description')
                }
                Write-Table -Rows $rows -Property $cols
            }
            return 0
        }

        'exec' {
            $p = Read-CredOptions -Argv $rest -Switches @() -Short @{}
            $o = $p.Options
            if ($tail.Count -eq 0) {
                throw (UsageError 'cred exec <project> -- <command> [args]')
            }
            $call = @{ Command = $tail[0] }
            if ($tail.Count -gt 1) { $call.ArgumentList = $tail[1..($tail.Count - 1)] }
            if ($p.Positional.Count -gt 0) { $call.Project = $p.Positional[0] }
            if (Get-Opt $o 'path')   { $call.Path = Get-Opt $o 'path' }
            if (Get-Opt $o 'only')   { $call.Only = (Get-Opt $o 'only') -split ',' }
            if (Get-Opt $o 'except') { $call.Exclude = (Get-Opt $o 'except') -split ',' }
            if (Get-Opt $o 'prefix') { $call.Prefix = Get-Opt $o 'prefix' }

            return (Invoke-CredCommand @call -PassThru)
        }

        { $_ -in 'rm', 'remove', 'delete' } {
            $p = Read-CredOptions -Argv $rest -Switches @('yes', 'keep-definition') -Short @{ 'y' = 'yes' }
            $o = $p.Options
            if ($p.Positional.Count -lt 1) { throw (UsageError 'cred rm <project>/<key>') }

            $call = @{ Name = $p.Positional[0]; Confirm = $false }
            if (Get-Opt $o 'path')            { $call.Path = Get-Opt $o 'path' }
            if (Get-Opt $o 'keep-definition') { $call.KeepDefinition = $true }

            $ok = Confirm-CredCliAction -Question "Remove $($p.Positional[0])?" `
                                        -Yes:([bool](Get-Opt $o 'yes')) -RequireTty
            if (-not $ok) { Write-Line 'Cancelled.'; return 0 }

            $r = Remove-Cred @call
            if ($r) { Write-Line "Removed $($r.Project)/$($r.Key)" }
            return 0
        }

        'env' {
            $p = Read-CredOptions -Argv $rest -Switches @() -Short @{}
            $o = $p.Options
            $call = @{}
            if ($p.Positional.Count -gt 0) { $call.Project = $p.Positional[0] }
            if (Get-Opt $o 'path')   { $call.Path = Get-Opt $o 'path' }
            if (Get-Opt $o 'only')   { $call.Only = (Get-Opt $o 'only') -split ',' }
            if (Get-Opt $o 'except') { $call.Exclude = (Get-Opt $o 'except') -split ',' }
            if (Get-Opt $o 'prefix') { $call.Prefix = Get-Opt $o 'prefix' }

            # One call for both answers, off one decryption.
            $projected = Get-CredEnvironmentReport @call
            $table   = $projected.Variables
            $skipped = $projected.Skipped
            if ($skipped.Count -gt 0) {
                $ref = if ($call.Contains('Project')) { "$($call.Project)/$($skipped[0])" } else { $skipped[0] }
                Write-CredNote "Not shown (file credentials): $($skipped -join ', '). Read one with: cred get $ref --out <path>"
            }
            $format = [string](Get-Opt $o 'format' 'powershell')
            foreach ($k in ($table.Keys | Sort-Object)) {
                $line = if ($format -eq 'posix') {
                    "export $k='" + ($table[$k] -replace "'", "'\''") + "'"
                } else {
                    "`$env:$k = '" + ($table[$k] -replace "'", "''") + "'"
                }
                Write-CredSecret -Value $line
            }
            return 0
        }

        'recipients' {
            $sub = if ($rest.Count -gt 0) { ([string]$rest[0]).ToLowerInvariant() } else { '' }
            if ($sub -in 'add', 'rm', 'remove') {
                $subArgv = @(if ($rest.Count -gt 1) { $rest[1..($rest.Count - 1)] } else { @() })
                $p = Read-CredOptions -Argv $subArgv -Switches @('yes') -Short @{ 'y' = 'yes' }
                $keys = @($p.Positional)
                if ($keys.Count -eq 0) { throw (UsageError "cred recipients $sub <public-key> [--project <name>]") }
                $call = @{ Recipient = $keys }
                if (Get-Opt $p.Options 'project') { $call.Project = Get-Opt $p.Options 'project' }
                if (Get-Opt $p.Options 'path')    { $call.Path = Get-Opt $p.Options 'path' }

                if ($sub -eq 'add') {
                    $r = Add-CredRecipient @call
                    Write-Line "Added $($r.Added.Count) recipient(s) to $($r.Project); store re-encrypted for $($r.Recipients.Count)."
                }
                else {
                    $call.Confirm = $false
                    $ok = Confirm-CredCliAction -Question "Revoke $($keys.Count) recipient(s) and re-encrypt the store?" `
                                                -Yes:([bool](Get-Opt $p.Options 'yes')) -RequireTty
                    if (-not $ok) { Write-Line 'Cancelled.'; return 0 }

                    $r = Remove-CredRecipient @call
                    if ($r) { Write-Line "Removed $($r.Removed.Count) recipient(s) from $($r.Project)." }
                }
                return 0
            }

            $p = Read-CredOptions -Argv $rest -Switches @() -Short @{}
            $call = @{}
            if ($p.Positional.Count -gt 0) { $call.Project = $p.Positional[0] }
            if (Get-Opt $p.Options 'path') { $call.Path = Get-Opt $p.Options 'path' }
            Write-Table -Rows @(Get-CredRecipient @call) -Property @('Recipient', 'IsMe')
            return 0
        }

        { $_ -in 'keygen', 'newkey' } {
            $p = Read-CredOptions -Argv $rest -Switches @('show', 'force', 'protect') -Short @{}
            $o = $p.Options
            $call = @{}
            if (Get-Opt $o 'show')  { $call.Show = $true }
            if (Get-Opt $o 'force') { $call.Force = $true }
            if (Get-Opt $o 'path')  { $call.Path = Get-Opt $o 'path' }

            $r = New-CredIdentity @call
            if ((Get-Opt $o 'protect') -and -not (Get-Opt $o 'show')) {
                $p2 = Protect-CredIdentity -Confirm:$false -Force
                $r = New-CredIdentity -Show
                Write-Line "Key wrapped with $($p2.Protection) at $($p2.Path)"
            }
            if (Get-Opt $o 'show') {
                Write-Line $r.Recipient
            }
            else {
                Write-Line $(if ($r.Created) { "Created a new key at $($r.Path)" } else { "Key already exists at $($r.Path)" })
                Write-Line "Public key: $($r.Recipient)"
                Write-Line ''
                Write-Line 'Back this file up. Without it you cannot read any store encrypted to it.'
            }
            return 0
        }

        'project' {
            $sub = if ($rest.Count -gt 0) { ([string]$rest[0]).ToLowerInvariant() } else { 'list' }
            if ($sub -in 'rm', 'remove') {
                if ($rest.Count -lt 2) { throw (UsageError 'cred project rm <name>') }
                Unregister-CredProject -Name $rest[1] -Confirm:$false
                Write-Line "Forgot $($rest[1]). Its .creds directory was left alone."
                return 0
            }
            $rows = @(Get-CredProject)
            if ($rows.Count -eq 0) {
                Write-Line 'No projects registered. Run: cd <repo>; cred init'
            }
            else {
                Write-Table -Rows $rows -Property @('Name', 'Available', 'Path')
            }
            return 0
        }

        { $_ -in 'providers', 'provider' } {
            Write-Table -Rows @(Get-CredProvider) -Property @('Name', 'Available', 'StoreFile', 'Detail')
            return 0
        }

        { $_ -in 'doctor', 'check' } {
            $p = Read-CredOptions -Argv $rest -Switches @('repair') -Short @{}
            $call = @{}
            if ($p.Positional.Count -gt 0) { $call.Project = $p.Positional[0] }
            if (Get-Opt $p.Options 'path') { $call.Path = Get-Opt $p.Options 'path' }

            $rows = if (Get-Opt $p.Options 'repair') { @(Repair-CredHealth -Confirm:$false) } else { @(Test-CredHealth @call) }
            Write-Table -Rows $rows -Property @('Check', 'Status', 'Detail', 'Fix')

            if ($rows | Where-Object { $_.Status -eq 'Fail' }) { return 1 }
            return 0
        }

        { $_ -in 'claude', 'agent', 'brief' } {
            $p = Read-CredOptions -Argv $rest -Switches @('write') -Short @{}
            $call = @{}
            if ($p.Positional.Count -gt 0) { $call.Project = $p.Positional[0] }
            if (Get-Opt $p.Options 'path') { $call.Path = Get-Opt $p.Options 'path' }

            if (Get-Opt $p.Options 'write') {
                $r = Update-CredAgentBrief @call
                Write-Line "Wrote the cred block for $($r.Project) into $($r.File) ($($r.Credentials) credential(s))."
            }
            else {
                Write-Line (Get-CredAgentBrief @call)
            }
            return 0
        }

        'key' {
            $sub = if ($rest.Count -gt 0) { ([string]$rest[0]).ToLowerInvariant() } else { '' }
            $subArgv = @(if ($rest.Count -gt 1) { $rest[1..($rest.Count - 1)] } else { @() })
            $p = Read-CredOptions -Argv $subArgv -Switches @('force') -Short @{}

            switch ($sub) {
                'protect' {
                    $call = @{ Confirm = $false }
                    if (Get-Opt $p.Options 'backup') { $call.Backup = Get-Opt $p.Options 'backup' }
                    if (Get-Opt $p.Options 'force')  { $call.Force = $true }
                    $r = Protect-CredIdentity @call
                    if ($r.Changed) { Write-Line "Key wrapped with $($r.Protection) at $($r.Path)" }
                    else            { Write-Line "Key was already wrapped ($($r.Protection))." }
                    return 0
                }
                { $_ -in 'unprotect', 'unwrap' } {
                    $r = Unprotect-CredIdentity -Confirm:$false
                    if ($r.Changed) { Write-Line "Key unwrapped to $($r.Path)" }
                    else            { Write-Line 'Key was not wrapped.' }
                    return 0
                }
                default {
                    $i = Get-CredIdentityInfo
                    Write-Line "path        $($i.Path)"
                    Write-Line "exists      $($i.Exists)"
                    Write-Line "protection  $($i.Protection)"
                    Write-Line "private     $($i.Private)"
                    Write-Line "keystore    $(if ($i.KeystoreAvailable) { 'available' } else { 'not available on this platform' })"
                    if ($i.Recipient) { Write-Line "public key  $($i.Recipient)" }
                    return 0
                }
            }
        }

        'import' {
            $p = Read-CredOptions -Argv $rest -Switches @('force', 'dry-run') -Short @{}
            $o = $p.Options
            if ($p.Positional.Count -lt 1) { throw (UsageError 'cred import <file-or-folder> [--name <key>]') }

            $call = @{ Path = $p.Positional[0] }
            if (Get-Opt $o 'name')    { $call.Name = Get-Opt $o 'name' }
            if (Get-Opt $o 'desc')    { $call.Description = Get-Opt $o 'desc' }
            if (Get-Opt $o 'project') { $call.Project = Get-Opt $o 'project' }
            if (Get-Opt $o 'path')    { $call.ProjectPath = Get-Opt $o 'path' }
            if (Get-Opt $o 'force')   { $call.Force = $true }
            if (Get-Opt $o 'dry-run') { $call.WhatIf = $true }

            $rows = @(Import-Cred @call)
            if ($rows.Count -eq 0) { Write-Line 'Nothing to import.' }
            else { Write-Table -Rows $rows -Property @('Key', 'Action', 'Source') }
            return 0
        }

        'export' {
            $p = Read-CredOptions -Argv $rest -Switches @('yes', 'force') -Short @{ 'y' = 'yes' }
            $o = $p.Options
            if ($p.Positional.Count -lt 1) { throw (UsageError 'cred export <folder> [--only <a,b>]') }

            $call = @{ Path = $p.Positional[0]; Confirm = $false }
            if (Get-Opt $o 'project') { $call.Project = Get-Opt $o 'project' }
            if (Get-Opt $o 'only')    { $call.Only = (Get-Opt $o 'only') -split ',' }
            if (Get-Opt $o 'force')   { $call.Force = $true }

            # Export is not destructive to the store, so a redirected stdin is
            # a yes here -- python/cred.py makes the same call.
            $ok = Confirm-CredCliAction -Question "Write credential files into '$($p.Positional[0])'?" `
                                        -Yes:([bool](Get-Opt $o 'yes'))
            if (-not $ok) { Write-Line 'Cancelled.'; return 0 }

            $rows = @(Export-Cred @call)
            Write-Table -Rows $rows -Property @('Key', 'UserName', 'File')
            return 0
        }

        default {
            throw (UsageError "Unknown command '$verb'." "Run 'cred help' to see what there is.")
        }
    }
}

function UsageError {
    param([string]$Message, [string]$Extra)
    $text = "$Message"
    if ($Extra) { $text += [Environment]::NewLine + $Extra }
    $ex = [System.InvalidOperationException]::new($text)
    $r  = [System.Management.Automation.ErrorRecord]::new(
              $ex, 'Cred.Usage', [System.Management.Automation.ErrorCategory]::InvalidArgument, $null)
    $r.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($text)
    return $r
}

function Merge-Env {
    param([hashtable]$Call, [string]$Field, [string]$Value)
    $e = if ($Call.ContainsKey('Env')) { $Call.Env } else { @{} }
    $e[$Field] = $Value
    return $e
}

# --------------------------------------------------------------- main --------

try {
    exit (Invoke-CredCli -Argv $script:Argv)
}
catch {
    $record = if ($_ -is [System.Management.Automation.ErrorRecord]) { $_ } else { $_.ErrorRecord }
    Write-CredCliError -Record $record
    # The module owns the code -> exit code table. This used to be a second
    # copy here, which is the kind of duplication that drifts silently.
    exit (Get-CredExitCode -ErrorRecord $record)
}
