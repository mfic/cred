#requires -Version 5.1
<#
    CLI tests -- the `cred` front end as an actual process: argv parsing, exit
    codes, which stream things land on, and whether a secret can escape into a
    transcript.
#>

BeforeDiscovery {
    $script:HasAge = [bool](Get-Command age -ErrorAction SilentlyContinue) -or
                     (Test-Path "$env:LOCALAPPDATA\Microsoft\WinGet\Links\age.exe")
}

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:Cli      = Join-Path $script:RepoRoot 'bin\cred-ps.ps1'
    $script:Pwsh     = (Get-Process -Id $PID).Path

    $script:Sandbox = Join-Path ([System.IO.Path]::GetTempPath()) "credcli-$([guid]::NewGuid().ToString('N'))"
    $null = New-Item -ItemType Directory -Path $script:Sandbox -Force
    $script:CredHomeDir = Join-Path $script:Sandbox 'home'

    function Invoke-Cred {
        <#
            Run the CLI as a separate process and capture both streams and the
            exit code -- exactly what a user or a script would see.
        #>
        param([string[]]$CliArgs, [string]$WorkingDirectory, [string]$StdIn)

        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName  = $script:Pwsh
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.RedirectStandardInput  = $true
        $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $psi.StandardErrorEncoding  = [System.Text.UTF8Encoding]::new($false)
        if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
        $psi.EnvironmentVariables['CRED_HOME'] = $script:CredHomeDir
        $psi.EnvironmentVariables.Remove('CRED_PROJECT')       | Out-Null
        $psi.EnvironmentVariables.Remove('CRED_IDENTITY_FILE') | Out-Null

        $quoted = @("-NoProfile", "-NonInteractive", "-File", $script:Cli) + $CliArgs |
                  ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }
        $psi.Arguments = $quoted -join ' '

        $p = [System.Diagnostics.Process]::Start($psi)
        if ($StdIn) {
            # Write UTF-8 bytes straight to the pipe. StandardInput's own writer
            # uses the console code page, which mangles non-ASCII on 5.1 -- the
            # same trap real callers hit, and the reason cred decodes stdin as
            # UTF-8 bytes rather than trusting the console encoding.
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($StdIn)
            $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
            $p.StandardInput.BaseStream.Flush()
        }
        $p.StandardInput.Close()
        $out = $p.StandardOutput.ReadToEnd()
        $err = $p.StandardError.ReadToEnd()
        $p.WaitForExit()
        $code = $p.ExitCode
        $p.Dispose()

        [pscustomobject]@{ StdOut = $out; StdErr = $err; ExitCode = $code }
    }

    # BeforeDiscovery and BeforeAll do not share variables, so this is computed
    # in both places rather than carried across.
    $script:HasAge = [bool](Get-Command age -ErrorAction SilentlyContinue) -or
                     (Test-Path "$env:LOCALAPPDATA\Microsoft\WinGet\Links\age.exe")

    if ($script:HasAge) {
        $null = Invoke-Cred -CliArgs @('keygen')
        $script:Proj = Join-Path $script:Sandbox 'cliproj'
        $null = New-Item -ItemType Directory -Path $script:Proj -Force
        $null = Invoke-Cred -CliArgs @('init', 'cliproj') -WorkingDirectory $script:Proj
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'CLI basics' {
    It 'prints usage and exits 0 for help' {
        $r = Invoke-Cred -CliArgs @('help')
        $r.ExitCode | Should -Be 0
        $r.StdOut   | Should -Match 'cred exec <project> -- <cmd>'
    }

    It 'prints usage when given nothing at all' {
        (Invoke-Cred -CliArgs @()).StdOut | Should -Match 'USAGE'
    }

    It 'reports its version' {
        (Invoke-Cred -CliArgs @('version')).StdOut | Should -Match '^cred \d+\.\d+\.\d+'
    }

    It 'rejects an unknown command with exit code 2 and points at help' {
        $r = Invoke-Cred -CliArgs @('frobnicate')
        $r.ExitCode | Should -Be 2
        $r.StdErr   | Should -Match "Unknown command 'frobnicate'"
        $r.StdErr   | Should -Match 'cred help'
    }

    It 'sends errors to stderr, never to stdout' {
        $r = Invoke-Cred -CliArgs @('get', 'nope/nope')
        $r.StdOut | Should -BeNullOrEmpty
        $r.StdErr | Should -Not -BeNullOrEmpty
    }
}

Describe 'CLI round trip' -Skip:(-not $script:HasAge) {

    It 'adds a value from stdin and gets it back byte for byte' {
        $secret = 'sk_ünï ☃ "quoted" $(x) end'
        $r = Invoke-Cred -CliArgs @('add', 'cliproj/api', '--stdin') -StdIn $secret
        $r.ExitCode | Should -Be 0
        $r.StdOut   | Should -Match 'Added cliproj/api'

        $g = Invoke-Cred -CliArgs @('get', 'cliproj/api', '-n')
        $g.ExitCode | Should -Be 0
        $g.StdOut   | Should -BeExactly $secret
    }

    It 'adds a trailing newline by default and omits it with -n' {
        $null = Invoke-Cred -CliArgs @('add', 'cliproj/nl', '--stdin') -StdIn 'value'
        (Invoke-Cred -CliArgs @('get', 'cliproj/nl')).StdOut    | Should -BeExactly "value$([Environment]::NewLine)"
        (Invoke-Cred -CliArgs @('get', 'cliproj/nl', '-n')).StdOut | Should -BeExactly 'value'
    }

    It 'lists names without printing any value' {
        $null = Invoke-Cred -CliArgs @('add', 'cliproj/listed', '--stdin', '--desc', 'a description') -StdIn 'TOPSECRETVALUE'
        $r = Invoke-Cred -CliArgs @('list', 'cliproj')
        $r.StdOut | Should -Match 'listed'
        $r.StdOut | Should -Match 'a description'
        $r.StdOut | Should -Not -Match 'TOPSECRETVALUE'
    }

    It 'emits machine-readable JSON on request' {
        $r = Invoke-Cred -CliArgs @('list', 'cliproj', '--json')
        { $r.StdOut | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'runs a command with the secrets injected and returns its exit code' {
        $null = Invoke-Cred -CliArgs @('add', 'cliproj/tok', '--stdin', '--env', 'MY_TOKEN') -StdIn 'tok-value'
        $r = Invoke-Cred -CliArgs @('exec', 'cliproj', '--', $script:Pwsh, '-NoProfile', '-Command',
                                    'if ($env:MY_TOKEN -eq "tok-value") { exit 0 } else { exit 9 }')
        $r.ExitCode | Should -Be 0
    }

    It 'passes everything after -- through untouched, including flags cred itself understands' {
        # --only and --json are cred options. After `--` they must reach the
        # child verbatim instead of being parsed by cred.
        $echo = Join-Path $script:Sandbox 'echoargs.ps1'
        Set-Content -LiteralPath $echo -Encoding UTF8 -Value '[Console]::Out.Write($args -join "|")'
        $r = Invoke-Cred -CliArgs @('exec', 'cliproj', '--', $script:Pwsh, '-NoProfile', '-File', $echo,
                                    '--only', '--json', 'a b', 'quote"here')
        $r.StdOut | Should -BeExactly '--only|--json|a b|quote"here'
    }

    It 'removes a credential with --yes and no prompt' {
        $null = Invoke-Cred -CliArgs @('add', 'cliproj/temp', '--stdin') -StdIn 'x'
        $r = Invoke-Cred -CliArgs @('rm', 'cliproj/temp', '--yes')
        $r.ExitCode | Should -Be 0
        (Invoke-Cred -CliArgs @('get', 'cliproj/temp')).ExitCode | Should -Be 3
    }

    It 'refuses to remove without --yes when stdin is not a terminal' {
        # The CLI asks its own question rather than handing -Confirm to the
        # module, so a piped or scripted run has to be an explicit --yes and
        # never a prompt nobody can answer.
        $null = Invoke-Cred -CliArgs @('add', 'cliproj/keepme', '--stdin') -StdIn 'x'
        $r = Invoke-Cred -CliArgs @('rm', 'cliproj/keepme')
        $r.ExitCode | Should -Be 2
        $r.StdErr   | Should -Match 'confirmation'
        (Invoke-Cred -CliArgs @('get', 'cliproj/keepme')).StdOut.Trim() | Should -BeExactly 'x'
    }

    It 'reports the health of the setup' {
        $r = Invoke-Cred -CliArgs @('doctor', 'cliproj')
        $r.ExitCode | Should -Be 0
        $r.StdOut   | Should -Match 'provider:age'
        $r.StdOut   | Should -Match 'decrypt'
    }

    It 'writes an agent brief that names credentials but no values' {
        $r = Invoke-Cred -CliArgs @('claude', 'cliproj')
        $r.StdOut | Should -Match 'cred exec cliproj'
        $r.StdOut | Should -Match 'api'
        $r.StdOut | Should -Not -Match 'TOPSECRETVALUE'
    }
}

Describe 'CLI exit codes' -Skip:(-not $script:HasAge) {
    It 'exits <code> for <case>' -ForEach @(
        @{ case = 'a missing credential'; code = 3; cliArgs = @('get', 'cliproj/absent') }
        @{ case = 'a missing project';    code = 3; cliArgs = @('get', 'ghost/x') }
        @{ case = 'a usage mistake';      code = 2; cliArgs = @('get') }
        @{ case = 'a missing command';    code = 8; cliArgs = @('exec', 'cliproj', '--', 'definitely-not-a-binary') }
    ) {
        (Invoke-Cred -CliArgs $cliArgs).ExitCode | Should -Be $code
    }
}

Describe 'Leak hygiene' -Skip:(-not $script:HasAge) {

    It 'keeps a secret out of a PowerShell transcript' {
        # Start-Transcript records everything that goes through the PowerShell
        # pipeline. `cred get` writes to the raw console handle instead, which
        # is the whole reason Write-CredSecret exists.
        $canary     = "transcript-canary-$([guid]::NewGuid().ToString('N'))"
        $null       = Invoke-Cred -CliArgs @('add', 'cliproj/canary', '--stdin') -StdIn $canary
        $transcript = Join-Path $script:Sandbox 'transcript.txt'

        $runner = Join-Path $script:Sandbox 'transcribe.ps1'
        Set-Content -LiteralPath $runner -Encoding UTF8 -Value @"
Start-Transcript -Path '$transcript' -Force | Out-Null
& '$($script:Cli)' get cliproj/canary
Stop-Transcript | Out-Null
"@
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName  = $script:Pwsh
        $psi.Arguments = "-NoProfile -NonInteractive -File `"$runner`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.EnvironmentVariables['CRED_HOME'] = $script:CredHomeDir
        $p = [System.Diagnostics.Process]::Start($psi)
        $stdout = $p.StandardOutput.ReadToEnd()
        $p.WaitForExit()

        Test-Path $transcript | Should -BeTrue
        (Get-Content -LiteralPath $transcript -Raw) | Should -Not -Match $canary
        # ...but the caller still received it, so this is genuine containment
        # rather than the value simply having gone missing.
        $stdout | Should -Match $canary
    }

    It 'never puts a secret on a child process command line' {
        # The store is handed to age over stdin. If it were ever an argument,
        # any user on the box could read it out of the process list.
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'src\Cred\Private\Providers.ps1') -Raw
        $src | Should -Not -Match '\$PlainBytes\s*\)?\s*(-join|\+)'
        $src | Should -Match 'InputBytes \$PlainBytes'
        $src | Should -Match 'InputBytes \$CipherBytes'
    }

    It 'keeps secrets out of verbose and debug output' {
        $r = Invoke-Cred -CliArgs @('add', 'cliproj/verbose', '--stdin', '--verbose') -StdIn 'VERBOSECANARY'
        ($r.StdOut + $r.StdErr) | Should -Not -Match 'VERBOSECANARY'
    }

    It 'keeps secrets out of error output when the store cannot be written' {
        $r = Invoke-Cred -CliArgs @('add', 'no-such-project/k', '--stdin') -StdIn 'ERRORCANARY'
        $r.ExitCode | Should -Be 3
        ($r.StdOut + $r.StdErr) | Should -Not -Match 'ERRORCANARY'
    }
}
