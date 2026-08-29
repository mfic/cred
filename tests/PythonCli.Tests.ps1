#requires -Version 5.1
<#
    Python CLI tests -- `cred` is now the Python implementation, so the surface
    that used to be PowerShell-only has to hold up here.

    Interop with the PowerShell side lives in Interop.Tests.ps1; this file is
    about the Python CLI standing on its own.
#>

BeforeDiscovery {
    $script:HasAge = [bool](Get-Command age -ErrorAction SilentlyContinue) -or
                     (Test-Path "$env:LOCALAPPDATA\Microsoft\WinGet\Links\age.exe")
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
    $script:HasPython = [bool]$py
    $script:OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or
                        [bool](Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)
}

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'src\Cred\Cred.psd1') -Force

    $script:PyExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $script:PyExe) { $script:PyExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
    $script:PyCli = Join-Path $script:RepoRoot 'python\cred.py'

    $script:Sandbox     = Join-Path ([System.IO.Path]::GetTempPath()) "credpy-$([guid]::NewGuid().ToString('N'))"
    $script:CredHomeDir = Join-Path $script:Sandbox 'home'
    $null = New-Item -ItemType Directory -Path $script:Sandbox -Force

    function Invoke-Cred {
        param([string[]]$CliArgs, [string]$StdIn, [string]$WorkingDirectory,
              [hashtable]$Environment)

        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $script:PyExe
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.RedirectStandardInput  = $true
        $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $psi.StandardErrorEncoding  = [System.Text.UTF8Encoding]::new($false)
        if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
        $psi.EnvironmentVariables['CRED_HOME'] = $script:CredHomeDir
        $psi.EnvironmentVariables['PYTHONIOENCODING'] = 'utf-8'
        $psi.EnvironmentVariables.Remove('CRED_PROJECT') | Out-Null
        $psi.EnvironmentVariables.Remove('CRED_IDENTITY_FILE') | Out-Null
        foreach ($k in $Environment.Keys) { $psi.EnvironmentVariables[$k] = $Environment[$k] }

        $quoted = @($script:PyCli) + $CliArgs |
                  ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }
        $psi.Arguments = $quoted -join ' '

        $p = [System.Diagnostics.Process]::Start($psi)
        if ($StdIn) {
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
                     (Test-Path "$env:LOCALAPPDATA\Microsoft\WinGet\Linksge.exe")

    if ($script:HasAge) {
        $null = Invoke-Cred -CliArgs @('keygen')
        $script:Proj = Join-Path $script:Sandbox 'pyproj'
        $null = New-Item -ItemType Directory -Path $script:Proj -Force
        $null = Invoke-Cred -CliArgs @('init', 'pyproj') -WorkingDirectory $script:Proj
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Python CLI basics' -Skip:(-not $script:HasPython) {
    It 'prints usage and exits 0 for help' {
        $r = Invoke-Cred -CliArgs @('help')
        $r.ExitCode | Should -Be 0
        $r.StdOut   | Should -Match 'cred exec <project> -- <cmd>'
    }

    It 'documents the commands that used to be PowerShell-only' {
        $u = (Invoke-Cred -CliArgs @('help')).StdOut
        $u | Should -Match 'key protect'
        $u | Should -Match 'import <path>'
        $u | Should -Match 'export <folder>'
        $u | Should -Match 'claude \[project\]'
        $u | Should -Match 'providers'
    }

    It 'rejects an unknown command with exit code 2' {
        $r = Invoke-Cred -CliArgs @('frobnicate')
        $r.ExitCode | Should -Be 2
        $r.StdErr   | Should -Match 'cred help'
    }
}

Describe 'Python CLI providers' -Skip:(-not ($script:HasAge -and $script:HasPython)) {
    It 'lists the registered backends' {
        $r = Invoke-Cred -CliArgs @('providers')
        $r.StdOut | Should -Match 'age'
    }

    It 'reports an unknown provider by name and lists the real ones' {
        $dir = Join-Path $script:Sandbox 'badprov'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $null = Invoke-Cred -CliArgs @('init', 'badprov') -WorkingDirectory $dir
        $cfg = Join-Path $dir '.creds\config.json'
        (Get-Content $cfg -Raw).Replace('"age"', '"nonesuch"') | Set-Content -LiteralPath $cfg -Encoding UTF8

        $r = Invoke-Cred -CliArgs @('list', '--path', $dir)
        $r.ExitCode | Should -Be 5
        $r.StdErr   | Should -Match "Unknown encryption provider 'nonesuch'"
        $r.StdErr   | Should -Match 'Known providers'
    }
}

Describe 'Python CLI keystore' -Skip:(-not ($script:HasAge -and $script:HasPython -and $script:OnWindows)) {

    It 'wraps the key and leaves no key material on disk' {
        $before = (Invoke-Cred -CliArgs @('key')).StdOut
        $before | Should -Match 'file-permissions'

        $r = Invoke-Cred -CliArgs @('key', 'protect', '--backup',
                                    (Join-Path $script:Sandbox 'kb.txt'))
        $r.ExitCode | Should -Be 0 -Because $r.StdErr
        $r.StdOut   | Should -Match 'dpapi-currentuser'

        foreach ($f in (Get-ChildItem -LiteralPath $script:CredHomeDir -Recurse -File -Force)) {
            [System.IO.File]::ReadAllText($f.FullName) | Should -Not -Match 'AGE-SECRET-KEY-'
        }
    }

    It 'still reads and writes through the wrapped key' {
        $null = Invoke-Cred -CliArgs @('add', 'pyproj/wrapped', '--stdin') -StdIn 'through-wrapped ☃'
        (Invoke-Cred -CliArgs @('get', 'pyproj/wrapped', '-n')).StdOut |
            Should -BeExactly 'through-wrapped ☃'
    }

    It 'produces a wrapped key the PowerShell module also opens' {
        $saved = $env:CRED_HOME
        try {
            $env:CRED_HOME = $script:CredHomeDir
            Get-Cred -Name 'pyproj/wrapped' -Path $script:Proj | Should -BeExactly 'through-wrapped ☃'
            (Get-CredIdentityInfo).Protection | Should -Be 'dpapi-currentuser'
        }
        finally { $env:CRED_HOME = $saved }
    }

    It 'unwraps again, and is idempotent either way' {
        (Invoke-Cred -CliArgs @('key', 'unprotect')).StdOut | Should -Match 'unwrapped'
        (Invoke-Cred -CliArgs @('key', 'unprotect')).StdOut | Should -Match 'was not wrapped'
        (Invoke-Cred -CliArgs @('get', 'pyproj/wrapped', '-n')).StdOut |
            Should -BeExactly 'through-wrapped ☃'
    }
}

Describe 'Python CLI migration' -Skip:(-not ($script:HasAge -and $script:HasPython -and $script:OnWindows)) {

    BeforeAll {
        # Written by PowerShell, on purpose: this is the format the user
        # actually has, and the point is that Python can read it unaided.
        $script:Legacy = Join-Path $script:Sandbox 'legacy'
        $null = New-Item -ItemType Directory -Path $script:Legacy -Force
        $ss = [System.Security.SecureString]::new()
        foreach ($c in 'legacy p@ss ünï'.ToCharArray()) { $ss.AppendChar($c) }
        [System.Management.Automation.PSCredential]::new('legacy_user', $ss) |
            Export-Clixml -LiteralPath (Join-Path $script:Legacy 'legacy.cred.xml')

        $ss2 = [System.Security.SecureString]::new()
        foreach ($c in 'bare-token ☃'.ToCharArray()) { $ss2.AppendChar($c) }
        $ss2 | Export-Clixml -LiteralPath (Join-Path $script:Legacy 'token.xml')
    }

    It 'shows what it would import and changes nothing' {
        $dir = Join-Path $script:Sandbox 'dryrun'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $null = Invoke-Cred -CliArgs @('init', 'dryrun') -WorkingDirectory $dir

        $r = Invoke-Cred -CliArgs @('import', $script:Legacy, '--dry-run', '--path', $dir)
        $r.StdOut | Should -Match 'would import'
        (Invoke-Cred -CliArgs @('list', '--path', $dir)).StdOut | Should -Match 'No credentials defined'
    }

    It 'imports Export-Clixml credentials written by PowerShell' {
        $r = Invoke-Cred -CliArgs @('import', $script:Legacy, '--project', 'pyproj',
                                    '--desc', 'migrated')
        $r.ExitCode | Should -Be 0 -Because $r.StdErr

        (Invoke-Cred -CliArgs @('get', 'pyproj/legacy', '--field', 'user', '-n')).StdOut |
            Should -Be 'legacy_user'
        (Invoke-Cred -CliArgs @('get', 'pyproj/legacy', '-n')).StdOut |
            Should -BeExactly 'legacy p@ss ünï'
        # A bare SecureString has no username, so it lands as a plain secret.
        (Invoke-Cred -CliArgs @('get', 'pyproj/token', '-n')).StdOut |
            Should -BeExactly 'bare-token ☃'
    }

    It 'refuses to clobber on a second run' {
        $r = Invoke-Cred -CliArgs @('import', $script:Legacy, '--project', 'pyproj')
        $r.StdOut | Should -Match 'skipped'
        (Invoke-Cred -CliArgs @('get', 'pyproj/legacy', '-n')).StdOut |
            Should -BeExactly 'legacy p@ss ünï'
    }

    It 'exports files PowerShell reads back as native PSCredentials' {
        $dest = Join-Path $script:Sandbox 'exported'
        $r = Invoke-Cred -CliArgs @('export', $dest, '--project', 'pyproj',
                                    '--only', 'legacy', '--yes')
        $r.ExitCode | Should -Be 0 -Because $r.StdErr

        $back = Import-Clixml -LiteralPath (Join-Path $dest 'legacy.cred.xml')
        $back | Should -BeOfType [System.Management.Automation.PSCredential]
        $back.UserName | Should -Be 'legacy_user'
        $back.GetNetworkCredential().Password | Should -BeExactly 'legacy p@ss ünï'
    }
}

Describe 'Python CLI agent brief' -Skip:(-not ($script:HasAge -and $script:HasPython)) {

    It 'names credentials and no values, and prefers exec over get' {
        $null = Invoke-Cred -CliArgs @('add', 'pyproj/brief', '--stdin', '--desc', 'a described one') -StdIn 'BRIEFCANARY'
        $r = Invoke-Cred -CliArgs @('claude', 'pyproj')
        $r.StdOut | Should -Match 'cred exec pyproj'
        $r.StdOut | Should -Match 'a described one'
        $r.StdOut | Should -Not -Match 'BRIEFCANARY'
    }

    It 'writes a replaceable block into CLAUDE.md' {
        $target = Join-Path $script:Proj 'CLAUDE.md'
        Set-Content -LiteralPath $target -Value "# My project`n`nExisting notes." -Encoding UTF8

        $null = Invoke-Cred -CliArgs @('claude', 'pyproj', '--write')
        $first = Get-Content -LiteralPath $target -Raw
        $first | Should -Match 'Existing notes\.'
        $first | Should -Match '<!-- cred:begin -->'

        # Re-running replaces the block rather than appending a second one.
        $null = Invoke-Cred -CliArgs @('claude', 'pyproj', '--write')
        $second = Get-Content -LiteralPath $target -Raw
        ([regex]::Matches($second, '<!-- cred:begin -->')).Count | Should -Be 1
        $second | Should -Match 'Existing notes\.'
    }
}

Describe 'Python CLI leak hygiene' -Skip:(-not ($script:HasAge -and $script:HasPython)) {

    It 'never prints a value in a list' {
        $null = Invoke-Cred -CliArgs @('add', 'pyproj/canary', '--stdin') -StdIn 'PYLISTCANARY'
        $r = Invoke-Cred -CliArgs @('list', 'pyproj')
        ($r.StdOut + $r.StdErr) | Should -Not -Match 'PYLISTCANARY'
    }

    It 'keeps a value out of an error when the project does not exist' {
        $r = Invoke-Cred -CliArgs @('add', 'ghost/k', '--stdin') -StdIn 'PYERRCANARY'
        $r.ExitCode | Should -Be 3
        ($r.StdOut + $r.StdErr) | Should -Not -Match 'PYERRCANARY'
    }

    It 'keeps values out of every file under the project' {
        $canary = "pyfilecanary$([guid]::NewGuid().ToString('N'))"
        $null = Invoke-Cred -CliArgs @('add', 'pyproj/onfile', '--stdin') -StdIn $canary
        foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $script:Proj '.creds') -Recurse -File -Force)) {
            [System.IO.File]::ReadAllText($f.FullName) | Should -Not -Match $canary
        }
    }

    It 'sends errors to stderr and keeps stdout clean' {
        $r = Invoke-Cred -CliArgs @('get', 'pyproj/absent')
        $r.StdOut | Should -BeNullOrEmpty
        $r.StdErr | Should -Match 'no credential named'
    }
}


Describe 'Python units' -Skip:(-not $script:HasPython) {
    # cred.py is the default implementation everywhere, so its pure functions
    # are checked directly rather than only through the process. tests/pyunit.py
    # holds the cases; this runs them under the one runner.
    It 'passes tests/pyunit.py' {
        $harness = Join-Path $PSScriptRoot 'pyunit.py'
        $out = & $script:PyExe $harness 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($out -join [Environment]::NewLine)
    }
}

Describe 'Python CLI init --force does not erase silently' -Skip:(-not ($script:HasAge -and $script:HasPython)) {
    # --force used to rewrite config.json and the store unconditionally. The
    # route into it was an error message about a *renamed* folder, so following
    # the advice destroyed the store you were trying to reach.
    BeforeEach {
        $script:Guard = Join-Path $script:Sandbox "guard-$([guid]::NewGuid().ToString('N'))"
        $null = New-Item -ItemType Directory -Path $script:Guard -Force
        $null = Invoke-Cred -CliArgs @('init', 'guardproj') -WorkingDirectory $script:Guard
        $null = Invoke-Cred -CliArgs @('add', 'guardproj/tok', '--value', 'keepme') `
                            -WorkingDirectory $script:Guard
    }

    It 'refuses on a non-empty store, names the cost, and changes nothing' {
        $r = Invoke-Cred -CliArgs @('init', '--force', 'guardproj') -WorkingDirectory $script:Guard
        $r.ExitCode | Should -Be 2
        $r.StdErr   | Should -Match 'will erase 1 credential'
        $r.StdErr   | Should -Match 'cred doctor'
        (Invoke-Cred -CliArgs @('get', 'tok', '-n', '--path', $script:Guard)).StdOut |
            Should -BeExactly 'keepme'
    }

    It 'proceeds when --yes is given' {
        $r = Invoke-Cred -CliArgs @('init', '--force', '--yes', 'guardproj') `
                         -WorkingDirectory $script:Guard
        $r.ExitCode | Should -Be 0 -Because $r.StdErr
        (Invoke-Cred -CliArgs @('list', '--path', $script:Guard)).StdOut |
            Should -Match 'No credentials defined'
    }

    It 'does not ask when there is nothing to lose' {
        $null = Invoke-Cred -CliArgs @('init', '--force', '--yes', 'guardproj') `
                            -WorkingDirectory $script:Guard
        $r = Invoke-Cred -CliArgs @('init', '--force', 'guardproj') -WorkingDirectory $script:Guard
        $r.ExitCode | Should -Be 0 -Because $r.StdErr
    }
}

Describe 'Python CLI doctor checks the key and the repo' -Skip:(-not ($script:HasAge -and $script:HasPython)) {
    # These four checks existed only in the PowerShell doctor, so the two
    # implementations disagreed about what `cred doctor` even reports.

    It 'warns when another principal can read the key, and --repair clears it' -Skip:(-not $script:OnWindows) {
        $key = Join-Path $script:CredHomeDir 'identity.txt'
        # *S-1-1-0 is Everyone by SID, so this works on a localised Windows.
        & icacls $key '/grant' '*S-1-1-0:(R)' 2>&1 | Out-Null
        (Invoke-Cred -CliArgs @('doctor')).StdOut | Should -Match 'identity permissions\s+Warn'

        (Invoke-Cred -CliArgs @('doctor', '--repair')).StdOut |
            Should -Match 'identity permissions\s+Ok'
    }

    It 'fails, and exits 1, when the key sits inside a repository' {
        $repo = Join-Path $script:Sandbox "keyinrepo-$([guid]::NewGuid().ToString('N'))"
        $null = New-Item -ItemType Directory -Path $repo -Force
        $null = Invoke-Cred -CliArgs @('init', 'keyinrepo', '--path', $repo)
        Copy-Item -LiteralPath (Join-Path $script:CredHomeDir 'identity.txt') `
                  -Destination (Join-Path $repo 'identity.txt')

        $r = Invoke-Cred -CliArgs @('doctor', '--path', $repo) `
                         -Environment @{ CRED_IDENTITY_FILE = (Join-Path $repo 'identity.txt') }
        $r.StdOut   | Should -Match 'identity location\s+Fail'
        $r.ExitCode | Should -Be 1
    }

    It 'warns when .creds is gitignored, and is quiet when it is not' {
        $repo = Join-Path $script:Sandbox "gitrepo-$([guid]::NewGuid().ToString('N'))"
        $null = New-Item -ItemType Directory -Path $repo -Force
        & git -C $repo init -q 2>&1 | Out-Null
        $null = Invoke-Cred -CliArgs @('init', 'gitrepo', '--path', $repo)

        (Invoke-Cred -CliArgs @('doctor', '--path', $repo)).StdOut | Should -Match 'git\s+Ok'

        Set-Content -LiteralPath (Join-Path $repo '.gitignore') -Value '.creds/' -Encoding ascii
        (Invoke-Cred -CliArgs @('doctor', '--path', $repo)).StdOut | Should -Match 'git\s+Warn'
    }

    It 'reports how the key is protected' {
        (Invoke-Cred -CliArgs @('doctor')).StdOut | Should -Match 'identity protection\s+Ok'
    }
}

Describe 'Python CLI doctor reconciles the project registry' -Skip:(-not ($script:HasAge -and $script:HasPython)) {
    # projects.json is a cache that only `cred init` ever wrote, so a clone or a
    # rename left every `cred get <project>/<key>` broken with no command able
    # to repair it.
    BeforeAll {
        # Defined here rather than in the Describe body: Pester 5 does not carry
        # a function declared there into the It blocks.
        function New-GuardProject {
            param([string]$Name)
            $dir = Join-Path $script:Sandbox "$Name-$([guid]::NewGuid().ToString('N'))"
            $null = New-Item -ItemType Directory -Path $dir -Force
            $null = Invoke-Cred -CliArgs @('init', $Name) -WorkingDirectory $dir
            $null = Invoke-Cred -CliArgs @('add', "$Name/tok", '--value', 'v') -WorkingDirectory $dir
            return $dir
        }
    }

    It 'registers a store that exists on disk but not in the registry' {
        $dir = New-GuardProject -Name 'cloneproj'
        # Forget it, the way a machine that has only ever cloned the repo would.
        $null = Invoke-Cred -CliArgs @('project', 'rm', 'cloneproj')
        (Invoke-Cred -CliArgs @('get', 'cloneproj/tok')).ExitCode | Should -Be 3

        $d = Invoke-Cred -CliArgs @('doctor') -WorkingDirectory $dir
        $d.StdOut | Should -Match 'registry\s+Fixed'
        (Invoke-Cred -CliArgs @('get', 'cloneproj/tok', '-n')).StdOut | Should -BeExactly 'v'
    }

    It 'updates a stale path after the folder is renamed' {
        $dir = New-GuardProject -Name 'renameproj'
        $moved = Join-Path (Split-Path -Parent $dir) "renamed-$([guid]::NewGuid().ToString('N'))"
        Move-Item -LiteralPath $dir -Destination $moved
        (Invoke-Cred -CliArgs @('get', 'renameproj/tok')).ExitCode | Should -Be 3

        $d = Invoke-Cred -CliArgs @('doctor') -WorkingDirectory $moved
        $d.StdOut | Should -Match 'registry\s+Fixed'
        (Invoke-Cred -CliArgs @('get', 'renameproj/tok', '-n')).StdOut | Should -BeExactly 'v'
    }

    It 'reports a collision rather than stealing the name from another clone' {
        $first  = New-GuardProject -Name 'collideproj'
        $second = Join-Path (Split-Path -Parent $first) "second-$([guid]::NewGuid().ToString('N'))"
        Copy-Item -LiteralPath $first -Destination $second -Recurse

        $d = Invoke-Cred -CliArgs @('doctor') -WorkingDirectory $second
        $d.StdOut | Should -Match 'registry\s+Warn'
        $d.StdOut | Should -Match 'cred project rm collideproj'
        # The other clone keeps the name; nothing was written. Asserted against
        # projects.json rather than the rendered table, so the check does not
        # depend on how wide the terminal happens to be.
        $reg = (Get-Content -LiteralPath (Join-Path $script:CredHomeDir 'projects.json') -Raw |
                ConvertFrom-Json)
        $reg.projects.collideproj.path |
            Should -Be (Resolve-Path -LiteralPath $first).ProviderPath
    }
}
