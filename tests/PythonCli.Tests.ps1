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
        param([string[]]$CliArgs, [string]$StdIn, [string]$WorkingDirectory)

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
    It 'knows about both backends, not just age' {
        $r = Invoke-Cred -CliArgs @('providers')
        $r.StdOut | Should -Match 'age'
        $r.StdOut | Should -Match 'gpg'
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
