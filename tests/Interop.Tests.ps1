#requires -Version 5.1
<#
    Interop tests -- the PowerShell and Python implementations against each
    other.

    These are the tests that make "peer implementation" a fact rather than a
    claim. If the file formats, the lock protocol or the default env-var naming
    ever drift apart, this file fails.
#>

BeforeDiscovery {
    $script:HasAge = [bool](Get-Command age -ErrorAction SilentlyContinue) -or
                     (Test-Path "$env:LOCALAPPDATA\Microsoft\WinGet\Links\age.exe")
    # No ?? here: that operator is PowerShell 7 only, and this file has to be
    # discoverable under 5.1 as well.
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
    $script:HasPython = [bool]$py
}

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'src\Cred\Cred.psd1') -Force

    $script:PyExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $script:PyExe) { $script:PyExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
    $script:PyCli = Join-Path $script:RepoRoot 'python\cred.py'

    $script:Sandbox   = Join-Path ([System.IO.Path]::GetTempPath()) "credio-$([guid]::NewGuid().ToString('N'))"
    $script:SavedHome = $env:CRED_HOME
    $env:CRED_HOME    = Join-Path $script:Sandbox 'home'
    $null = New-Item -ItemType Directory -Path $script:Sandbox -Force
    $null = New-CredIdentity

    function Invoke-PyCred {
        <#
            Run the Python cred as a separate process and capture both streams
            and the exit code, with byte-exact UTF-8 on the way in and out.
        #>
        param([string[]]$CliArgs, [string]$StdIn)

        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $script:PyExe
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.RedirectStandardInput  = $true
        $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $psi.StandardErrorEncoding  = [System.Text.UTF8Encoding]::new($false)
        $psi.EnvironmentVariables['CRED_HOME'] = $env:CRED_HOME
        # Make Python's own stdio UTF-8 regardless of the console code page.
        $psi.EnvironmentVariables['PYTHONIOENCODING'] = 'utf-8'
        $psi.EnvironmentVariables.Remove('CRED_PROJECT') | Out-Null

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

    function New-TestProject {
        param([string]$Name = "i$([guid]::NewGuid().ToString('N').Substring(0,8))")
        $dir = Join-Path $script:Sandbox $Name
        $null = New-Item -ItemType Directory -Path $dir -Force
        $null = Initialize-CredProject -Project $Name -Path $dir
        [pscustomobject]@{ Name = $Name; Path = $dir }
    }
}

AfterAll {
    $env:CRED_HOME = $script:SavedHome
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'PowerShell writes, Python reads' -Skip:(-not ($script:HasAge -and $script:HasPython)) {

    It 'reads back <label> byte for byte' -ForEach @(
        @{ label = 'ascii';    value = 'sk_test_abc123' }
        @{ label = 'unicode';  value = 'pässwörd ☃ 日本語' }
        @{ label = 'quotes';   value = 'a"b''c`d' }
        @{ label = 'spaces';   value = '  padded  ' }
        @{ label = 'metas';    value = '$(rm -rf /) `whoami` %PATH% & | > <' }
    ) {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret $value
        $r = Invoke-PyCred -CliArgs @('get', "$($p.Name)/k", '-n')
        $r.ExitCode | Should -Be 0 -Because $r.StdErr
        $r.StdOut   | Should -BeExactly $value
    }

    It 'sees the same credential list and the same env-var names' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/db" -User 'svc' -Secret 'x' -Description 'the database'
        $null = Set-Cred -Name "$($p.Name)/api" -Secret 'y' -Env @{ secret = 'API_TOKEN' }

        $r = Invoke-PyCred -CliArgs @('list', $p.Name, '--json')
        $r.ExitCode | Should -Be 0 -Because $r.StdErr
        $rows = $r.StdOut | ConvertFrom-Json

        ($rows | Where-Object Key -eq 'db').Environment  | Should -Be 'DB_USER, DB_PASSWORD'
        ($rows | Where-Object Key -eq 'db').Description  | Should -Be 'the database'
        ($rows | Where-Object Key -eq 'api').Environment | Should -Be 'API_TOKEN'
    }
}

Describe 'Python writes, PowerShell reads' -Skip:(-not ($script:HasAge -and $script:HasPython)) {

    It 'reads back <label> byte for byte' -ForEach @(
        @{ label = 'ascii';   value = 'written-by-python' }
        @{ label = 'unicode'; value = 'ünï ☃ 日本語 🔐' }
        @{ label = 'quotes';  value = 'a"b''c' }
    ) {
        $p = New-TestProject
        $r = Invoke-PyCred -CliArgs @('add', "$($p.Name)/k", '--stdin') -StdIn $value
        $r.ExitCode | Should -Be 0 -Because $r.StdErr
        Get-Cred -Name "$($p.Name)/k" | Should -BeExactly $value
    }

    It 'produces a userpass credential PowerShell reads as a PSCredential' {
        $p = New-TestProject
        $r = Invoke-PyCred -CliArgs @('add', "$($p.Name)/db", '--stdin', '--user', 'svc acme') -StdIn 'p@ss ünï'
        $r.ExitCode | Should -Be 0 -Because $r.StdErr

        $c = Get-CredCredential -Name "$($p.Name)/db"
        $c.UserName | Should -Be 'svc acme'
        $c.GetNetworkCredential().Password | Should -BeExactly 'p@ss ünï'
    }

    It 'writes a config PowerShell parses without complaint' {
        $p = New-TestProject
        $null = Invoke-PyCred -CliArgs @('add', "$($p.Name)/x", '--stdin', '--desc', 'from python') -StdIn 'v'
        (Get-CredList -Project $p.Name | Where-Object Key -eq 'x').Description | Should -Be 'from python'
    }
}

Describe 'Both directions in one store' -Skip:(-not ($script:HasAge -and $script:HasPython)) {

    It 'interleaves writes without either side losing the other' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/ps1" -Secret 'one'
        $null = Invoke-PyCred -CliArgs @('add', "$($p.Name)/py1", '--stdin') -StdIn 'two'
        $null = Set-Cred -Name "$($p.Name)/ps2" -Secret 'three'
        $null = Invoke-PyCred -CliArgs @('add', "$($p.Name)/py2", '--stdin') -StdIn 'four'

        @(Get-CredList -Project $p.Name).Key | Should -Be @('ps1', 'ps2', 'py1', 'py2')
        Get-Cred -Name "$($p.Name)/py1" | Should -Be 'two'
        Get-Cred -Name "$($p.Name)/py2" | Should -Be 'four'

        $r = Invoke-PyCred -CliArgs @('get', "$($p.Name)/ps2", '-n')
        $r.StdOut | Should -BeExactly 'three'
    }

    It 'agrees on removal' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/gone" -Secret 'x'
        $null = Set-Cred -Name "$($p.Name)/stays" -Secret 'y'
        $r = Invoke-PyCred -CliArgs @('rm', "$($p.Name)/gone", '--yes')
        $r.ExitCode | Should -Be 0 -Because $r.StdErr

        @(Get-CredList -Project $p.Name).Key | Should -Be 'stays'
        { Get-Cred -Name "$($p.Name)/gone" } | Should -Throw -ExpectedMessage '*no credential named*'
    }

    It 'agrees on adding a recipient and re-encrypting' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'survives'
        $friend = Join-Path $script:Sandbox 'friend.txt'
        $friendPub = (New-CredIdentity -Path $friend).Recipient

        $r = Invoke-PyCred -CliArgs @('recipients', 'add', $friendPub, '--project', $p.Name)
        $r.ExitCode | Should -Be 0 -Because $r.StdErr

        @(Get-CredRecipient -Project $p.Name).Count | Should -Be 2
        Get-Cred -Name "$($p.Name)/k" | Should -Be 'survives'
    }
}

Describe 'Matching behaviour' -Skip:(-not ($script:HasAge -and $script:HasPython)) {

    It 'uses the same exit code for <case>' -ForEach @(
        @{ case = 'a missing credential'; code = 3 }
        @{ case = 'a missing project';    code = 3 }
        @{ case = 'a usage mistake';      code = 2 }
    ) {
        $p = New-TestProject
        $cliArgs = switch ($case) {
            'a missing credential' { @('get', "$($p.Name)/absent") }
            'a missing project'    { @('get', 'ghost-project/x') }
            'a usage mistake'      { @('get') }
        }
        (Invoke-PyCred -CliArgs $cliArgs).ExitCode | Should -Be $code
    }

    It 'sends errors to stderr and keeps stdout clean' {
        $r = Invoke-PyCred -CliArgs @('get', 'ghost-project/x')
        $r.StdOut | Should -BeNullOrEmpty
        $r.StdErr | Should -Match 'No project named'
        $r.StdErr | Should -Match 'cred project list'
    }

    It 'never prints a value in a list' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'PYTHONCANARY'
        $r = Invoke-PyCred -CliArgs @('list', $p.Name)
        $r.StdOut | Should -Not -Match 'PYTHONCANARY'
        ($r.StdOut + $r.StdErr) | Should -Not -Match 'PYTHONCANARY'
    }
}
