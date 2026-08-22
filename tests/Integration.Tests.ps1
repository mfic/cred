#requires -Version 5.1
<#
    Integration tests -- real age keys, real encryption, real child processes.

    Each run gets its own CRED_HOME and its own throwaway repositories, so
    nothing here can touch the machine's actual credentials.
#>

BeforeDiscovery {
    $script:HasAge = [bool](Get-Command age -ErrorAction SilentlyContinue) -or
                     (Test-Path "$env:LOCALAPPDATA\Microsoft\WinGet\Links\age.exe")
}

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'src\Cred\Cred.psd1') -Force

    $script:Sandbox      = Join-Path ([System.IO.Path]::GetTempPath()) "credit-$([guid]::NewGuid().ToString('N'))"
    $script:SavedHome    = $env:CRED_HOME
    $script:SavedProject = $env:CRED_PROJECT
    $script:SavedIdent   = $env:CRED_IDENTITY_FILE
    $env:CRED_HOME       = Join-Path $script:Sandbox 'home'
    $env:CRED_PROJECT    = $null
    $env:CRED_IDENTITY_FILE = $null

    $null = New-Item -ItemType Directory -Path $script:Sandbox -Force
    $script:Identity = New-CredIdentity

    function New-TestProject {
        param([string]$Name = "p$([guid]::NewGuid().ToString('N').Substring(0,8))")
        $dir = Join-Path $script:Sandbox $Name
        $null = New-Item -ItemType Directory -Path $dir -Force
        $null = Initialize-CredProject -Project $Name -Path $dir
        return [pscustomobject]@{ Name = $Name; Path = $dir }
    }

    function Get-SandboxFileText {
        # Everything on disk under a project, as one string, for leak hunting.
        param([string]$Root)
        $sb = [System.Text.StringBuilder]::new()
        foreach ($f in (Get-ChildItem -LiteralPath $Root -Recurse -File -Force)) {
            [void]$sb.AppendLine($f.FullName)
            [void]$sb.AppendLine([System.IO.File]::ReadAllText($f.FullName))
        }
        return $sb.ToString()
    }
}

AfterAll {
    $env:CRED_HOME          = $script:SavedHome
    $env:CRED_PROJECT       = $script:SavedProject
    $env:CRED_IDENTITY_FILE = $script:SavedIdent
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Lifecycle' -Skip:(-not $script:HasAge) {

    It 'initialises a project that is decryptable by its creator' {
        $p = New-TestProject
        Test-Path (Join-Path $p.Path '.creds\config.json') | Should -BeTrue
        Test-Path (Join-Path $p.Path '.creds\store.age')   | Should -BeTrue
        (Get-CredRecipient -Project $p.Name).IsMe | Should -Contain $true
    }

    It 'refuses to re-initialise without -Force, and says what to do instead' {
        $p = New-TestProject
        { Initialize-CredProject -Project $p.Name -Path $p.Path } |
            Should -Throw -ExpectedMessage '*already has a credential store*'
    }

    It 'stores and returns a value byte for byte' -ForEach @(
        @{ label = 'ascii';       value = 'sk_test_abc123' }
        @{ label = 'spaces';      value = '  leading and trailing  ' }
        @{ label = 'quotes';      value = 'a"b''c`d' }
        @{ label = 'unicode';     value = 'pässwörd ☃ 日本語 🔐' }
        @{ label = 'newlines';    value = "line1`nline2`r`nline3" }
        @{ label = 'shell metas'; value = '$(rm -rf /) `whoami` %PATH% & | > <' }
        @{ label = 'json';        value = '{"nested":"value","n":[1,2]}' }
        @{ label = 'long';        value = ('x' * 8192) }
    ) {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret $value
        Get-Cred -Name "$($p.Name)/k" | Should -BeExactly $value
    }

    It 'keeps values out of every file on disk' {
        $p = New-TestProject
        $secret = "canary-$([guid]::NewGuid().ToString('N'))"
        $null = Set-Cred -Name "$($p.Name)/leak" -Secret $secret -User "user-$secret"

        (Get-SandboxFileText -Root $p.Path)          | Should -Not -Match $secret
        (Get-SandboxFileText -Root $env:CRED_HOME)   | Should -Not -Match $secret
    }

    It 'keeps values out of the plaintext config while keeping names in it' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/stripe" -Secret 'sk_live_dontleakme' -Description 'billing'
        $config = Get-Content (Join-Path $p.Path '.creds\config.json') -Raw
        $config | Should -Match 'stripe'
        $config | Should -Match 'billing'
        $config | Should -Not -Match 'sk_live_dontleakme'
    }

    It 'updates a value in place without creating a duplicate' {
        $p = New-TestProject
        $a = Set-Cred -Name "$($p.Name)/k" -Secret 'one'
        $b = Set-Cred -Name "$($p.Name)/k" -Secret 'two'
        $a.Created | Should -BeTrue
        $b.Created | Should -BeFalse
        Get-Cred -Name "$($p.Name)/k" | Should -Be 'two'
        @(Get-CredList -Project $p.Name).Count | Should -Be 1
    }

    It 'removes a credential and its declaration' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/gone" -Secret 'x'
        $null = Remove-Cred -Name "$($p.Name)/gone" -Confirm:$false
        @(Get-CredList -Project $p.Name).Count | Should -Be 0
        { Get-Cred -Name "$($p.Name)/gone" } | Should -Throw -ExpectedMessage '*no credential named*'
    }

    It 'lists credentials without needing to decrypt anything' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/a" -Secret '1' -Description 'first'
        $saved = $env:CRED_IDENTITY_FILE
        try {
            # Point at a key that does not exist: listing must still work.
            $env:CRED_IDENTITY_FILE = Join-Path $script:Sandbox 'nope.txt'
            $rows = @(Get-CredList -Project $p.Name)
            $rows.Count       | Should -Be 1
            $rows[0].Key      | Should -Be 'a'
            $rows[0].Description | Should -Be 'first'
        }
        finally { $env:CRED_IDENTITY_FILE = $saved }
    }
}

Describe 'Console encoding' -Skip:(-not $script:HasAge) {

    It 'works with a UTF-8 console, where .NET would otherwise inject a BOM into stdin' {
        # Regression test. On Windows PowerShell 5.1, Process.StandardInput is a
        # StreamWriter over Console.InputEncoding and writes that encoding's
        # preamble to the pipe as soon as it is touched. Under `chcp 65001` --
        # which is a normal thing for people to set -- every encrypt and decrypt
        # received three leading junk bytes and failed.
        $saved = [Console]::InputEncoding
        try {
            try { [Console]::InputEncoding = [System.Text.Encoding]::UTF8 }
            catch { Set-ItResult -Skipped -Because 'this host will not let us change the console encoding' ; return }

            [Console]::InputEncoding.GetPreamble().Length | Should -BeGreaterThan 0 -Because 'the test needs the hazardous setting to be in effect'

            $p = New-TestProject
            $null = Set-Cred -Name "$($p.Name)/k" -Secret 'survives-a-utf8-console'
            Get-Cred -Name "$($p.Name)/k" | Should -Be 'survives-a-utf8-console'
        }
        finally {
            try { [Console]::InputEncoding = $saved }
            catch { Write-Verbose 'Could not restore the console encoding; harmless in a test process.' }
        }
    }
}

Describe 'Access paths' -Skip:(-not $script:HasAge) {
    BeforeAll {
        $script:AP = New-TestProject
        $null = Set-Cred -Name "$($script:AP.Name)/db" -User 'svc acme' -Secret 'p@ss w0rd" ünï' -Description 'Postgres'
        $null = Set-Cred -Name "$($script:AP.Name)/stripe" -Secret 'sk_test_☃' -Env @{ secret = 'STRIPE_API_KEY' }
    }

    It 'path 1: returns a plain string suitable for piping' {
        $v = Get-Cred -Name "$($script:AP.Name)/stripe"
        $v | Should -BeOfType [string]
        $v | Should -BeExactly 'sk_test_☃'
    }

    It 'path 2: injects environment variables into a child process' {
        # Invoke-CredCommand deliberately does NOT redirect the child's stdout
        # (that is how it stays out of transcripts), so the probe reports back
        # through a file instead.
        $probe  = Join-Path $script:Sandbox 'probe.ps1'
        $report = Join-Path $script:Sandbox "report-$([guid]::NewGuid().ToString('N')).txt"
        Set-Content -LiteralPath $probe -Encoding UTF8 -Value @'
param()
$out = "U=$env:DB_USER|P=$env:DB_PASSWORD|S=$env:STRIPE_API_KEY|N=$env:CRED_PROJECT|I=$env:CRED_INJECTED"
[System.IO.File]::WriteAllText($env:PROBE_REPORT, $out, [System.Text.UTF8Encoding]::new($false))
'@
        $env:PROBE_REPORT = $report
        try {
            $exit = Invoke-CredCommand -Project $script:AP.Name `
                        -Command (Get-Process -Id $PID).Path `
                        -ArgumentList @('-NoProfile', '-File', $probe) -PassThru
            $exit | Should -Be 0

            $text = [System.IO.File]::ReadAllText($report, [System.Text.Encoding]::UTF8)
            $text | Should -Match 'U=svc acme'
            $text | Should -Match ([regex]::Escape('P=p@ss w0rd" ünï'))
            $text | Should -Match ([regex]::Escape('S=sk_test_☃'))
            $text | Should -Match "N=$($script:AP.Name)"
            $text | Should -Match 'I=.*STRIPE_API_KEY'
        }
        finally { $env:PROBE_REPORT = $null }
    }

    It 'path 2: leaves the parent process environment untouched' {
        $null = Invoke-CredCommand -Project $script:AP.Name `
                    -Command (Get-Process -Id $PID).Path `
                    -ArgumentList @('-NoProfile', '-Command', 'exit 0') -PassThru
        $env:DB_PASSWORD    | Should -BeNullOrEmpty
        $env:STRIPE_API_KEY | Should -BeNullOrEmpty
    }

    It 'path 2: propagates the child exit code' {
        $exit = Invoke-CredCommand -Project $script:AP.Name `
                    -Command (Get-Process -Id $PID).Path `
                    -ArgumentList @('-NoProfile', '-Command', 'exit 42') -PassThru
        $exit | Should -Be 42
    }

    It 'path 2: injects only what was asked for' {
        $only = Get-CredEnvironment -Project $script:AP.Name -Only 'stripe'
        $only.Keys | Should -Contain 'STRIPE_API_KEY'
        $only.Keys | Should -Not -Contain 'DB_USER'
    }

    It 'path 2: honours the declared environment variable names' {
        $table = Get-CredEnvironment -Project $script:AP.Name
        $table['DB_USER']        | Should -Be 'svc acme'
        $table['DB_PASSWORD']    | Should -Be 'p@ss w0rd" ünï'
        $table['STRIPE_API_KEY'] | Should -Be 'sk_test_☃'
    }

    It 'path 3: returns a real PSCredential' {
        $c = Get-CredCredential -Name "$($script:AP.Name)/db"
        $c            | Should -BeOfType [System.Management.Automation.PSCredential]
        $c.UserName   | Should -Be 'svc acme'
        $c.Password   | Should -BeOfType [System.Security.SecureString]
        $c.GetNetworkCredential().Password | Should -BeExactly 'p@ss w0rd" ünï'
    }

    It 'path 3: makes a PSCredential out of a bare secret too' {
        $c = Get-CredCredential -Name "$($script:AP.Name)/stripe" -UserName 'token'
        $c.UserName | Should -Be 'token'
        $c.GetNetworkCredential().Password | Should -BeExactly 'sk_test_☃'
    }

    It 'path 3: returns a SecureString on request' {
        Get-Cred -Name "$($script:AP.Name)/stripe" -AsSecureString |
            Should -BeOfType [System.Security.SecureString]
    }
}
