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

    function Invoke-PsCred {
        <#
            Run the PowerShell cred CLI as a separate process, the same way
            Invoke-PyCred runs the Python one, so the two can be compared as
            the user meets them rather than as functions.
        #>
        param([string[]]$CliArgs, [string]$StdIn)

        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = (Get-Process -Id $PID).Path
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.RedirectStandardInput  = $true
        $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $psi.StandardErrorEncoding  = [System.Text.UTF8Encoding]::new($false)
        $psi.EnvironmentVariables['CRED_HOME'] = $env:CRED_HOME
        $psi.EnvironmentVariables.Remove('CRED_PROJECT')       | Out-Null
        $psi.EnvironmentVariables.Remove('CRED_IDENTITY_FILE') | Out-Null

        $cli    = Join-Path $script:RepoRoot 'bin\cred-ps.ps1'
        $quoted = @('-NoProfile', '-NonInteractive', '-File', $cli) + $CliArgs |
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

    function Get-DoctorCheckNames {
        <#
            The Check column of a `cred doctor` table, in order.

            Anchored on the status word rather than on column positions,
            because the two editions pad their columns differently -- Python
            joins with two spaces, Format-Table with one -- and the widest
            check name would otherwise be indistinguishable from its status.
        #>
        param([string]$TableText)

        $names = @()
        foreach ($line in ($TableText -split "`r?`n")) {
            if ($line -match '^(?<check>[a-z][a-z0-9 :._-]*?)\s+(Ok|Warn|Fail)(\s|$)') {
                $names += $Matches['check']
            }
        }
        return @($names)
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

Describe 'File credentials cross the implementations byte for byte' -Skip:(-not ($script:HasAge -and $script:HasPython)) {

    BeforeAll {
        function New-TestFile {
            <# Bytes on disk, written raw so no encoder can normalise them. #>
            param([byte[]]$Bytes, [string]$Name = 'f.bin')
            $path = Join-Path $script:Sandbox "$([guid]::NewGuid().ToString('N').Substring(0,8))-$Name"
            [System.IO.File]::WriteAllBytes($path, $Bytes)
            return $path
        }
        $utf8 = [System.Text.UTF8Encoding]::new($false)
        # A PEM with LF endings, one with CRLF, and something that is not text
        # at all -- the three shapes a private key or certificate arrives in.
        $script:PemLf   = $utf8.GetBytes("-----BEGIN PRIVATE KEY-----`nMIIEvQIBADAN`nab+/`n-----END PRIVATE KEY-----`n")
        $script:PemCrLf = $utf8.GetBytes("-----BEGIN CERTIFICATE-----`r`nMIIC`r`n`r`n-----END CERTIFICATE-----`r`n")
        $script:Binary  = [byte[]](0..255) + [byte[]](0..255)
    }

    It 'PowerShell imports a <label> and Python returns the same bytes' -ForEach @(
        @{ label = 'LF PEM';   which = 'PemLf' }
        @{ label = 'CRLF PEM'; which = 'PemCrLf' }
        @{ label = 'binary';   which = 'Binary' }
    ) {
        $bytes = Get-Variable -Name $which -Scope Script -ValueOnly
        $src   = New-TestFile -Bytes $bytes -Name 'server.key'
        $p     = New-TestProject
        $null  = Set-Cred -Name "$($p.Name)/f" -File $src

        $dest = Join-Path $script:Sandbox "py-$([guid]::NewGuid().ToString('N').Substring(0,8)).out"
        $r = Invoke-PyCred -CliArgs @('get', "$($p.Name)/f", '--out', $dest)
        $r.ExitCode | Should -Be 0 -Because $r.StdErr
        [System.IO.File]::ReadAllBytes($dest) | Should -Be $bytes
    }

    It 'Python imports a <label> and PowerShell returns the same bytes' -ForEach @(
        @{ label = 'LF PEM';   which = 'PemLf' }
        @{ label = 'CRLF PEM'; which = 'PemCrLf' }
        @{ label = 'binary';   which = 'Binary' }
    ) {
        $bytes = Get-Variable -Name $which -Scope Script -ValueOnly
        $src   = New-TestFile -Bytes $bytes -Name 'cert.pfx'
        $p     = New-TestProject
        $r     = Invoke-PyCred -CliArgs @('add', "$($p.Name)/f", '--file', $src)
        $r.ExitCode | Should -Be 0 -Because $r.StdErr

        $dest = Join-Path $script:Sandbox "ps-$([guid]::NewGuid().ToString('N').Substring(0,8)).out"
        $null = Export-CredFile -Name "$($p.Name)/f" -OutFile $dest
        [System.IO.File]::ReadAllBytes($dest) | Should -Be $bytes
    }

    It 'agrees on the stored encoding for text and for binary' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/pem" -File (New-TestFile -Bytes $script:PemLf)
        $null = Set-Cred -Name "$($p.Name)/bin" -File (New-TestFile -Bytes $script:Binary)

        # The declaration is plaintext and committed, so both sides must write
        # the same thing into it.
        $r = Invoke-PyCred -CliArgs @('list', $p.Name, '--json')
        $rows = $r.StdOut | ConvertFrom-Json
        ($rows | Where-Object Key -eq 'pem').Type | Should -Be 'file'
        ($rows | Where-Object Key -eq 'bin').Type | Should -Be 'file'
    }

    It 'leaves file credentials out of the environment on both sides' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/pem" -File (New-TestFile -Bytes $script:PemLf)
        $null = Set-Cred -Name "$($p.Name)/tok" -Secret 'plain-token'

        # One decryption gives the variables and the file credentials left out
        # of them; that used to be a [ref] out-parameter on Get-CredEnvironment.
        $projected = Get-CredStoreEnvironment -Store (Open-CredStore -Project $p.Name)
        @($projected.Variables.Keys) | Should -Be @('TOK')
        $projected.Skipped           | Should -Be @('pem')

        @((Get-CredEnvironment -Project $p.Name).Keys) | Should -Be @('TOK')

        $r = Invoke-PyCred -CliArgs @('env', $p.Name)
        $r.StdOut | Should -Match 'TOK='
        $r.StdOut | Should -Not -Match 'BEGIN PRIVATE KEY'
        $r.StdErr | Should -Match 'file credentials'
    }

    It 'refuses to hand a binary file credential back as a PSCredential' {
        # Get-CredCredential used to ignore the kind entirely, so this returned
        # a base64 blob as the password and looked like it had worked. Every
        # access path now asks Resolve-CredEntry the same question.
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/bin" -File (New-TestFile -Bytes $script:Binary)
        { Get-CredCredential -Name "$($p.Name)/bin" } |
            Should -Throw -ExpectedMessage '*binary content*'
    }

    It 'reports a binary file credential as a file when config.json has lost the declaration' {
        # The store wins over the config wherever the store has something to
        # say: 'encoding' is only ever set by the file importer. Get-CredList
        # used to read 'type' straight off the declaration and called this a
        # secret. (A *text* file credential carries no marker, so its kind
        # genuinely lives in config.json alone -- that is the format, not a
        # bug, and Get-CredList still reports it from the declaration.)
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/bin" -File (New-TestFile -Bytes $script:Binary)

        $cfgPath = Join-Path (Join-Path $p.Path '.creds') 'config.json'
        $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
        $cfg.credentials.PSObject.Properties.Remove('bin')
        Set-Content -LiteralPath $cfgPath -Value ($cfg | ConvertTo-Json -Depth 10) -Encoding UTF8

        (Get-CredList -Project $p.Name -Verify | Where-Object Key -eq 'bin').Type |
            Should -BeExactly 'file'
        # And it is still excluded from the injected environment.
        @((Get-CredEnvironment -Project $p.Name).Keys) | Should -Not -Contain 'BIN'
    }

    It 'never lets the encoding marker become an environment variable' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/bin" -File (New-TestFile -Bytes $script:Binary)
        $t = Get-CredEnvironment -Project $p.Name
        @($t.Keys) | Should -Not -Contain 'BIN_ENCODING'
        @($t.Keys).Count | Should -Be 0
    }

    It 'refuses to overwrite an existing file on both sides' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/pem" -File (New-TestFile -Bytes $script:PemLf)
        $dest = New-TestFile -Bytes ([byte[]](1, 2, 3)) -Name 'occupied'

        { Export-CredFile -Name "$($p.Name)/pem" -OutFile $dest } |
            Should -Throw -ExpectedMessage '*already exists*'
        (Invoke-PyCred -CliArgs @('get', "$($p.Name)/pem", '--out', $dest)).ExitCode | Should -Be 2

        # -Force is the way through, and it really does replace the content.
        $null = Export-CredFile -Name "$($p.Name)/pem" -OutFile $dest -Force
        [System.IO.File]::ReadAllBytes($dest) | Should -Be $script:PemLf
    }

    It 'refuses -File together with -User on both sides' {
        $p   = New-TestProject
        $src = New-TestFile -Bytes $script:PemLf
        { Set-Cred -Name "$($p.Name)/x" -File $src -User 'bob' } |
            Should -Throw -ExpectedMessage '*cannot be combined*'
        (Invoke-PyCred -CliArgs @('add', "$($p.Name)/x", '--file', $src, '--user', 'bob')).ExitCode |
            Should -Be 2
    }

    It 'honours --field when writing a userpass credential to a file' {
        # The bug this guards against: --out ignored --field and wrote the
        # password when the username was asked for -- silently, and into a
        # file the caller then trusted.
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/db" -User 'alice' -Secret 'PASSWORD-NOT-USERNAME'

        $dest = Join-Path $script:Sandbox "field-$([guid]::NewGuid().ToString('N').Substring(0,8)).txt"
        $r = Invoke-PyCred -CliArgs @('get', "$($p.Name)/db", '--field', 'user', '--out', $dest)
        $r.ExitCode | Should -Be 0 -Because $r.StdErr
        [System.IO.File]::ReadAllText($dest) | Should -BeExactly 'alice'

        $dest2 = "$dest.ps"
        $null = Export-CredFile -Name "$($p.Name)/db" -OutFile $dest2 -Field user
        [System.IO.File]::ReadAllText($dest2) | Should -BeExactly 'alice'
    }

    It 'never prints the content of a file credential in a list' {
        $p = New-TestProject
        $utf8 = [System.Text.UTF8Encoding]::new($false)
        $null = Set-Cred -Name "$($p.Name)/pem" -File (New-TestFile -Bytes ($utf8.GetBytes('FILECANARY')))
        $r = Invoke-PyCred -CliArgs @('list', $p.Name)
        ($r.StdOut + $r.StdErr) | Should -Not -Match 'FILECANARY'
        (Get-CredList -Project $p.Name | Out-String) | Should -Not -Match 'FILECANARY'
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

    It 'agrees --reveal full is the cleartext value across editions' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'pässwörd☃日本語end'
        $r = Invoke-PyCred -CliArgs @('get', "$($p.Name)/k", '--reveal', 'full', '-n')
        $r.ExitCode | Should -Be 0
        $r.StdOut   | Should -BeExactly 'pässwörd☃日本語end'
    }

    It 'masks --reveal partial identically for <label>' -ForEach @(
        @{ label = 'long';  value = 'demo-key-abcdefghijklmnopqrstuvwxyz0123456789' }
        @{ label = 'short'; value = 'ab' }
        @{ label = 'unicode'; value = 'pässwörd☃日本語end' }
    ) {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret $value
        $expected = ConvertTo-CredMaskedValue -Text $value
        $r = Invoke-PyCred -CliArgs @('get', "$($p.Name)/k", '--reveal', 'partial', '-n')
        $r.ExitCode | Should -Be 0
        $r.StdOut   | Should -BeExactly $expected
    }

    It 'reports --stat identically for <label>' -ForEach @(
        @{ label = 'mixed';   value = 'Tr0ub4dor&3' }
        @{ label = 'empty';   value = '' }
        @{ label = 'unicode'; value = 'pässwörd☃日本語end' }
    ) {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret $value -AllowEmpty
        $expected = ConvertTo-CredValueStat -Text $value
        $r = Invoke-PyCred -CliArgs @('get', "$($p.Name)/k", '--stat', '-n')
        $r.ExitCode | Should -Be 0
        $r.StdOut   | Should -BeExactly $expected
    }

    It 'agrees match/no-match for --check across editions' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'pässwörd☃日本語end'
        $ok = Invoke-PyCred -CliArgs @('get', "$($p.Name)/k", '--check', '-n') -StdIn 'pässwörd☃日本語end'
        $ok.ExitCode | Should -Be 0
        $ok.StdOut   | Should -BeExactly 'match'
        $bad = Invoke-PyCred -CliArgs @('get', "$($p.Name)/k", '--check', '-n') -StdIn 'wrong'
        $bad.ExitCode | Should -Be 1
        $bad.StdOut   | Should -BeExactly 'no match'
    }
}

Describe 'Both doctors report the same rows' -Skip:(-not ($script:HasAge -and $script:HasPython)) {
    # ARCHITECTURE.md: "They now report the same rows, in the same order, and
    # differ only in the first one." Nothing checked that, which is how the
    # keystore row came to exist only in Python -- the two implementations
    # were once again answering different questions about the same machine.

    It 'agrees on every check name, and differs only in the first' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'x'

        $py = Invoke-PyCred -CliArgs @('doctor', '--path', $p.Path)
        $ps = Invoke-PsCred -CliArgs @('doctor', '--path', $p.Path)

        $pyRows = Get-DoctorCheckNames $py.StdOut
        $psRows = Get-DoctorCheckNames $ps.StdOut

        $pyRows.Count | Should -BeGreaterThan 5 -Because $py.StdOut
        $pyRows[0]    | Should -BeExactly 'python'
        $psRows[0]    | Should -BeExactly 'powershell'

        # Everything after the first row is the contract.
        (($pyRows | Select-Object -Skip 1) -join ', ') |
            Should -BeExactly (($psRows | Select-Object -Skip 1) -join ', ') `
                   -Because "python:`n$($py.StdOut)`npowershell:`n$($ps.StdOut)"
    }

    It 'reports the key protection from the file rather than the platform' {
        # Hardcoding DPAPI here labelled a systemd-creds key as DPAPI, on the
        # one report whose whole job is to say how your key is actually held.
        Get-CredIdentityProtection -Path (Get-CredIdentityInfo).Path |
            Should -BeExactly 'file-permissions'

        # Named outside CRED_HOME so it cannot become the identity cred picks.
        $wrapped = Join-Path $script:Sandbox 'foreign-key.json'
        Set-Content -LiteralPath $wrapped -Encoding Ascii -Value (
            '{"format":"cred-identity","protection":"systemd-creds-user","blob":"AA=="}')
        Get-CredIdentityProtection -Path $wrapped | Should -BeExactly 'systemd-creds-user'
    }
}
