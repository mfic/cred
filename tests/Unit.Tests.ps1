#requires -Version 5.1
<#
    Unit tests -- pure functions and file plumbing. No crypto backend needed.
#>

BeforeDiscovery {
    # -Skip is evaluated during discovery, so this has to be resolved here.
    # PSScriptAnalyzer flags this as unused because it cannot see the -Skip: use.
    $IsWindowsHost = ($PSVersionTable.PSEdition -eq 'Desktop') -or
                     [bool](Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)
}

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'src\Cred\Cred.psd1') -Force

    # Reach into the module to test the private helpers directly. This is a
    # deliberate choice: the private layer is where the portability landmines
    # are, and testing it only through the public surface would leave them
    # covered by accident rather than on purpose.
    $script:M = Get-Module Cred
    # Note the parameter is NOT called $Args: that name is automatic in every
    # PowerShell scope and would silently swallow the values.
    function InModule { param([scriptblock]$Block, [object[]]$Argument) & $script:M $Block @Argument }
}

Describe 'Module manifest' {
    It 'is a valid manifest' {
        { Test-ModuleManifest (Join-Path $script:RepoRoot 'src\Cred\Cred.psd1') -ErrorAction Stop } |
            Should -Not -Throw
    }

    # Test-ModuleManifest rather than Import-PowerShellDataFile: the latter does
    # not exist on Windows PowerShell 5.1, which is half of what we support.
    It 'exports exactly what the manifest declares' {
        $manifest = Test-ModuleManifest (Join-Path $script:RepoRoot 'src\Cred\Cred.psd1')
        $declared = @($manifest.ExportedFunctions.Keys) | Sort-Object
        $actual   = @((Get-Command -Module Cred -CommandType Function).Name) | Sort-Object
        $declared | Should -Be $actual
    }

    It 'declares support for both editions' {
        $manifest = Test-ModuleManifest (Join-Path $script:RepoRoot 'src\Cred\Cred.psd1')
        $manifest.CompatiblePSEditions | Should -Contain 'Desktop'
        $manifest.CompatiblePSEditions | Should -Contain 'Core'
    }

    It 'gives every exported function help with an example' {
        foreach ($f in (Get-Command -Module Cred -CommandType Function)) {
            $help = Get-Help $f.Name -ErrorAction SilentlyContinue
            $help.Synopsis | Should -Not -BeNullOrEmpty -Because "$($f.Name) needs a synopsis"
        }
    }
}

Describe 'Windows argument quoting' {
    It 'leaves a simple token alone' {
        InModule { ConvertTo-CredWindowsArgumentString -ArgumentList @('run', 'build') } |
            Should -Be 'run build'
    }

    It 'quotes a token containing spaces' {
        InModule { ConvertTo-CredWindowsArgumentString -ArgumentList @('a b') } |
            Should -Be '"a b"'
    }

    It 'escapes embedded double quotes' {
        InModule { ConvertTo-CredWindowsArgumentString -ArgumentList @('say "hi"') } |
            Should -Be '"say \"hi\""'
    }

    It 'leaves a trailing backslash alone when the token needs no quoting' {
        # Outside quotes a backslash is literal, so quoting here would be wrong.
        InModule { ConvertTo-CredWindowsArgumentString -ArgumentList @('c:\dir\', 'x') } |
            Should -Be 'c:\dir\ x'
    }

    It 'doubles a trailing backslash when the token must be quoted' {
        # Inside quotes, \" would escape the closing quote, so it has to double.
        InModule { ConvertTo-CredWindowsArgumentString -ArgumentList @('c:\my dir\') } |
            Should -Be '"c:\my dir\\"'
    }

    It 'round-trips through the real Windows command line parser' -Skip:(-not $IsWindowsHost) {
        # The definitive check. Build the command line ourselves, hand it to
        # CreateProcess as a raw string, and see whether the child's own
        # CommandLineToArgvW reconstructs the original array element for
        # element. Anything less than this is guessing.
        $original = @('plain', 'with space', 'quote"inside', 'trailing\', 'a\"b')
        $line     = InModule { param($a) ConvertTo-CredWindowsArgumentString -ArgumentList $a } @(, $original)

        $probe = Join-Path ([System.IO.Path]::GetTempPath()) "credprobe-$([guid]::NewGuid().ToString('N')).ps1"
        Set-Content -LiteralPath $probe -Value 'foreach ($a in $args) { [Console]::Out.WriteLine("<$a>") }' -Encoding ASCII
        try {
            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            $psi.FileName  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            $psi.Arguments = "-NoProfile -NonInteractive -File `"$probe`" $line"
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            $out = $p.StandardOutput.ReadToEnd()
            $p.WaitForExit()

            $seen = @($out -split "`r?`n" | Where-Object { $_ -match '^<.*>$' } |
                      ForEach-Object { $_.Substring(1, $_.Length - 2) })
            $seen | Should -Be $original
        }
        finally { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'JSON and file plumbing' {
    BeforeAll { $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) "credtest-$([guid]::NewGuid().ToString('N'))" }
    AfterAll  { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }

    It 'writes UTF-8 without a byte order mark' {
        $f = Join-Path $script:Tmp 'a.txt'
        InModule { param($p) Set-CredFileText -Path $p -Text 'hällo ☃' } @($f)
        $bytes = [System.IO.File]::ReadAllBytes($f)
        $bytes[0] | Should -Not -Be 0xEF
        [System.Text.Encoding]::UTF8.GetString($bytes) | Should -Be 'hällo ☃'
    }

    It 'overwrites an existing file atomically and leaves no temp files behind' {
        $f = Join-Path $script:Tmp 'b.txt'
        InModule { param($p) Set-CredFileText -Path $p -Text 'first' } @($f)
        InModule { param($p) Set-CredFileText -Path $p -Text 'second' } @($f)
        Get-Content -LiteralPath $f -Raw | Should -Be 'second'
        @(Get-ChildItem -LiteralPath $script:Tmp -Filter '*.tmp*').Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $script:Tmp -Filter '*.bak*').Count | Should -Be 0
    }

    It 'round-trips bytes exactly' {
        $f = Join-Path $script:Tmp 'c.bin'
        $data = [byte[]](0, 1, 2, 255, 254, 10, 13)
        InModule { param($p, $d) Set-CredFileBytes -Path $p -Bytes $d } @($f, $data)
        [System.IO.File]::ReadAllBytes($f) | Should -Be $data
    }

    It 'converts nested JSON into ordered hashtables on both editions' {
        $h = InModule { ConvertFrom-CredJson '{"a":{"b":[1,2]},"c":"x"}' }
        $h.a.b[1] | Should -Be 2
        $h.c      | Should -Be 'x'
        $h.a      | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
    }

    It 'serialises deeper than the default depth of 2' {
        $deep = InModule { ConvertFrom-CredJson '{"a":{"b":{"c":{"d":{"e":"deep"}}}}}' }
        $json = InModule { param($o) ConvertTo-CredJson $o } @($deep)
        $json | Should -Match 'deep'
    }
}

Describe 'Reference parsing' {
    It 'splits <ref> into project <project> and key <key>' -ForEach @(
        @{ ref = 'proj/key';  project = 'proj'; key = 'key' }
        @{ ref = 'key';       project = $null;  key = 'key' }
        @{ ref = 'proj/';     project = 'proj'; key = $null }
        @{ ref = '/key';      project = $null;  key = 'key' }
    ) {
        $r = InModule { param($x) Split-CredReference -Reference $x } @($ref)
        $r.Project | Should -Be $project
        $r.Key     | Should -Be $key
    }

    It 'accepts <name> as a key name: <ok>' -ForEach @(
        @{ name = 'db';          ok = $true }
        @{ name = 'stripe.live'; ok = $true }
        @{ name = 'a_b-c.1';     ok = $true }
        @{ name = '';            ok = $false }
        @{ name = '.hidden';     ok = $false }
        @{ name = 'has space';   ok = $false }
        @{ name = 'a/b';         ok = $false }
    ) {
        InModule { param($n) Test-CredKeyName $n } @($name) | Should -Be $ok
    }
}

Describe 'Error records' {
    It 'carries a code that maps to an exit code' {
        $code = InModule {
            $r = New-CredErrorRecord -Code 'NoCredential' -Message 'nope'
            Get-CredExitCode -ErrorRecord $r
        }
        $code | Should -Be 3
    }

    It 'falls back to 1 for anything unrecognised' {
        InModule { Get-CredExitCode -ErrorRecord $null } | Should -Be 1
    }

    It 'appends the next steps to the message' {
        $msg = InModule {
            (New-CredErrorRecord -Code 'Usage' -Message 'broke' -Next @('do this', 'then that')).Exception.Message
        }
        $msg | Should -Match 'Next:'
        $msg | Should -Match 'do this'
        $msg | Should -Match 'then that'
    }
}

Describe 'SecureString handling' {
    It 'round-trips a value including unicode and quotes' {
        $original = 'p@ss "w0rd" ünï ☃'
        $back = InModule {
            param($v)
            $ss = ConvertTo-CredSecureString -PlainText $v
            ConvertFrom-CredSecureString -SecureString $ss
        } @($original)
        $back | Should -Be $original
    }

    It 'handles an empty string' {
        InModule { ConvertFrom-CredSecureString -SecureString (ConvertTo-CredSecureString -PlainText '') } |
            Should -Be ''
    }
}

Describe 'Provider contract' {
    It 'ships age and gpg' {
        (Get-CredProvider).Name | Should -Contain 'age'
        (Get-CredProvider).Name | Should -Contain 'gpg'
    }

    It 'rejects a provider missing part of the contract' {
        { Register-CredProvider -Provider ([pscustomobject]@{ Name = 'broken' }) -Confirm:$false } |
            Should -Throw -ExpectedMessage '*missing*'
    }

    It 'accepts and uses a complete custom provider' {
        # A deliberately trivial backend (ROT-ish XOR) that proves the seam is
        # real: nothing outside Providers.ps1 knows what encryption means.
        $fake = [pscustomobject]@{
            Name = 'test-xor'; Summary = 'test only'; StoreFileName = 'store.xor'
            InstallHint = 'n/a'
            Test         = { [pscustomobject]@{ Available = $true; Path = ''; Detail = 'always' } }
            NewIdentity  = { param($p) [pscustomobject]@{ Path = $p; Recipient = 'xor1' } }
            GetRecipient = { param($c) 'xor1' }
            Encrypt      = { param($b, $c) ,[byte[]]@($b | ForEach-Object { $_ -bxor 0x5A }) }
            Decrypt      = { param($b, $p, $c) ,[byte[]]@($b | ForEach-Object { $_ -bxor 0x5A }) }
        }
        Register-CredProvider -Provider $fake -Confirm:$false
        (Get-CredProvider -Name 'test-xor').Available | Should -BeTrue
    }
}

Describe 'Confirmation does not leak downstream' {
    # The bug this guards against: passing -Confirm to a cmdlet sets
    # $ConfirmPreference = 'Low' for its whole call stack, so one confirmed
    # `cred rm` went on to ask separately about writing config.json, deleting
    # its own backup file and scrubbing a variable. Every public function that
    # gates on ShouldProcess must reset the preference once its own question
    # has been answered. See ARCHITECTURE.md, 'Confirmation belongs to one
    # question'.
    It 'resets $ConfirmPreference in every function that supports ShouldProcess' {
        $offenders = @()
        foreach ($file in Get-ChildItem (Join-Path $script:RepoRoot 'src\Cred\Public') -Filter '*.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            $functions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
            foreach ($fn in $functions) {
                $body = $fn.Extent.Text
                if ($body -notmatch 'SupportsShouldProcess') { continue }
                if ($body -notmatch '\$ConfirmPreference\s*=') { $offenders += $fn.Name }
            }
        }
        $offenders | Should -BeNullOrEmpty
    }

    It 'leaves no backup or temp file for a prompt to have blocked on' {
        # The prompts the user saw were about .bak and .tmp files the atomic
        # write creates and then deletes. If one survives a write, the cleanup
        # did not run -- which is exactly what a swallowed prompt looks like.
        $path = Join-Path ([System.IO.Path]::GetTempPath()) "credconf-$([guid]::NewGuid().ToString('N')).json"
        try {
            InModule { param($p) Set-CredFileText -Path $p -Text 'first' -Confirm:$false } -Argument @($path)
            InModule { param($p) Set-CredFileText -Path $p -Text 'second' -Confirm:$false } -Argument @($path)
            Get-Content -LiteralPath $path -Raw | Should -BeExactly 'second'
            # Nothing beside it. -Filter is not used here: on Windows a
            # trailing '.*' pattern also matches the bare name.
            $leaf = Split-Path -Leaf $path
            @(Get-ChildItem -Path (Split-Path -Parent $path) -File |
                Where-Object { $_.Name -like "$leaf.*" }) | Should -BeNullOrEmpty
        }
        finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    }
}
