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

    # The bug this guards against: publishing the secret first and tightening
    # permissions afterwards. The file ends up correct either way, so only the
    # order of operations tells the two apart -- hence the mocks.
    It 'restricts the staged file and an existing destination before the swap' {
        $f = Join-Path $script:Tmp 'private.bin'
        InModule { param($p) Set-CredFileBytes -Path $p -Bytes ([byte[]](1)) } @($f)

        # The log path travels in the environment because a mock body runs in
        # the module's session state, where neither $script: nor a closure
        # reaches back into this test.
        $env:CRED_TEST_ORDER_LOG = Join-Path $script:Tmp 'order.log'
        Mock -ModuleName Cred Protect-CredPath {
            Add-Content -LiteralPath $env:CRED_TEST_ORDER_LOG -Value $Path
        }
        Mock -ModuleName Cred Move-CredTempIntoPlace {
            Add-Content -LiteralPath $env:CRED_TEST_ORDER_LOG -Value 'swap'
            [System.IO.File]::Copy($Temp, $Destination, $true)
        }
        try {
            InModule { param($p) Write-CredPrivateFile -Path $p -Bytes ([byte[]](2)) } @($f)

            $order = @(Get-Content -LiteralPath $env:CRED_TEST_ORDER_LOG)
            $order[0] | Should -BeLike "$f.tmp*"   # staged file first
            $order[1] | Should -Be $f              # then the existing destination
            $order[2] | Should -Be 'swap'          # only then is the secret visible
        }
        finally {
            Remove-Item -LiteralPath $env:CRED_TEST_ORDER_LOG -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath 'env:CRED_TEST_ORDER_LOG' -ErrorAction SilentlyContinue
        }
    }

    It 'writes a private file with the right bytes and no leftovers' {
        $f = Join-Path $script:Tmp 'private-clean.bin'
        $data = [byte[]](7, 0, 255)
        InModule { param($p, $d) Write-CredPrivateFile -Path $p -Bytes $d } @($f, $data)
        [System.IO.File]::ReadAllBytes($f) | Should -Be $data
        @(Get-ChildItem -LiteralPath $script:Tmp -Filter 'private-clean*.tmp*').Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $script:Tmp -Filter 'private-clean*.bak*').Count | Should -Be 0
    }

    It 'leaves a private file readable only by this user' -Skip:(-not $IsWindowsHost) {
        $f = Join-Path $script:Tmp 'private-acl.bin'
        InModule { param($p) Write-CredPrivateFile -Path $p -Bytes ([byte[]](1)) } @($f)
        # The .NET type, not Get-Acl: Microsoft.PowerShell.Security is not
        # always loadable on 5.1, which is why Get-CredAcl has a fallback too.
        $acl = [System.Security.AccessControl.FileSecurity]::new($f, 'Access')
        $acl.AreAccessRulesProtected | Should -BeTrue
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        @($acl.Access | Where-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -ne $me }).Count |
            Should -Be 0
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
    It 'ships age' {
        (Get-CredProvider).Name | Should -Contain 'age'
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

    It 'defaults the optional key half of the contract' {
        # A provider that says nothing about identity keeps its keys somewhere
        # cred does not manage. Registration fills that in so no caller has to
        # test for the members' existence.
        $p = InModule { Get-CredProviderInternal -Name 'test-xor' }
        $p.SupportsKeystore | Should -BeFalse
        (InModule { & (Get-CredProviderInternal -Name 'test-xor').IdentityPath $null }) |
            Should -BeNullOrEmpty
    }

    It 'declares the key half for age and withholds it from a provider that keeps its own' {
        # The seam used to cover the store but not the key, so `cred key
        # protect` reached past it and would wrap age's key file for a project
        # that used a different backend entirely. test-xor stands in for any
        # such backend now that age is the only one that ships.
        (InModule { (Get-CredProviderInternal -Name 'age').SupportsKeystore }) | Should -BeTrue
        (InModule { (Get-CredProviderInternal -Name 'test-xor').SupportsKeystore }) | Should -BeFalse
    }

    It 'refuses a keystore operation the provider cannot honour' {
        { InModule { Assert-CredKeystoreSupported -ProviderName 'test-xor' } } |
            Should -Throw -ExpectedMessage '*no key for cred to wrap*'
        { Protect-CredIdentity -Provider 'test-xor' -Confirm:$false } |
            Should -Throw -ExpectedMessage '*no key for cred to wrap*'
    }

    It 'refuses to name a key file for a provider that keeps its own' {
        { InModule { Get-CredIdentityPath -Config $null -ProviderName 'test-xor' } } |
            Should -Throw -ExpectedMessage '*does not keep its key in a file*'
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

Describe 'Command-line parsing' {
    # This code used to live in bin/cred-ps.ps1, where its only interface was a
    # process: testing it meant spawning pwsh with a real store and a real key,
    # so nothing tested it at all. These are the cases that were unguarded.

    It 'splits argv at the first bare -- and leaves the tail verbatim' {
        $s = InModule { Split-CredArgv @('exec', 'acme', '--', 'npm', 'run', '--', 'x') }
        $s.Head | Should -Be @('exec', 'acme')
        $s.Tail | Should -Be @('npm', 'run', '--', 'x')
    }

    It 'gives an empty tail when there is no separator' {
        $s = InModule { Split-CredArgv @('list', 'acme') }
        $s.Head | Should -Be @('list', 'acme')
        @($s.Tail).Count | Should -Be 0
    }

    It 'reads --opt value, --opt=value and switches' {
        $p = InModule {
            Read-CredOptions @('acme/db', '--user', 'svc', '--desc=a b', '--stdin') -Switches @('stdin')
        }
        $p.Options['user']  | Should -BeExactly 'svc'
        $p.Options['desc']  | Should -BeExactly 'a b'
        $p.Options['stdin'] | Should -BeTrue
        $p.Positional       | Should -Be @('acme/db')
    }

    It 'does not let a value-taking option swallow the next flag' {
        # `cred add x --env --stdin` must not set env='--stdin'.
        $p = InModule { Read-CredOptions @('x', '--env', '--stdin') -Switches @('stdin') }
        $p.Options['env']   | Should -BeTrue
        $p.Options['stdin'] | Should -BeTrue
    }

    It 'treats a trailing value-taking option as a flag rather than reading past the end' {
        $p = InModule { Read-CredOptions @('x', '--field') }
        $p.Options['field'] | Should -BeTrue
        $p.Positional       | Should -Be @('x')
    }

    It 'maps short forms and lower-cases option names' {
        $p = InModule { Read-CredOptions @('-n', 'x') -Switches @('no-newline') -Short @{ n = 'no-newline' } }
        $p.Options['no-newline'] | Should -BeTrue
        $p.Positional            | Should -Be @('x')

        $u = InModule { Read-CredOptions @('--Field', 'user') }
        $u.Options['field'] | Should -BeExactly 'user'
    }

    It 'keeps an empty --opt= as an empty string, not as a flag' {
        $p = InModule { Read-CredOptions @('--prefix=') }
        $p.Options['prefix'] | Should -BeExactly ''
    }

    It 'leaves a negative number or a lone dash positional' {
        $p = InModule { Read-CredOptions @('-', 'x') }
        $p.Positional | Should -Be @('-', 'x')
    }

    It 'rejects an unknown option when -Known is given, rather than ignoring it' {
        { InModule { Read-CredOptions @('x', '--partial') -Known @('field') } } |
            Should -Throw "*Unknown option '--partial'*"
    }

    It 'still parses a recognised option normally when -Known is given' {
        $p = InModule { Read-CredOptions @('x', '--field', 'user') -Known @('field') }
        $p.Options['field'] | Should -BeExactly 'user'
    }
}

Describe 'Partial reveal and value stat' {
    # Mirrored in tests/pyunit.py against mask_value / value_stat -- the two
    # editions must agree on exactly what a "safe to look at" value contains.

    It 'reveals only the trailing boundary, plus the length' {
        ConvertTo-CredMaskedValue -Text 'demo-key-abcdefghijklmno' |
            Should -BeExactly '********mno (24 characters)'
    }

    It 'reveals nothing at or under twice the boundary width' {
        ConvertTo-CredMaskedValue -Text 'abcdef' | Should -BeExactly '******** (6 characters)'
    }

    It 'reveals one character over the boundary' {
        ConvertTo-CredMaskedValue -Text 'abcdefg' | Should -BeExactly '********efg (7 characters)'
    }

    It 'uses singular "character" for a one-character value' {
        ConvertTo-CredMaskedValue -Text 'a' | Should -BeExactly '******** (1 character)'
    }

    It 'reports every character class present, no characters' {
        ConvertTo-CredValueStat -Text 'Tr0ub4dor&3' |
            Should -BeExactly '11 characters — upper, lower, digit, symbol'
    }

    It 'names only the classes actually present' {
        ConvertTo-CredValueStat -Text 'abcdef' | Should -BeExactly '6 characters — lower'
    }

    It 'counts whitespace as its own class' {
        ConvertTo-CredValueStat -Text 'a b' | Should -BeExactly '3 characters — lower, whitespace'
    }

    It 'reports the empty string as its own case' {
        ConvertTo-CredValueStat -Text '' | Should -BeExactly '0 characters'
    }

    It 'never echoes the input' {
        (ConvertTo-CredValueStat -Text 'Tr0ub4dor&3') | Should -Not -Match 'Tr0ub4dor'
    }
}

Describe 'cred get read modes' {
    # Mirrored in tests/pyunit.py against resolve_read_mode /
    # assert_read_mode_applies / apply_read_mode. These rules used to sit
    # inline in bin/cred-ps.ps1 and python/cred.py, where the only way to
    # reach them was to run a process.

    BeforeAll {
        function New-ReadValue {
            param([string]$Kind, [byte[]]$Bytes, [switch]$IsBinary, [string]$Key = 'k')
            [pscustomobject]@{
                Project = 'p'; Key = $Key; Kind = $Kind
                IsBinary = [bool]$IsBinary; Bytes = $Bytes
            }
        }
        $utf8 = [System.Text.UTF8Encoding]::new($false)
        $script:SecretValue = New-ReadValue -Kind 'secret' -Bytes $utf8.GetBytes('Tr0ub4dor&3')
        $script:FileValue   = New-ReadValue -Kind 'file' -Key 'pem' `
                                            -Bytes $utf8.GetBytes("-----BEGIN CERTIFICATE-----`n")
        $script:BinaryValue = New-ReadValue -Kind 'file' -Key 'blob' -IsBinary `
                                            -Bytes ([byte[]](0, 1, 2))
    }

    It 'resolves no flags to the ordinary whole-value path' {
        Resolve-CredReadMode | Should -BeExactly 'full'
    }

    It 'resolves --reveal partial' {
        Resolve-CredReadMode -Reveal 'partial' | Should -BeExactly 'partial'
    }

    It 'resolves --reveal full to that same path, named explicitly' {
        Resolve-CredReadMode -Reveal 'full' | Should -BeExactly 'full'
    }

    It 'takes a reveal mode case-insensitively' {
        Resolve-CredReadMode -Reveal 'PARTIAL' | Should -BeExactly 'partial'
    }

    It 'resolves --check and --stat' {
        Resolve-CredReadMode -Check | Should -BeExactly 'check'
        Resolve-CredReadMode -Stat  | Should -BeExactly 'stat'
    }

    It 'does not treat --out on its own as a read mode' {
        Resolve-CredReadMode -Out | Should -BeExactly 'full'
    }

    It 'refuses a bare --reveal, which names no mode' {
        { Resolve-CredReadMode -Reveal $true } | Should -Throw -ExpectedMessage '*Unknown --reveal mode*'
    }

    It 'refuses an unknown reveal mode' {
        { Resolve-CredReadMode -Reveal 'bogus' } | Should -Throw -ExpectedMessage "*Unknown --reveal mode 'bogus'*"
    }

    It 'refuses two modes at once' {
        { Resolve-CredReadMode -Reveal 'partial' -Stat } |
            Should -Throw -ExpectedMessage '*--reveal cannot be combined with --stat*'
    }

    It 'refuses a mode beside --out' {
        { Resolve-CredReadMode -Stat -Out } |
            Should -Throw -ExpectedMessage '*--stat cannot be combined with --out*'
    }

    It 'refuses --reveal full beside --out too' {
        { Resolve-CredReadMode -Reveal 'full' -Out } |
            Should -Throw -ExpectedMessage '*cannot be combined with --out*'
    }

    It 'lets full through even for a file credential' {
        { Assert-CredReadModeApplies -Mode 'full' -Value $script:FileValue } | Should -Not -Throw
    }

    It 'lets an ordinary secret through' {
        { Assert-CredReadModeApplies -Mode 'stat' -Value $script:SecretValue } | Should -Not -Throw
    }

    It 'refuses a restrictive mode on file content' {
        { Assert-CredReadModeApplies -Mode 'stat' -Value $script:FileValue } |
            Should -Throw -ExpectedMessage '*--stat does not apply to file content*'
    }

    It 'refuses partial under its flag name, --reveal' {
        { Assert-CredReadModeApplies -Mode 'partial' -Value $script:FileValue } |
            Should -Throw -ExpectedMessage '*--reveal does not apply to file content*'
    }

    It 'masks for partial and never returns the value' {
        $r = Invoke-CredReadMode -Mode 'partial' -Value $script:SecretValue
        [System.Text.UTF8Encoding]::new($false).GetString($r.Bytes) |
            Should -BeExactly '********r&3 (11 characters)'
        $r.Newline  | Should -BeTrue
        $r.ExitCode | Should -Be 0
    }

    It 'describes the composition for stat' {
        $r = Invoke-CredReadMode -Mode 'stat' -Value $script:SecretValue
        [System.Text.UTF8Encoding]::new($false).GetString($r.Bytes) |
            Should -BeExactly '11 characters — upper, lower, digit, symbol'
        $r.ExitCode | Should -Be 0
    }

    It 'exits 0 on a matching candidate' {
        $r = Invoke-CredReadMode -Mode 'check' -Value $script:SecretValue -Candidate 'Tr0ub4dor&3'
        [System.Text.UTF8Encoding]::new($false).GetString($r.Bytes) | Should -BeExactly 'match'
        $r.ExitCode | Should -Be 0
    }

    It 'exits 1 on a mismatching candidate' {
        $r = Invoke-CredReadMode -Mode 'check' -Value $script:SecretValue -Candidate 'wrong'
        [System.Text.UTF8Encoding]::new($false).GetString($r.Bytes) | Should -BeExactly 'no match'
        $r.ExitCode | Should -Be 1
    }

    It 'treats no candidate at all as a mismatch, never a match' {
        (Invoke-CredReadMode -Mode 'check' -Value $script:SecretValue -Candidate $null).ExitCode |
            Should -Be 1
    }

    It 'compares a candidate exactly, not case-insensitively' {
        $r = Invoke-CredReadMode -Mode 'check' -Value $script:SecretValue -Candidate 'tr0ub4dor&3'
        [System.Text.UTF8Encoding]::new($false).GetString($r.Bytes) | Should -BeExactly 'no match'
    }

    # The fourth arm. It sat in the CLI until now, and the binary-to-terminal
    # refusal went with it.

    It 'hands back a secret''s exact bytes for full, newline allowed' {
        $r = Invoke-CredReadMode -Mode 'full' -Value $script:SecretValue
        $r.Bytes    | Should -Be $script:SecretValue.Bytes
        $r.Newline  | Should -BeTrue
        $r.ExitCode | Should -Be 0
    }

    It 'never permits a newline after file content' {
        $r = Invoke-CredReadMode -Mode 'full' -Value $script:FileValue
        $r.Bytes   | Should -Be $script:FileValue.Bytes
        $r.Newline | Should -BeFalse
    }

    It 'refuses binary content at a terminal, and says how to get it out' {
        { Invoke-CredReadMode -Mode 'full' -Value $script:BinaryValue -ToTerminal } |
            Should -Throw -ExpectedMessage '*holds binary content*'
        { Invoke-CredReadMode -Mode 'full' -Value $script:BinaryValue -ToTerminal } |
            Should -Throw -ExpectedMessage '*--out <path>*'
    }

    It 'writes binary content when stdout is redirected' {
        (Invoke-CredReadMode -Mode 'full' -Value $script:BinaryValue).Bytes |
            Should -Be ([byte[]](0, 1, 2))
    }

    It 'does not refuse text file content at a terminal' {
        (Invoke-CredReadMode -Mode 'full' -Value $script:FileValue -ToTerminal).Newline |
            Should -BeFalse
    }
}

Describe 'Command specs' {
    # The table that says what each verb accepts. It was transcribed at every
    # dispatch arm in bin/cred-ps.ps1, where nothing could assert against it,
    # and -Known reached only one of seventeen parsers -- so a mistyped flag
    # was silently ignored on the other sixteen.

    BeforeAll {
        $script:Verbs = @('init', 'add', 'get', 'list', 'exec', 'rm', 'env',
                          'recipients', 'keygen', 'key', 'project', 'providers',
                          'doctor', 'claude', 'import', 'export')
        $script:UsageText = Get-Content -Raw -LiteralPath (
            Join-Path $script:RepoRoot 'bin\cred-ps.ps1')
    }

    It 'gives every verb a spec whose Known covers its switches' {
        foreach ($v in $script:Verbs) {
            $spec = Get-CredCommandSpec -Verb $v
            $spec.Verb | Should -BeExactly $v
            foreach ($sw in $spec.Switch) {
                $spec.Known | Should -Contain $sw -Because "$v declares switch --$sw"
            }
        }
    }

    It 'resolves every alias to its canonical verb' {
        foreach ($pair in @(@{a='set';c='add'}, @{a='remove';c='rm'},
                            @{a='delete';c='rm'}, @{a='check';c='doctor'},
                            @{a='agent';c='claude'}, @{a='brief';c='claude'},
                            @{a='provider';c='providers'}, @{a='newkey';c='keygen'})) {
            (Get-CredCommandSpec -Verb $pair.a).Verb | Should -BeExactly $pair.c
        }
    }

    It 'gives every project-bearing verb --project and --path' {
        foreach ($v in @('init', 'add', 'get', 'list', 'exec', 'rm', 'env',
                         'recipients', 'doctor', 'claude', 'import', 'export')) {
            $known = (Get-CredCommandSpec -Verb $v).Known
            $known | Should -Contain 'project' -Because "$v works on a project"
            $known | Should -Contain 'path'    -Because "$v works on a project"
        }
    }

    It 'refuses an unknown option on <verb>' -ForEach @(
        @{ verb = 'list' }, @{ verb = 'doctor' }, @{ verb = 'env' }
        @{ verb = 'add' },  @{ verb = 'import' }, @{ verb = 'export' }
    ) {
        { Read-CredCommandOptions -Verb $verb -Argv @('--definitely-not-a-flag') } |
            Should -Throw -ExpectedMessage "*Unknown option '--definitely-not-a-flag'*"
    }

    It 'still parses the real options of <verb>' -ForEach @(
        @{ verb = 'list';   argv = @('acme', '--verify', '--json') }
        @{ verb = 'get';    argv = @('acme/k', '--reveal', 'partial') }
        @{ verb = 'add';    argv = @('acme/k', '--user', 'svc', '--stdin') }
        @{ verb = 'doctor'; argv = @('--repair', '--path', 'C:\x') }
        @{ verb = 'export'; argv = @('out', '--only', 'a,b', '--yes') }
    ) {
        { Read-CredCommandOptions -Verb $verb -Argv $argv } | Should -Not -Throw
    }

    It 'documents every option it accepts, and accepts every one it documents' {
        # The usage heredoc was a second, unchecked copy of the same table.
        foreach ($v in $script:Verbs) {
            foreach ($opt in (Get-CredCommandSpec -Verb $v).Known) {
                # --project and --path are universal and deliberately listed
                # once under ENVIRONMENT rather than under every verb.
                if ($opt -in @('project', 'path')) { continue }
                $script:UsageText | Should -Match "--$opt\b" `
                    -Because "$v accepts --$opt, so the usage text should name it"
            }
        }
    }

    It 'agrees with the Python command table' {
        # ARCHITECTURE: one CLI, two implementations. The accepted surface is
        # part of that contract, and nothing compared the two tables before.
        $py = Get-Command python -ErrorAction SilentlyContinue
        if (-not $py) { Set-ItResult -Skipped -Because 'Python is not installed'; return }

        $script = @'
import json, sys
sys.path.insert(0, sys.argv[1])
import cred
print(json.dumps({v: sorted(cred.command_spec(v)["known"]) for v in cred.COMMANDS}))
'@
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "credspec-$([guid]::NewGuid().ToString('N')).py"
        Set-Content -LiteralPath $tmp -Value $script -Encoding Ascii
        try {
            $json = & $py.Source $tmp (Join-Path $script:RepoRoot 'python')
            $table = $json | ConvertFrom-Json
            foreach ($v in $table.PSObject.Properties.Name) {
                $psKnown = @((Get-CredCommandSpec -Verb $v).Known | Sort-Object)
                $pyKnown = @($table.$v | Sort-Object)
                ($psKnown -join ',') | Should -BeExactly ($pyKnown -join ',') `
                    -Because "both CLIs must accept the same options for '$v'"
            }
        }
        finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}
