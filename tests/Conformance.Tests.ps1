#requires -Version 5.1
<#
    Conformance tests -- both implementations against fixed bytes.

    Interop.Tests.ps1 drives the two implementations against each other, which
    proves they agree but not that either is right: a round trip passes
    whenever both sides are wrong in the same way. That is how four format
    divergences survived -- a project resolving to store.age in Python and
    store.asc in PowerShell, a write verified by length on one side and by
    content on the other, a userpass fallback naming $env:KEY here and
    $env:KEY_PASSWORD there, and a binary guard keyed off different facts.

    tests/fixtures/ is the contract as an artifact. Each implementation is an
    adapter measured against it, not against its peer. A third implementation
    in sh would use this same corpus as its conformance suite.

    Neither the key nor the ciphertext is committed. tests/fixtures/ holds the
    plaintext payload (values.json), the declaration (config.json) and the
    exact resolution each implementation must produce; the store is encrypted
    into a sandbox at setup time against a key generated there. A credentials
    tool should not ship a private key in its own repository, and the format
    divergences this corpus pins are about resolution rules, not about age's
    envelope -- which age itself guarantees.
#>

BeforeDiscovery {
    $script:HasAge = [bool](Get-Command age -ErrorAction SilentlyContinue) -or
                     (Test-Path "$env:LOCALAPPDATA\Microsoft\WinGet\Links\age.exe")
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
    $script:HasPython = [bool]$py
    # -Skip is evaluated during discovery, so this has to be resolved here.
    $IsWindowsHost = ($PSVersionTable.PSEdition -eq 'Desktop') -or
                     [bool](Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)
}

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'src\Cred\Cred.psd1') -Force

    $script:Fixtures = Join-Path $PSScriptRoot 'fixtures'

    # Build the corpus in a sandbox: a fresh key, and the committed plaintext
    # encrypted to it. The committed half stays free of anything key-shaped.
    $script:Sandbox = Join-Path ([System.IO.Path]::GetTempPath()) "credconf-$([guid]::NewGuid().ToString('N'))"
    $null = New-Item -ItemType Directory -Path $script:Sandbox -Force
    Copy-Item -Path (Join-Path $script:Fixtures '*') -Destination $script:Sandbox -Recurse -Force

    $script:Basic = Join-Path $script:Sandbox 'basic'
    $identity     = Join-Path $script:Sandbox 'identity.txt'

    $script:SavedHome = $env:CRED_HOME
    $env:CRED_HOME    = Join-Path $script:Sandbox 'home'
    $env:CRED_IDENTITY_FILE = $identity
    $null = New-CredIdentity -Path $identity
    $recipient = (Get-CredIdentityInfo -Path $identity).Recipient

    # Name the generated key as the project's recipient, then encrypt the
    # committed payload into place.
    $cfgPath = Join-Path (Join-Path $script:Basic '.creds') 'config.json'
    $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
    $cfg.recipients = @($recipient)
    Set-Content -LiteralPath $cfgPath -Encoding UTF8 -Value ($cfg | ConvertTo-Json -Depth 12)

    $payload = [System.IO.File]::ReadAllBytes((Join-Path $script:Basic 'values.json'))
    $age = (Get-Command age -ErrorAction SilentlyContinue).Source
    if (-not $age) { $age = "$env:LOCALAPPDATA\Microsoft\WinGet\Linksge.exe" }
    $storePath = Join-Path (Join-Path $script:Basic '.creds') 'store.age'
    $psiAge = [System.Diagnostics.ProcessStartInfo]::new()
    $psiAge.FileName = $age
    $psiAge.Arguments = "--encrypt --armor -r $recipient -o `"$storePath`""
    $psiAge.UseShellExecute = $false
    $psiAge.RedirectStandardInput = $true
    $procAge = [System.Diagnostics.Process]::Start($psiAge)
    $procAge.StandardInput.BaseStream.Write($payload, 0, $payload.Length)
    $procAge.StandardInput.BaseStream.Flush()
    $procAge.StandardInput.Close()
    $procAge.WaitForExit()
    if ($procAge.ExitCode -ne 0) { throw "could not build the fixture store (age exit $($procAge.ExitCode))" }

    $script:PyExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $script:PyExe) { $script:PyExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
    $script:Harness = Join-Path $PSScriptRoot 'conformance.py'
    $script:PyCli   = Join-Path $script:RepoRoot 'python\cred.py'
    $script:M       = Get-Module Cred
    function InModule { param([scriptblock]$Block, [object[]]$Argument) & $script:M $Block @Argument }


    function Get-FixtureJson {
        param([string]$Path)
        $text = [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false))
        return ConvertFrom-Json $text
    }

    function ConvertTo-Comparable {
        <#
            Both implementations emit JSON; compare the canonical text of each
            so ordering and numeric formatting cannot make an equal thing look
            unequal.
        #>
        param($Object)
        return (ConvertTo-Json $Object -Depth 12 -Compress)
    }

    function Invoke-Harness {
        param([string]$Mode, [string]$Fixture)
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName  = $script:PyExe
        $psi.UseShellExecute        = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $psi.StandardErrorEncoding  = [System.Text.UTF8Encoding]::new($false)
        # ArgumentList is .NET Core only; Windows PowerShell 5.1 is half of what
        # we support, so quote into Arguments the way Interop.Tests.ps1 does.
        $quoted = @($script:Harness, $Mode, $Fixture) |
                  ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }
        $psi.Arguments = $quoted -join ' '
        $psi.EnvironmentVariables['CRED_IDENTITY_FILE'] = $env:CRED_IDENTITY_FILE
        # Python's own stdio must be UTF-8 regardless of the console code page.
        $psi.EnvironmentVariables['PYTHONIOENCODING'] = 'utf-8'

        $proc = [System.Diagnostics.Process]::Start($psi)
        $out  = $proc.StandardOutput.ReadToEnd()
        $err  = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) { throw "conformance.py $Mode failed: $err" }
        return $out
    }

    function Invoke-PyCli {
        <#
            The shipped Python CLI, not the harness: what a registry write
            actually produces is only a contract if the real command produces
            it. Exit code included, because the codes are part of the contract.
        #>
        param([string[]]$CliArgs, [hashtable]$WithEnv = @{})

        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $script:PyExe
        $psi.UseShellExecute        = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $psi.StandardErrorEncoding  = [System.Text.UTF8Encoding]::new($false)
        $psi.EnvironmentVariables['PYTHONIOENCODING']   = 'utf-8'
        $psi.EnvironmentVariables['CRED_IDENTITY_FILE'] = $env:CRED_IDENTITY_FILE
        $psi.EnvironmentVariables.Remove('CRED_PROJECT') | Out-Null
        foreach ($k in $WithEnv.Keys) { $psi.EnvironmentVariables[$k] = $WithEnv[$k] }

        $quoted = @($script:PyCli) + $CliArgs |
                  ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }
        $psi.Arguments = $quoted -join ' '

        $p    = [System.Diagnostics.Process]::Start($psi)
        $out  = $p.StandardOutput.ReadToEnd()
        $err  = $p.StandardError.ReadToEnd()
        $p.WaitForExit()
        $code = $p.ExitCode
        $p.Dispose()
        [pscustomobject]@{ StdOut = $out; StdErr = $err; ExitCode = $code }
    }

    function Get-Utf8Text {
        param([string]$Path)
        return [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false))
    }

}

AfterAll {
    $env:CRED_IDENTITY_FILE = $null
    $env:CRED_HOME = $script:SavedHome
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'The on-disk format is a fixed contract' -Skip:(-not $script:HasAge) {

    It 'the PowerShell implementation resolves the fixture exactly as declared' {
        $expected = Get-FixtureJson (Join-Path $script:Basic 'expected.json')
        $store    = Open-CredStore -Path $script:Basic

        foreach ($key in ($expected.PSObject.Properties.Name | Sort-Object)) {
            $want = $expected.$key
            $view = $store.Entries[$key]
            $view | Should -Not -BeNullOrEmpty -Because "'$key' is in the fixture"

            $view.Kind     | Should -BeExactly $want.kind     -Because "kind of '$key'"
            $view.Display  | Should -BeExactly $want.display  -Because "display of '$key'"
            $view.FileName | Should -BeExactly $want.filename -Because "filename of '$key'"
            [bool]$view.IsBinary | Should -Be ([bool]$want.is_binary) -Because "is_binary of '$key'"

            $wantEnv = @{}
            foreach ($p in $want.env.PSObject.Properties) { $wantEnv[$p.Name] = [string]$p.Value }
            @($view.EnvVars.Keys | Sort-Object) | Should -Be @($wantEnv.Keys | Sort-Object) `
                -Because "environment variable names of '$key'"
            foreach ($n in $wantEnv.Keys) {
                [string]$view.EnvVars[$n] | Should -BeExactly $wantEnv[$n] -Because "`$env:$n"
            }

            $bytes = Get-Cred -Name $key -Path $script:Basic -AsBytes
            [Convert]::ToBase64String($bytes) | Should -BeExactly ([string]$want.bytes_b64) `
                -Because "exact bytes of '$key'"
        }
    }

    It 'sees every key the fixture declares or stores, and no others' {
        $expected = Get-FixtureJson (Join-Path $script:Basic 'expected.json')
        $store    = Open-CredStore -Path $script:Basic
        @($store.Entries.Keys | Sort-Object) |
            Should -Be @($expected.PSObject.Properties.Name | Sort-Object)
    }

    It 'injects exactly the declared environment, and skips the file credentials' {
        $expected = Get-FixtureJson (Join-Path $script:Basic 'expected-environment.json')
        $projected = Get-CredStoreEnvironment -Store (Open-CredStore -Path $script:Basic)

        $wantVars = @{}
        foreach ($p in $expected.variables.PSObject.Properties) { $wantVars[$p.Name] = [string]$p.Value }

        @($projected.Variables.Keys | Sort-Object) | Should -Be @($wantVars.Keys | Sort-Object)
        foreach ($n in $wantVars.Keys) {
            [string]$projected.Variables[$n] | Should -BeExactly $wantVars[$n] -Because "`$env:$n"
        }
        @($projected.Skipped) | Should -Be @($expected.skipped)
    }

    It 'takes the store filename from config.json rather than assuming one' {
        # This used to be a gpg project with no 'store' key, where Python
        # hardcoded store.age and PowerShell asked the provider. gpg is gone,
        # so the fixture names the file explicitly instead: an implementation
        # that assumes the default still opens the wrong file for one repo.
        $store = Open-CredStore -Path (Join-Path $script:Sandbox 'custom-store-name')
        (Split-Path -Leaf $store.Context.StorePath) | Should -BeExactly 'vault.age'
    }
}

Describe 'Both implementations agree with the fixture' -Skip:(-not ($script:HasAge -and $script:HasPython)) {

    It 'the Python implementation resolves the fixture exactly as declared' {
        $got      = Invoke-Harness -Mode 'entries' -Fixture $script:Basic | ConvertFrom-Json
        $expected = Get-FixtureJson (Join-Path $script:Basic 'expected.json')
        (ConvertTo-Comparable $got) | Should -BeExactly (ConvertTo-Comparable $expected)
    }

    It 'the Python implementation builds the same environment' {
        $got      = Invoke-Harness -Mode 'environment' -Fixture $script:Basic | ConvertFrom-Json
        $expected = Get-FixtureJson (Join-Path $script:Basic 'expected-environment.json')
        (ConvertTo-Comparable $got) | Should -BeExactly (ConvertTo-Comparable $expected)
    }

    It 'the Python implementation honours the same store filename' {
        $got = Invoke-Harness -Mode 'store-name' -Fixture (Join-Path $script:Sandbox 'custom-store-name') |
               ConvertFrom-Json
        $got.store | Should -BeExactly 'vault.age'
    }
}

Describe 'The project registry is a fixed contract' -Skip:(-not ($script:HasAge -and $script:HasPython)) {
    <#
        projects.json is written by both implementations and read by both, so
        its bytes are as much a contract as the store's. Nothing was holding
        them to it: PowerShell wrote CRLF and Python wrote LF for the same
        registry, and the same serialiser writes .creds/config.json, which is
        tracked -- so alternating editions rewrote every line of a committed
        file.
    #>

    BeforeAll {
        $script:RegRoot = Join-Path $script:Sandbox 'registry'
        $paths = @{}
        foreach ($edition in 'ps', 'py') {
            $paths[$edition] = [pscustomobject]@{
                Home    = Join-Path $script:RegRoot "$edition\home"
                Project = Join-Path $script:RegRoot "$edition\demo"
            }
            $null = New-Item -ItemType Directory -Force -Path $paths[$edition].Home
            $null = New-Item -ItemType Directory -Force -Path $paths[$edition].Project
        }

        $saved = $env:CRED_HOME
        try {
            $env:CRED_HOME = $paths['ps'].Home
            $null = Initialize-CredProject -Project 'demo' -Path $paths['ps'].Project
        }
        finally { $env:CRED_HOME = $saved }

        $r = Invoke-PyCli -CliArgs @('init', 'demo', '--path', $paths['py'].Project) `
                          -WithEnv @{ CRED_HOME = $paths['py'].Home }
        if ($r.ExitCode -ne 0) { throw "python init failed: $($r.StdErr)" }

        # Fold out the one part that legitimately differs -- the absolute path,
        # JSON-escaped as it appears in the file -- and compare everything else.
        function ConvertTo-Placeholder {
            param([string]$Text, [string]$ProjectPath)
            $escaped = $ProjectPath -replace '\\', '\\'
            return ($Text -replace [regex]::Escape($escaped), '<PATH>')
        }

        $script:PsRegistry = Get-Utf8Text (Join-Path $paths['ps'].Home 'projects.json')
        $script:PyRegistry = Get-Utf8Text (Join-Path $paths['py'].Home 'projects.json')
        $script:PsNormal   = ConvertTo-Placeholder $script:PsRegistry (Resolve-Path $paths['ps'].Project).ProviderPath
        $script:PyNormal   = ConvertTo-Placeholder $script:PyRegistry (Resolve-Path $paths['py'].Project).ProviderPath
        $script:WantReg    = (Get-Utf8Text (Join-Path $script:Fixtures 'registry\expected-projects.json')) -replace "`r`n", "`n"
    }

    It 'PowerShell writes the registry the fixture declares' {
        $script:PsNormal.TrimEnd("`n") | Should -BeExactly $script:WantReg.TrimEnd("`n")
    }

    It 'Python writes the registry the fixture declares' {
        $script:PyNormal.TrimEnd("`n") | Should -BeExactly $script:WantReg.TrimEnd("`n")
    }

    It 'both write it byte for byte the same, line endings included' {
        # Not covered by the two above: TrimEnd there would hide a disagreement
        # about the trailing newline, and neither would catch a shared CR.
        $script:PsNormal | Should -BeExactly $script:PyNormal
        $script:PsRegistry | Should -Not -Match "`r"
        $script:PyRegistry | Should -Not -Match "`r"
    }

    It 'both report a malformed registry as malformed, with the same exit code' {
        $home2 = Join-Path $script:RegRoot 'broken'
        $null  = New-Item -ItemType Directory -Force -Path $home2
        [System.IO.File]::WriteAllText((Join-Path $home2 'projects.json'), 'not json at all')

        $saved = $env:CRED_HOME
        $ps = try {
            $env:CRED_HOME = $home2
            $null = Get-CredProject
            [pscustomobject]@{ Code = 0; Message = '' }
        }
        catch { [pscustomobject]@{ Code = (Get-CredExitCode -ErrorRecord $_); Message = $_.Exception.Message } }
        finally { $env:CRED_HOME = $saved }

        $py = Invoke-PyCli -CliArgs @('project', 'list') -WithEnv @{ CRED_HOME = $home2 }

        $ps.Code | Should -Be 6 -Because 'a corrupt store is exit 6 on both sides'
        $py.ExitCode | Should -Be $ps.Code
        $ps.Message  | Should -Match 'not valid JSON'
        $py.StdErr   | Should -Match 'not valid JSON'
    }

    It 'neither reports an unreadable registry as a malformed one' -Skip:(-not $IsWindowsHost) {
        # The regression this pins: the read used to sit inside the try that
        # caught a parse failure, so an access-denied arrived as "not valid
        # JSON" and told the user to delete a perfectly good file.
        $home2 = Join-Path $script:RegRoot 'denied'
        $null  = New-Item -ItemType Directory -Force -Path $home2
        $reg   = Join-Path $home2 'projects.json'
        [System.IO.File]::WriteAllText($reg, '{"version":1,"projects":{}}')

        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $null = & icacls $reg /deny "*${sid}:(R)" 2>&1
        if ($LASTEXITCODE -ne 0) { Set-ItResult -Skipped -Because 'could not deny read on this filesystem' }

        try {
            $saved = $env:CRED_HOME
            $ps = try {
                $env:CRED_HOME = $home2
                $null = Get-CredProject
                [pscustomobject]@{ Code = 0; Message = '' }
            }
            catch { [pscustomobject]@{ Code = (Get-CredExitCode -ErrorRecord $_); Message = $_.Exception.Message } }
            finally { $env:CRED_HOME = $saved }

            $py = Invoke-PyCli -CliArgs @('project', 'list') -WithEnv @{ CRED_HOME = $home2 }

            $ps.Code     | Should -Be 1
            $py.ExitCode | Should -Be $ps.Code
            $ps.Message  | Should -Not -Match 'not valid JSON'
            $py.StdErr   | Should -Not -Match 'not valid JSON'
            $ps.Message  | Should -Match 'Cannot read'
            $py.StdErr   | Should -Match 'Cannot read'
        }
        finally { $null = & icacls $reg /remove:d "*${sid}" 2>&1 }
    }
}

Describe 'Serialised JSON is canonical on every edition' -Skip:(-not $script:HasPython) {
    <#
        The registry test above catches this only for the shapes a registry
        happens to contain. .creds/config.json is the tracked file and it
        carries the awkward ones: an array, an empty map, an empty list, a
        null, a bool, non-ASCII, and backslash and quote escapes. Both
        implementations format the same committed input, so neither is being
        compared against its own transcription of it.
    #>

    BeforeAll {
        $script:CanonDir = Join-Path $script:Fixtures 'canonical-json'
        $script:CanonIn  = Join-Path $script:CanonDir 'input.json'
        $script:CanonWant = (Get-Utf8Text (Join-Path $script:CanonDir 'expected.json')) -replace "`r`n", "`n"
    }

    It 'PowerShell reproduces the declared canonical form' {
        $compact = Get-Utf8Text $script:CanonIn
        $got = InModule { param($c) ConvertTo-CredJson -InputObject (ConvertFrom-CredJson $c) } @($compact)
        $got.TrimEnd("`n") | Should -BeExactly $script:CanonWant.TrimEnd("`n")
        $got | Should -Not -Match "`r" -Because 'json.dumps writes LF and this file is committed'
    }

    It 'Python reproduces the declared canonical form' {
        $got = Invoke-Harness -Mode 'canonical' -Fixture $script:CanonIn
        $got.TrimEnd("`n") | Should -BeExactly $script:CanonWant.TrimEnd("`n")
    }
}

Describe 'Both implementations restrict a path the same way' -Skip:(-not ($script:HasPython -and $IsWindowsHost)) {
    <#
        Permissions are a contract too, and this one was being broken quietly
        by both sides at once -- Python's icacls call removed only inherited
        ACEs, and PowerShell's Set-Acl route failed on a file whose DACL was
        already protected. Both reported success.
    #>

    It 'produces the same DACL, from the same starting ACL' {
        $dir = Join-Path $script:Sandbox 'restrict'
        $null = New-Item -ItemType Directory -Force -Path $dir

        $subjects = @{}
        foreach ($edition in 'ps', 'py') {
            $p = Join-Path $dir "$edition.bin"
            [System.IO.File]::WriteAllText($p, 'x')
            # An extra explicit ACE, the shape a file written by another logon
            # session carries. Removing it is the whole job.
            $null = & icacls $p /grant "*S-1-5-5-2-608175707:(RX)" 2>&1
            $subjects[$edition] = $p
        }

        InModule { param($p) $null = Protect-CredPath -Path $p } @($subjects['ps'])
        $got = Invoke-Harness -Mode 'restrict' -Fixture $subjects['py'] | ConvertFrom-Json
        [bool]$got.ok | Should -BeTrue -Because 'the Python side reports whether it worked'

        $sddl = @{}
        foreach ($edition in 'ps', 'py') {
            $sddl[$edition] = [System.Security.AccessControl.FileSecurity]::new(
                                  $subjects[$edition], 'Access').GetSecurityDescriptorSddlForm('Access')
        }
        $sddl['ps'] | Should -BeExactly $sddl['py']

        # And it is the right DACL, not merely the same one: protected, and
        # naming this user and nobody else.
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $sddl['ps'] | Should -BeExactly "D:PAI(A;;FA;;;$me)"
    }
}
