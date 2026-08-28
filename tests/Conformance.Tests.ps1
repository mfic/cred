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
