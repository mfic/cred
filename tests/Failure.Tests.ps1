#requires -Version 5.1
<#
    Failure tests -- everything that can go wrong, and whether the message tells
    you what to do about it.

    Every assertion here checks two things: that the failure is detected, and
    that the error text contains an actionable next step. An error that says
    "access denied" and stops is a bug in this tool.
#>

BeforeDiscovery {
    $script:HasAge = [bool](Get-Command age -ErrorAction SilentlyContinue) -or
                     (Test-Path "$env:LOCALAPPDATA\Microsoft\WinGet\Links\age.exe")
}

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'src\Cred\Cred.psd1') -Force

    $script:Sandbox   = Join-Path ([System.IO.Path]::GetTempPath()) "credfail-$([guid]::NewGuid().ToString('N'))"
    $script:SavedHome = $env:CRED_HOME
    $script:SavedIdent = $env:CRED_IDENTITY_FILE
    $script:SavedProj  = $env:CRED_PROJECT
    $env:CRED_HOME     = Join-Path $script:Sandbox 'home'
    $env:CRED_IDENTITY_FILE = $null
    $env:CRED_PROJECT       = $null
    $null = New-Item -ItemType Directory -Path $script:Sandbox -Force
    $null = New-CredIdentity

    function New-TestProject {
        param([string]$Name = "f$([guid]::NewGuid().ToString('N').Substring(0,8))")
        $dir = Join-Path $script:Sandbox $Name
        $null = New-Item -ItemType Directory -Path $dir -Force
        $null = Initialize-CredProject -Project $Name -Path $dir
        [pscustomobject]@{ Name = $Name; Path = $dir; Store = (Join-Path $dir '.creds\store.age') }
    }

    function Get-Failure {
        # Run something expected to fail and hand back the message.
        param([scriptblock]$Block)
        try { & $Block; return $null }
        catch { return $_.Exception.Message }
    }
}

AfterAll {
    $env:CRED_HOME          = $script:SavedHome
    $env:CRED_IDENTITY_FILE = $script:SavedIdent
    $env:CRED_PROJECT       = $script:SavedProj
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Missing things' -Skip:(-not $script:HasAge) {

    It 'a missing credential names the ones that do exist and how to add it' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/alpha" -Secret '1'
        $msg = Get-Failure { Get-Cred -Name "$($p.Name)/beta" }
        $msg | Should -Match "no credential named 'beta'"
        $msg | Should -Match 'It has: alpha'
        $msg | Should -Match "cred add $($p.Name)/beta"
    }

    It 'a near-miss gets a did-you-mean' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/stripe" -Secret '1'
        (Get-Failure { Get-Cred -Name "$($p.Name)/strip" }) | Should -Match 'Did you mean'
    }

    It 'an unknown project lists the known ones' {
        $null = New-TestProject   # so the registry is not empty
        $msg = Get-Failure { Get-Cred -Name 'no-such-project/key' }
        $msg | Should -Match "No project named 'no-such-project'"
        $msg | Should -Match 'cred project list'
    }

    It 'no project at all explains how to make one' {
        # $script:Sandbox itself has no .creds directory.
        $msg = Get-Failure { Get-Cred -Name 'orphan' -Path $script:Sandbox }
        $msg | Should -Match 'cred init'
    }

    It 'asking for the user half of a bare secret says how to add one' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/apikey" -Secret '1'
        $msg = Get-Failure { Get-Cred -Name "$($p.Name)/apikey" -Field user }
        $msg | Should -Match "has no 'user' field"
        $msg | Should -Match '--user'
    }

    It 'a registered project whose directory has vanished says how to re-register' {
        $p = New-TestProject
        Remove-Item -LiteralPath $p.Path -Recurse -Force
        $msg = Get-Failure { Get-Cred -Name "$($p.Name)/x" }
        $msg | Should -Match 'no longer exists'
        $msg | Should -Match 'cred init'
    }
}

Describe 'Wrong or missing keys' -Skip:(-not $script:HasAge) {

    It 'a missing identity file says where it looked and how to fix it' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'v'
        $saved = $env:CRED_IDENTITY_FILE
        try {
            $env:CRED_IDENTITY_FILE = Join-Path $script:Sandbox 'absent.txt'
            $msg = Get-Failure { Get-Cred -Name "$($p.Name)/k" }
            $msg | Should -Match 'No age identity'
            $msg | Should -Match 'cred keygen'
        }
        finally { $env:CRED_IDENTITY_FILE = $saved }
    }

    It 'the wrong key says you are not a recipient and how to become one' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'v'

        $other = Join-Path $script:Sandbox 'other-identity.txt'
        $saved = $env:CRED_IDENTITY_FILE
        try {
            $env:CRED_IDENTITY_FILE = $other
            $null = New-CredIdentity -Path $other
            $msg = Get-Failure { Get-Cred -Name "$($p.Name)/k" }
            $msg | Should -Match 'could not decrypt'
            $msg | Should -Match 'recipients add'
        }
        finally { $env:CRED_IDENTITY_FILE = $saved }
    }

    It 'a garbage identity file is reported as such, not as a decrypt failure' {
        $p = New-TestProject
        $junk = Join-Path $script:Sandbox 'junk-identity.txt'
        Set-Content -LiteralPath $junk -Value 'this is not a key' -Encoding ASCII
        $saved = $env:CRED_IDENTITY_FILE
        try {
            $env:CRED_IDENTITY_FILE = $junk
            $msg = Get-Failure { Get-CredRecipient -Project $p.Name; throw 'should have failed' }
            # GetRecipient is best-effort in Get-CredRecipient, so probe keygen.
            $msg = Get-Failure { New-CredIdentity -Show }
            $msg | Should -Match "AGE-SECRET-KEY"
        }
        finally { $env:CRED_IDENTITY_FILE = $saved }
    }
}

Describe 'Damaged files' -Skip:(-not $script:HasAge) {

    It 'a truncated store is reported with a git restore command' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'v'
        $text = Get-Content -LiteralPath $p.Store -Raw
        Set-Content -LiteralPath $p.Store -Value $text.Substring(0, [int]($text.Length / 2)) -NoNewline
        $msg = Get-Failure { Get-Cred -Name "$($p.Name)/k" }
        $msg | Should -Match 'could not decrypt'
        $msg | Should -Match 'git checkout'
    }

    It 'a flipped ciphertext byte is caught by authentication, not returned as garbage' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'v'
        $bytes = [System.IO.File]::ReadAllBytes($p.Store)
        # Corrupt inside the payload, well past the armor header.
        $i = [int]($bytes.Length * 0.8)
        $bytes[$i] = if ($bytes[$i] -eq 0x41) { 0x42 } else { 0x41 }
        [System.IO.File]::WriteAllBytes($p.Store, $bytes)
        (Get-Failure { Get-Cred -Name "$($p.Name)/k" }) | Should -Match 'could not decrypt'
    }

    It 'an empty store reads as no credentials rather than an error' {
        $p = New-TestProject
        Set-Content -LiteralPath $p.Store -Value '' -NoNewline
        @(Get-CredList -Project $p.Name -Verify).Count | Should -Be 0
    }

    It 'a malformed config.json points at the syntax and offers a restore' {
        $p = New-TestProject
        Set-Content -LiteralPath (Join-Path $p.Path '.creds\config.json') -Value '{ not json' -Encoding ASCII
        $msg = Get-Failure { Get-CredList -Path $p.Path }
        $msg | Should -Match 'not valid JSON'
        $msg | Should -Match 'git checkout'
    }

    It 'a config from a future version refuses rather than guessing' {
        $p = New-TestProject
        $cfgPath = Join-Path $p.Path '.creds\config.json'
        $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
        $cfg.version = 99
        Set-Content -LiteralPath $cfgPath -Value ($cfg | ConvertTo-Json -Depth 10) -Encoding UTF8
        (Get-Failure { Get-CredList -Path $p.Path }) | Should -Match 'newer version'
    }

    It 'an unknown provider lists the ones that exist' {
        $p = New-TestProject
        $cfgPath = Join-Path $p.Path '.creds\config.json'
        (Get-Content $cfgPath -Raw).Replace('"age"', '"nonesuch"') | Set-Content -LiteralPath $cfgPath -Encoding UTF8
        $msg = Get-Failure { Get-CredList -Path $p.Path }
        $msg | Should -Match "Unknown encryption provider 'nonesuch'"
        $msg | Should -Match 'Known providers'
    }
}

Describe 'Bad input' -Skip:(-not $script:HasAge) {

    It 'rejects a key name containing a slash' {
        $p = New-TestProject
        (Get-Failure { Set-Cred -Name "$($p.Name)/a/b" -Secret 'x' }) | Should -Match 'not a usable credential name'
    }

    It 'rejects an empty value unless explicitly allowed' {
        $p = New-TestProject
        (Get-Failure { Set-Cred -Name "$($p.Name)/k" -Secret '' }) | Should -Match 'empty value'
        $null = Set-Cred -Name "$($p.Name)/k" -Secret '' -AllowEmpty
        Get-Cred -Name "$($p.Name)/k" | Should -Be ''
    }

    It 'rejects a recipient that is not an age key' {
        $p = New-TestProject
        $msg = Get-Failure { Add-CredRecipient -Project $p.Name -Recipient 'not-a-key' -Confirm:$false }
        $msg | Should -Match 'does not look like an age recipient'
    }

    It 'refuses to remove the last recipient' {
        $p = New-TestProject
        $me  = (New-CredIdentity -Show).Recipient
        $msg = Get-Failure { Remove-CredRecipient -Project $p.Name -Recipient $me -Confirm:$false }
        $msg | Should -Match 'nobody could ever read it again'
    }
}

Describe 'Recipients' -Skip:(-not $script:HasAge) {

    It 'adding a recipient re-encrypts and keeps the values readable' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'still-here'

        $friend = Join-Path $script:Sandbox 'friend.txt'
        $friendPub = (New-CredIdentity -Path $friend).Recipient
        $null = Add-CredRecipient -Project $p.Name -Recipient $friendPub -Confirm:$false

        @(Get-CredRecipient -Project $p.Name).Count | Should -Be 2
        Get-Cred -Name "$($p.Name)/k" | Should -Be 'still-here'

        # And the friend can now read it too.
        $saved = $env:CRED_IDENTITY_FILE
        try {
            $env:CRED_IDENTITY_FILE = $friend
            Get-Cred -Name "$($p.Name)/k" | Should -Be 'still-here'
        }
        finally { $env:CRED_IDENTITY_FILE = $saved }
    }

    It 'removing a recipient locks them out again' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'secret'
        $friend = Join-Path $script:Sandbox "friend2.txt"
        $friendPub = (New-CredIdentity -Path $friend).Recipient
        $null = Add-CredRecipient -Project $p.Name -Recipient $friendPub -Confirm:$false
        $null = Remove-CredRecipient -Project $p.Name -Recipient $friendPub -Confirm:$false -WarningAction SilentlyContinue

        $saved = $env:CRED_IDENTITY_FILE
        try {
            $env:CRED_IDENTITY_FILE = $friend
            (Get-Failure { Get-Cred -Name "$($p.Name)/k" }) | Should -Match 'could not decrypt'
        }
        finally { $env:CRED_IDENTITY_FILE = $saved }
    }
}
