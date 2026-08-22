#requires -Version 5.1
<#
    Keystore tests -- wrapping the age key with the OS keystore.

    The property that matters: after wrapping, the key is not recoverable from
    the file on disk, and everything still works.
#>

BeforeDiscovery {
    $script:HasAge = [bool](Get-Command age -ErrorAction SilentlyContinue) -or
                     (Test-Path "$env:LOCALAPPDATA\Microsoft\WinGet\Links\age.exe")
    $script:OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or
                        [bool](Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)
}

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'src\Cred\Cred.psd1') -Force

    $script:Sandbox    = Join-Path ([System.IO.Path]::GetTempPath()) "credks-$([guid]::NewGuid().ToString('N'))"
    $script:SavedHome  = $env:CRED_HOME
    $script:SavedIdent = $env:CRED_IDENTITY_FILE
    $env:CRED_HOME     = Join-Path $script:Sandbox 'home'
    $env:CRED_IDENTITY_FILE = $null
    $null = New-Item -ItemType Directory -Path $script:Sandbox -Force
    $null = New-CredIdentity

    $script:Proj = Join-Path $script:Sandbox 'ksproj'
    $null = New-Item -ItemType Directory -Path $script:Proj -Force
    $null = Initialize-CredProject -Project 'ksproj' -Path $script:Proj
    $null = Set-Cred -Name 'ksproj/before' -Secret 'set-before-wrapping ünï ☃'
}

AfterAll {
    $env:CRED_HOME          = $script:SavedHome
    $env:CRED_IDENTITY_FILE = $script:SavedIdent
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Keystore' -Skip:(-not ($script:HasAge -and $script:OnWindows)) {

    It 'reports the keystore as available on Windows' {
        (Get-CredIdentityInfo).KeystoreAvailable | Should -BeTrue
    }

    It 'starts out as a plain permission-restricted key file' {
        $i = Get-CredIdentityInfo
        $i.Protection | Should -Be 'file-permissions'
        $i.Private    | Should -BeTrue
    }

    It 'wraps the key, and the secret key is no longer anywhere on disk' {
        $before = Get-CredIdentityInfo
        $keyText = Get-Content -LiteralPath $before.Path -Raw
        $keyText | Should -Match 'AGE-SECRET-KEY-'

        $r = Protect-CredIdentity -Confirm:$false -Force
        $r.Changed    | Should -BeTrue
        $r.Protection | Should -Be 'dpapi-currentuser'

        # The old plaintext file is gone...
        Test-Path -LiteralPath $before.Path | Should -BeFalse
        # ...and no file under the cred home holds the key any more.
        foreach ($f in (Get-ChildItem -LiteralPath $env:CRED_HOME -Recurse -File -Force)) {
            [System.IO.File]::ReadAllText($f.FullName) | Should -Not -Match 'AGE-SECRET-KEY-'
        }
    }

    It 'keeps the public key identical across the wrap' {
        (Get-CredIdentityInfo).Recipient |
            Should -Be (Get-CredRecipient -Project 'ksproj' | Select-Object -First 1).Recipient
    }

    It 'still reads credentials written before wrapping' {
        Get-Cred -Name 'ksproj/before' | Should -BeExactly 'set-before-wrapping ünï ☃'
    }

    It 'still writes, using an identity that never becomes a file' {
        $null = Set-Cred -Name 'ksproj/after' -Secret 'set-while-wrapped ☃'
        Get-Cred -Name 'ksproj/after' | Should -BeExactly 'set-while-wrapped ☃'
    }

    It 'leaves no staged ciphertext or temp files behind' {
        @(Get-ChildItem -LiteralPath (Join-Path $script:Proj '.creds') -Force |
          Where-Object { $_.Name -like '*.tmp*' -or $_.Name -like '*.bak*' }).Count |
            Should -Be 0
    }

    It 'detects wrapping by content, not by filename' {
        $info = Get-CredIdentityInfo
        $copy = Join-Path $script:Sandbox 'renamed-key.txt'
        Copy-Item -LiteralPath $info.Path -Destination $copy
        $m = Get-Module Cred
        (& $m { param($p) Test-CredIdentityIsWrapped -Path $p } $copy) | Should -BeTrue
    }

    It 'unwraps back to a plaintext key that still works' {
        $r = Unprotect-CredIdentity -Confirm:$false -WarningAction SilentlyContinue
        $r.Changed | Should -BeTrue
        (Get-CredIdentityInfo).Protection | Should -Be 'file-permissions'
        Get-Cred -Name 'ksproj/after' | Should -BeExactly 'set-while-wrapped ☃'
    }

    It 'is idempotent in both directions' {
        (Unprotect-CredIdentity -Confirm:$false -WarningAction SilentlyContinue).Changed | Should -BeFalse
        $null = Protect-CredIdentity -Confirm:$false -Force
        (Protect-CredIdentity -Confirm:$false -Force).Changed | Should -BeFalse
        $null = Unprotect-CredIdentity -Confirm:$false -WarningAction SilentlyContinue
    }

    It 'keeps an optional backup of the unwrapped key when asked' {
        $backup = Join-Path $script:Sandbox 'key-backup.txt'
        $null = Protect-CredIdentity -Confirm:$false -Backup $backup -WarningAction SilentlyContinue
        Test-Path $backup | Should -BeTrue
        (Get-Content -LiteralPath $backup -Raw) | Should -Match 'AGE-SECRET-KEY-'
        $null = Unprotect-CredIdentity -Confirm:$false -WarningAction SilentlyContinue
    }
}
