#requires -Version 5.1
<#
    Concurrency tests -- the store is a single file that several processes may
    want to change at once. These run real, separate PowerShell processes; an
    in-process test would not exercise the file lock at all.
#>

BeforeDiscovery {
    $script:HasAge = [bool](Get-Command age -ErrorAction SilentlyContinue) -or
                     (Test-Path "$env:LOCALAPPDATA\Microsoft\WinGet\Links\age.exe")
}

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'src\Cred\Cred.psd1') -Force

    $script:Sandbox   = Join-Path ([System.IO.Path]::GetTempPath()) "credcc-$([guid]::NewGuid().ToString('N'))"
    $script:SavedHome = $env:CRED_HOME
    $env:CRED_HOME    = Join-Path $script:Sandbox 'home'
    $null = New-Item -ItemType Directory -Path $script:Sandbox -Force
    $null = New-CredIdentity

    $script:Pwsh = (Get-Process -Id $PID).Path

    function Start-Writer {
        <#
            Launch a separate process that adds one credential.
        #>
        param([string]$ProjectPath, [string]$Key, [string]$Value)

        $script = @"
`$ErrorActionPreference = 'Stop'
Import-Module '$($script:RepoRoot)\src\Cred\Cred.psd1' -Force
`$null = Set-Cred -Name '$Key' -Secret '$Value' -Path '$ProjectPath'
"@
        $file = Join-Path $script:Sandbox "writer-$Key.ps1"
        Set-Content -LiteralPath $file -Value $script -Encoding UTF8

        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName  = $script:Pwsh
        $psi.Arguments = "-NoProfile -NonInteractive -File `"$file`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardError = $true
        $psi.EnvironmentVariables['CRED_HOME'] = $env:CRED_HOME
        return [System.Diagnostics.Process]::Start($psi)
    }
}

AfterAll {
    $env:CRED_HOME = $script:SavedHome
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Concurrent writes' -Skip:(-not $script:HasAge) {

    It 'never loses an update when several processes write at once' {
        $dir = Join-Path $script:Sandbox 'race'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $null = Initialize-CredProject -Project 'race' -Path $dir

        $keys  = 1..6 | ForEach-Object { "k$_" }
        $procs = foreach ($k in $keys) { Start-Writer -ProjectPath $dir -Key $k -Value "value-$k" }

        foreach ($p in $procs) {
            $p.WaitForExit(120000) | Should -BeTrue -Because 'a writer should not hang on the lock'
            $err = $p.StandardError.ReadToEnd()
            $p.ExitCode | Should -Be 0 -Because "writer failed: $err"
        }

        # Every writer's value must be present: a lost update means one of them
        # read the store before another's write and then clobbered it.
        foreach ($k in $keys) {
            Get-Cred -Name $k -Path $dir | Should -Be "value-$k"
        }
        @(Get-CredList -Path $dir).Count | Should -Be $keys.Count
    }

    It 'leaves no temp or backup files behind' {
        $dir = Join-Path $script:Sandbox 'race'
        @(Get-ChildItem -LiteralPath (Join-Path $dir '.creds') -Force |
          Where-Object { $_.Name -like '*.tmp*' -or $_.Name -like '*.bak*' }).Count |
            Should -Be 0
    }

    It 'leaves an empty lock file that git ignores' {
        # The lock file persists on purpose -- see Lock-CredStore -- so the
        # thing to verify is that it is empty and excluded from the repo.
        #
        # -Force is load-bearing off Windows: PowerShell treats a dotfile as
        # hidden, so Get-Item cannot see '.lock' without it. That failure is
        # non-terminating, and the expression then yields 0, which is exactly
        # what this asserts -- so without -Force the check passed on Linux
        # while looking at nothing at all. Assert existence separately so a
        # lookup that finds nothing can never read as an empty file again.
        $creds = Join-Path (Join-Path $script:Sandbox 'race') '.creds'
        $lock  = Get-Item (Join-Path $creds '.lock') -Force
        $lock          | Should -Not -BeNullOrEmpty
        $lock.Length   | Should -Be 0
        (Get-Content (Join-Path $creds '.gitignore') -Raw) | Should -Match '\.lock'
    }

    It 'lets many readers work while a writer holds the lock' {
        $dir = Join-Path $script:Sandbox 'readers'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $null = Initialize-CredProject -Project 'readers' -Path $dir
        $null = Set-Cred -Name 'k' -Secret 'readable' -Path $dir

        $writer = Start-Writer -ProjectPath $dir -Key 'other' -Value 'x'
        try {
            # Reads take no lock and are served from the last atomically
            # replaced file, so they must succeed throughout.
            1..5 | ForEach-Object { Get-Cred -Name 'k' -Path $dir | Should -Be 'readable' }
        }
        finally {
            $null = $writer.WaitForExit(120000)
            $writer.Dispose()
        }
        Get-Cred -Name 'other' -Path $dir | Should -Be 'x'
    }

    It 'times out with an actionable message rather than hanging forever' {
        $dir = Join-Path $script:Sandbox 'locked'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $null = Initialize-CredProject -Project 'locked' -Path $dir

        $m = Get-Module Cred
        $lock = & $m { param($d) Lock-CredStore -CredsDir $d } (Join-Path $dir '.creds')
        try {
            $msg = try {
                & $m { param($d) Lock-CredStore -CredsDir $d -TimeoutMs 400 } (Join-Path $dir '.creds')
                $null
            } catch { $_.Exception.Message }

            $msg | Should -Match 'holding the write lock'
            $msg | Should -Match 'Remove-Item'
        }
        finally { $lock.Dispose() }
    }
}
