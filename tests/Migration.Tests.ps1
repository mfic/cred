#requires -Version 5.1
<#
    Migration tests -- the PSCredential boundary.

    This is where existing credentials come in and, if something else still
    needs them in the old shape, go back out. Everyday use does not touch any of
    this.
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

    $script:Sandbox   = Join-Path ([System.IO.Path]::GetTempPath()) "credmig-$([guid]::NewGuid().ToString('N'))"
    $script:SavedHome = $env:CRED_HOME
    $env:CRED_HOME    = Join-Path $script:Sandbox 'home'
    $null = New-Item -ItemType Directory -Path $script:Sandbox -Force
    $null = New-CredIdentity

    function New-TestProject {
        param([string]$Name = "m$([guid]::NewGuid().ToString('N').Substring(0,8))")
        $dir = Join-Path $script:Sandbox $Name
        $null = New-Item -ItemType Directory -Path $dir -Force
        $null = Initialize-CredProject -Project $Name -Path $dir
        [pscustomobject]@{ Name = $Name; Path = $dir }
    }

    function New-LegacyCredential {
        param([string]$Folder, [string]$File, [string]$User, [string]$Secret)
        $null = New-Item -ItemType Directory -Path $Folder -Force
        $ss = ConvertTo-CredSecureStringForTest $Secret
        if ($User) {
            [System.Management.Automation.PSCredential]::new($User, $ss) |
                Export-Clixml -LiteralPath (Join-Path $Folder $File)
        }
        else {
            $ss | Export-Clixml -LiteralPath (Join-Path $Folder $File)
        }
    }

    function ConvertTo-CredSecureStringForTest {
        param([string]$Plain)
        $ss = [System.Security.SecureString]::new()
        foreach ($c in $Plain.ToCharArray()) { $ss.AppendChar($c) }
        $ss.MakeReadOnly()
        $ss
    }
}

AfterAll {
    $env:CRED_HOME = $script:SavedHome
    Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Set-Cred -Credential' -Skip:(-not $script:HasAge) {

    It 'takes the username and the password from one object' {
        $p = New-TestProject
        $cred = [System.Management.Automation.PSCredential]::new(
                    'svc acme', (ConvertTo-CredSecureStringForTest 'p@ss ünï ☃'))

        $r = Set-Cred -Name "$($p.Name)/db" -Credential $cred
        $r.Type | Should -Be 'userpass'
        Get-Cred -Name "$($p.Name)/db" -Field user | Should -Be 'svc acme'
        Get-Cred -Name "$($p.Name)/db"             | Should -BeExactly 'p@ss ünï ☃'
    }

    It 'lets an explicit -User override the one on the object' {
        $p = New-TestProject
        $cred = [System.Management.Automation.PSCredential]::new(
                    'ignored', (ConvertTo-CredSecureStringForTest 'x'))
        $null = Set-Cred -Name "$($p.Name)/db" -Credential $cred -User 'preferred'
        Get-Cred -Name "$($p.Name)/db" -Field user | Should -Be 'preferred'
    }

    It 'round-trips out through Get-CredCredential' {
        $p = New-TestProject
        $original = [System.Management.Automation.PSCredential]::new(
                        'round tripper', (ConvertTo-CredSecureStringForTest 'secret "quoted" ünï'))
        $null = Set-Cred -Name "$($p.Name)/rt" -Credential $original

        $back = Get-CredCredential -Name "$($p.Name)/rt"
        $back.UserName | Should -Be $original.UserName
        $back.GetNetworkCredential().Password |
            Should -BeExactly $original.GetNetworkCredential().Password
    }
}

Describe 'Import-Cred' -Skip:(-not $script:HasAge) {

    It 'imports a folder of Export-Clixml credentials' {
        $p   = New-TestProject
        $old = Join-Path $script:Sandbox "old-$($p.Name)"
        New-LegacyCredential -Folder $old -File 'db.cred.xml'  -User 'svc_acme' -Secret 'p@ss w0rd ünï'
        New-LegacyCredential -Folder $old -File 'deploy.xml'   -User 'deploy'   -Secret 'deploy-secret'
        New-LegacyCredential -Folder $old -File 'token.xml'    -User ''         -Secret 'just-a-token ☃'

        $rows = @(Import-Cred -Path $old -Project $p.Name -Description 'migrated')
        @($rows | Where-Object Action -eq 'imported').Count | Should -Be 3

        # Name comes from the filename, with a .cred suffix stripped.
        Get-Cred -Name "$($p.Name)/db" -Field user | Should -Be 'svc_acme'
        Get-Cred -Name "$($p.Name)/db"     | Should -BeExactly 'p@ss w0rd ünï'
        Get-Cred -Name "$($p.Name)/deploy" | Should -BeExactly 'deploy-secret'
        # A bare SecureString has no username, so it lands as a plain secret.
        Get-Cred -Name "$($p.Name)/token"  | Should -BeExactly 'just-a-token ☃'
        (Get-CredList -Project $p.Name | Where-Object Key -eq 'token').Type | Should -Be 'secret'
    }

    It 'changes nothing with -WhatIf' {
        $p   = New-TestProject
        $old = Join-Path $script:Sandbox "whatif-$($p.Name)"
        New-LegacyCredential -Folder $old -File 'a.xml' -User 'u' -Secret 's'

        $rows = @(Import-Cred -Path $old -Project $p.Name -WhatIf)
        $rows[0].Action | Should -Be 'would import'
        @(Get-CredList -Project $p.Name).Count | Should -Be 0
    }

    It 'skips existing credentials unless -Force is given' {
        $p   = New-TestProject
        $old = Join-Path $script:Sandbox "dup-$($p.Name)"
        New-LegacyCredential -Folder $old -File 'k.xml' -User 'u' -Secret 'from-file'
        $null = Set-Cred -Name "$($p.Name)/k" -Secret 'already-here'

        $rows = @(Import-Cred -Path $old -Project $p.Name -WarningAction SilentlyContinue)
        $rows[0].Action | Should -Be 'skipped'
        Get-Cred -Name "$($p.Name)/k" | Should -Be 'already-here'

        $rows = @(Import-Cred -Path $old -Project $p.Name -Force)
        $rows[0].Action | Should -Be 'replaced'
        Get-Cred -Name "$($p.Name)/k" | Should -Be 'from-file'
    }

    It 'takes a PSCredential straight off the pipeline' {
        $p = New-TestProject
        $cred = [System.Management.Automation.PSCredential]::new(
                    'pipeline_user', (ConvertTo-CredSecureStringForTest 'piped'))
        $null = $cred | Import-Cred -Project $p.Name -Name 'piped'
        Get-Cred -Name "$($p.Name)/piped" | Should -Be 'piped'
    }

    It 'names a single file explicitly when asked' {
        $p   = New-TestProject
        $old = Join-Path $script:Sandbox "named-$($p.Name)"
        New-LegacyCredential -Folder $old -File 'awkward name.xml' -User 'u' -Secret 's'
        $null = Import-Cred -Path (Join-Path $old 'awkward name.xml') -Project $p.Name -Name 'clean'
        Get-Cred -Name "$($p.Name)/clean" | Should -Be 's'
    }

    It 'sanitises a filename that is not a usable key name' {
        $p   = New-TestProject
        $old = Join-Path $script:Sandbox "sanitise-$($p.Name)"
        New-LegacyCredential -Folder $old -File 'my creds!.xml' -User 'u' -Secret 's'
        $null = Import-Cred -Path $old -Project $p.Name
        (Get-CredList -Project $p.Name).Key | Should -Be 'my-creds-'
    }

    It 'says so and carries on when a file is not a credential' {
        $p   = New-TestProject
        $old = Join-Path $script:Sandbox "mixed-$($p.Name)"
        New-LegacyCredential -Folder $old -File 'good.xml' -User 'u' -Secret 's'
        'just some text' | Set-Content -LiteralPath (Join-Path $old 'notes.txt')
        @{ a = 1 } | Export-Clixml -LiteralPath (Join-Path $old 'hashtable.xml')

        $rows = @(Import-Cred -Path $old -Project $p.Name -WarningAction SilentlyContinue)
        @($rows | Where-Object Action -eq 'imported').Count | Should -Be 1
        (Get-CredList -Project $p.Name).Key | Should -Be 'good'
    }

    It 'explains what it was looking for when a folder holds nothing usable' {
        $p     = New-TestProject
        $empty = Join-Path $script:Sandbox "empty-$($p.Name)"
        $null  = New-Item -ItemType Directory -Path $empty -Force
        $null  = Import-Cred -Path $empty -Project $p.Name -WarningVariable w -WarningAction SilentlyContinue
        "$w" | Should -Match '\*\.xml'
    }
}

# Export-Clixml only protects a SecureString on Windows, so off Windows
# Export-Cred refuses rather than writing a file that looks encrypted and is
# not. These three assert the Windows shape and can only run there; the
# refusal itself is covered below, on the platform that does the refusing.
Describe 'Export-Cred' -Skip:(-not ($script:HasAge -and $script:OnWindows)) {

    It 'writes files PowerShell can read straight back as PSCredentials' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/db" -User 'svc acme' -Secret 'p@ss ünï ☃'
        $dest = Join-Path $script:Sandbox "export-$($p.Name)"

        $rows = @(Export-Cred -Path $dest -Project $p.Name -Confirm:$false -WarningAction SilentlyContinue)
        $rows.Count | Should -Be 1

        $back = Import-Clixml -LiteralPath $rows[0].File
        $back | Should -BeOfType [System.Management.Automation.PSCredential]
        $back.UserName | Should -Be 'svc acme'
        $back.GetNetworkCredential().Password | Should -BeExactly 'p@ss ünï ☃'
    }

    It 'exports only what was asked for' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/a" -Secret '1'
        $null = Set-Cred -Name "$($p.Name)/b" -Secret '2'
        $dest = Join-Path $script:Sandbox "partial-$($p.Name)"

        $rows = @(Export-Cred -Path $dest -Project $p.Name -Only 'a' -Confirm:$false -WarningAction SilentlyContinue)
        $rows.Count | Should -Be 1
        $rows[0].Key | Should -Be 'a'
    }

    It 'warns that the files it just wrote are a liability' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/a" -Secret '1'
        $dest = Join-Path $script:Sandbox "warn-$($p.Name)"
        $null = Export-Cred -Path $dest -Project $p.Name -Confirm:$false -WarningVariable w -WarningAction SilentlyContinue
        "$w" | Should -Match 'Delete them once the migration is done'
    }
}

Describe 'Export-Cred off Windows' -Skip:(-not ($script:HasAge -and -not $script:OnWindows)) {

    It 'refuses rather than writing a file that only looks protected' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/db" -User 'svc' -Secret 'p@ss'
        $dest = Join-Path $script:Sandbox "refuse-$($p.Name)"

        { Export-Cred -Path $dest -Project $p.Name -Confirm:$false } |
            Should -Throw -ExpectedMessage '*plain text*'

        # The refusal must come before any work: a directory of half-written
        # plaintext would be the exact thing it is refusing to produce.
        Test-Path -LiteralPath $dest | Should -BeFalse
    }

    It 'still exports when the caller says -Force, and says what that cost' {
        $p = New-TestProject
        $null = Set-Cred -Name "$($p.Name)/db" -User 'svc' -Secret 'p@ss ünï ☃'
        $dest = Join-Path $script:Sandbox "forced-$($p.Name)"

        $rows = @(Export-Cred -Path $dest -Project $p.Name -Force -Confirm:$false `
                              -WarningVariable w -WarningAction SilentlyContinue)
        $rows.Count | Should -Be 1
        "$w" | Should -Match 'Delete them once the migration is done'

        # Import-Clixml round-trips it here too -- the difference is that the
        # file it read is plaintext, which is why -Force had to be asked for.
        $back = Import-Clixml -LiteralPath $rows[0].File
        $back.UserName | Should -Be 'svc'
        $back.GetNetworkCredential().Password | Should -BeExactly 'p@ss ünï ☃'
    }
}
