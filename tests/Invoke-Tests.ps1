#requires -Version 5.1
<#
    Run the whole suite under both Windows PowerShell 5.1 and PowerShell 7.

    Run me from either edition:  .\tests\Invoke-Tests.ps1
    Run only this edition:       .\tests\Invoke-Tests.ps1 -ThisEditionOnly
#>

[CmdletBinding()]
param(
    [switch]$ThisEditionOnly,
    [ValidateSet('Normal', 'Detailed', 'Diagnostic')][string]$Output = 'Normal',
    [string]$Path
)

$ErrorActionPreference = 'Stop'
$testsDir = $PSScriptRoot
$target   = if ($Path) { $Path } else { $testsDir }

function Get-DesktopModulePath {
    <#
        The module path Windows PowerShell would have if PowerShell 7 had not
        been in the room.

        pwsh puts its own module directories on PSModulePath and every child
        process inherits them, so launching 5.1 from a 7 session -- which is
        exactly what this script does -- points 5.1 at
        $PSHOME_7\Modules. It finds PowerShell 7's builds of
        Microsoft.PowerShell.Security, PowerShellGet and PackageManagement
        there, cannot load a single one of them, and Get-Acl, Set-Acl and
        Install-Module all vanish. The 5.1 leg was not testing 5.1; it was
        testing 5.1 wearing 7's modules, and it could not even find Pester.

        The machine value is the honest one, plus the current user's own
        Windows PowerShell directory, which is where Pester 5 installs to.
    #>
    [OutputType([string])]
    param()

    $parts = [System.Collections.Generic.List[string]]::new()
    $machine = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
    if ($machine) { foreach ($p in ($machine -split ';')) { if ($p) { $parts.Add($p) } } }
    foreach ($fallback in @(
        (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'),
        (Join-Path $env:SystemRoot 'system32\WindowsPowerShell\v1.0\Modules'),
        (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules')
    )) {
        if ($parts -notcontains $fallback) { $parts.Add($fallback) }
    }
    return ($parts -join ';')
}

function Invoke-Suite {
    param([string]$Exe, [string]$Label, [string]$ModulePath)

    Write-Host ''
    Write-Host "=== $Label ===" -ForegroundColor Cyan

    $runner = @"
`$ErrorActionPreference = 'Stop'
Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
`$cfg = New-PesterConfiguration
`$cfg.Run.Path            = '$target'
`$cfg.Run.Exit            = `$true
`$cfg.Output.Verbosity    = '$Output'
`$cfg.TestResult.Enabled  = `$true
`$cfg.TestResult.OutputPath = Join-Path '$testsDir' ('results-' + `$PSVersionTable.PSEdition + '.xml')
Invoke-Pester -Configuration `$cfg
"@
    $file = Join-Path ([System.IO.Path]::GetTempPath()) "credrun-$([guid]::NewGuid().ToString('N')).ps1"
    Set-Content -LiteralPath $file -Value $runner -Encoding UTF8
    $saved = $env:PSModulePath
    try {
        if ($ModulePath) { $env:PSModulePath = $ModulePath }
        # Out-Host, not a bare call: the child's output must reach the console
        # rather than becoming this function's return value alongside the exit
        # code we actually want.
        & $Exe -NoProfile -ExecutionPolicy Bypass -File $file | Out-Host
        return $LASTEXITCODE
    }
    finally {
        $env:PSModulePath = $saved
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    }
}

$results = @{}

if ($ThisEditionOnly) {
    $results[$PSVersionTable.PSEdition] = Invoke-Suite -Exe (Get-Process -Id $PID).Path -Label "PowerShell $($PSVersionTable.PSVersion)"
}
else {
    $ps51 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path $ps51) {
        $results['Desktop'] = Invoke-Suite -Exe $ps51 -Label 'Windows PowerShell 5.1' `
                                           -ModulePath (Get-DesktopModulePath)
    }
    else {
        Write-Host 'Windows PowerShell 5.1 not present; skipping.' -ForegroundColor Yellow
    }

    $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if (-not $pwsh -and (Test-Path "$env:ProgramFiles\PowerShell\7\pwsh.exe")) {
        $pwsh = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    }
    if ($pwsh) {
        $results['Core'] = Invoke-Suite -Exe $pwsh -Label 'PowerShell 7'
    }
    else {
        Write-Host 'PowerShell 7 not present; skipping.' -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host '=== Summary ===' -ForegroundColor Cyan
$failed = $false
foreach ($k in $results.Keys) {
    $ok = ($results[$k] -eq 0)
    if (-not $ok) { $failed = $true }
    Write-Host ("  {0,-8} {1}" -f $k, $(if ($ok) { 'passed' } else { "FAILED (exit $($results[$k]))" })) `
               -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
}
if ($failed) { exit 1 }
exit 0
