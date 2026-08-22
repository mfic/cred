#requires -Version 5.1
<#
    Process.ps1 -- run an external binary with bytes on stdin and bytes on
    stdout, never touching the filesystem and never putting a secret on a
    command line.

    This is the single choke point through which plaintext leaves or enters the
    module. Everything here works identically on .NET Framework 4.x
    (PowerShell 5.1) and modern .NET (PowerShell 7).
#>

function Invoke-CredProcess {
    <#
        .SYNOPSIS
        Run FilePath with ArgumentList, piping InputBytes to stdin.

        .OUTPUTS
        [pscustomobject] ExitCode, StdOut (byte[]), StdErr (string)

        .NOTES
        stdout and stderr are drained on background tasks so a large payload
        cannot deadlock against our stdin write.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [byte[]]$InputBytes,
        [hashtable]$Environment,
        [int]$TimeoutSeconds = 120
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = $FilePath
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true

    if ($psi.PSObject.Properties['ArgumentList'] -and $null -ne $psi.ArgumentList) {
        foreach ($a in $ArgumentList) { $psi.ArgumentList.Add([string]$a) }
    }
    else {
        $psi.Arguments = ConvertTo-CredWindowsArgumentString -ArgumentList $ArgumentList
    }

    if ($Environment) {
        foreach ($k in $Environment.Keys) {
            $psi.EnvironmentVariables[[string]$k] = [string]$Environment[$k]
        }
    }

    # Keep a byte order mark out of the child's stdin.
    #
    # .NET builds Process.StandardInput as a StreamWriter over Console.InputEncoding
    # and sets AutoFlush, which writes that encoding's preamble to the pipe the
    # moment the property is first touched -- before anything we write to
    # BaseStream. On a UTF-8 console (chcp 65001, which plenty of people set so
    # that Unicode works at all) that preamble is EF BB BF, and age quite
    # correctly rejects a file that starts with three junk bytes.
    #
    # PowerShell 7 can say so declaratively. Windows PowerShell 5.1 has no such
    # property, so we swap the console encoding for a preamble-free one of the
    # same code page for the duration of the call.
    $utf8NoBom     = [System.Text.UTF8Encoding]::new($false)
    $savedInputEnc = $null
    if ($psi.PSObject.Properties['StandardInputEncoding']) {
        $psi.StandardInputEncoding = $utf8NoBom
    }
    elseif ([Console]::InputEncoding.GetPreamble().Length -gt 0) {
        try {
            $savedInputEnc = [Console]::InputEncoding
            [Console]::InputEncoding = $utf8NoBom
        }
        catch {
            $savedInputEnc = $null
            Write-Verbose "Could not clear the console input preamble: $($_.Exception.Message)"
        }
    }

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $outBuf = [System.IO.MemoryStream]::new()
    $errBuf = [System.IO.MemoryStream]::new()

    try {
        if (-not $proc.Start()) {
            throw (New-CredErrorRecord -Code 'ProviderMissing' `
                -Message "Failed to start '$FilePath'." `
                -Next "Confirm the executable exists and is on PATH.")
        }

        $outTask = $proc.StandardOutput.BaseStream.CopyToAsync($outBuf)
        $errTask = $proc.StandardError.BaseStream.CopyToAsync($errBuf)

        try {
            if ($InputBytes -and $InputBytes.Length -gt 0) {
                $proc.StandardInput.BaseStream.Write($InputBytes, 0, $InputBytes.Length)
                $proc.StandardInput.BaseStream.Flush()
            }
        }
        catch [System.IO.IOException] {
            # Child exited before consuming all input (e.g. bad arguments).
            # Its stderr is the useful signal; fall through and report that.
            Write-Verbose "stdin closed early by '$FilePath'."
        }
        finally {
            $proc.StandardInput.Close()
        }

        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            try { $proc.Kill() } catch { Write-Verbose "Kill failed: $($_.Exception.Message)" }
            throw (New-CredErrorRecord -Code 'General' `
                -Message "'$FilePath' did not finish within $TimeoutSeconds seconds." `
                -Next "Run 'cred doctor' to check the encryption backend.")
        }

        [void]$outTask.Wait(10000)
        [void]$errTask.Wait(10000)

        # age appends a "report unexpected or unhelpful errors at ..." line to
        # every failure. It is noise inside our own message, which already ends
        # with concrete next steps.
        $stderr = ([System.Text.Encoding]::UTF8.GetString($errBuf.ToArray()) -split "`r?`n" |
                   Where-Object { $_ -notmatch 'report unexpected or unhelpful errors' }) -join ' '

        return [pscustomobject]@{
            ExitCode = $proc.ExitCode
            StdOut   = $outBuf.ToArray()
            StdErr   = $stderr.Trim()
        }
    }
    finally {
        $outBuf.Dispose()
        $errBuf.Dispose()
        $proc.Dispose()
        if ($savedInputEnc) {
            try { [Console]::InputEncoding = $savedInputEnc } catch { Write-Verbose 'Could not restore console input encoding.' }
        }
    }
}

function Start-CredChildProcess {
    <#
        .SYNOPSIS
        Run a command with extra environment variables, inheriting this
        console's stdin/stdout/stderr, and return its exit code.

        Nothing is redirected: the child talks straight to the terminal, so its
        output never passes through our pipeline and never lands in a
        PowerShell transcript because of us.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][string]$Command,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory)][hashtable]$Environment,
        [string]$WorkingDirectory
    )

    $resolved = Get-Command -Name $Command -CommandType Application -ErrorAction SilentlyContinue |
                Select-Object -First 1
    $exe  = if ($resolved) { $resolved.Source } else { $Command }
    $argv = @($ArgumentList)
    $rawArguments = $null

    # CreateProcess cannot execute a batch file; hand those to cmd.exe.
    if ((Test-CredIsWindows) -and $exe -match '\.(cmd|bat)$') {
        $line = ConvertTo-CredWindowsArgumentString -ArgumentList (@($exe) + $argv)
        $exe  = "$env:SystemRoot\System32\cmd.exe"
        $argv = $null
        $rawArguments = "/s /c `"$line`""
    }

    if (-not (Get-Command -Name $exe -ErrorAction SilentlyContinue) -and
        -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw (New-CredErrorRecord -Code 'CommandFailed' -Category ObjectNotFound -Target $Command `
            -Message "Command not found: '$Command'." `
            -Next @("Check the spelling, or give a full path.",
                    "Everything after '--' is run verbatim: cred exec <project> -- <command> [args]"))
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName        = $exe
    $psi.UseShellExecute = $false
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }

    if ($rawArguments) {
        $psi.Arguments = $rawArguments
    }
    elseif ($psi.PSObject.Properties['ArgumentList'] -and $null -ne $psi.ArgumentList) {
        foreach ($a in $argv) { $psi.ArgumentList.Add([string]$a) }
    }
    else {
        $psi.Arguments = ConvertTo-CredWindowsArgumentString -ArgumentList $argv
    }

    foreach ($k in $Environment.Keys) {
        $psi.EnvironmentVariables[[string]$k] = [string]$Environment[$k]
    }

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    try {
        $null = $proc.Start()
        $proc.WaitForExit()
        return $proc.ExitCode
    }
    catch [System.ComponentModel.Win32Exception] {
        throw (New-CredErrorRecord -Code 'CommandFailed' -Target $Command `
            -Message "Could not run '$Command': $($_.Exception.Message)" `
            -Next "Check that it is an executable this shell can start.")
    }
    finally {
        $proc.Dispose()
    }
}

function Resolve-CredExecutable {
    <#
        .SYNOPSIS
        Find an external command, honouring an explicit override path.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$OverridePath
    )

    if ($OverridePath) {
        if (Test-Path -LiteralPath $OverridePath -PathType Leaf) {
            return (Resolve-Path -LiteralPath $OverridePath).ProviderPath
        }
        return $null
    }

    $cmd = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue |
           Select-Object -First 1
    if ($cmd) { return $cmd.Source }

    # winget "Links" shims are not always on PATH in a fresh non-login shell.
    if ((Test-CredIsWindows) -and $env:LOCALAPPDATA) {
        $shim = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\$Name.exe"
        if (Test-Path -LiteralPath $shim -PathType Leaf) { return $shim }
    }
    return $null
}
