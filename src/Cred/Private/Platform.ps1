#requires -Version 5.1
<#
    Platform.ps1 -- every OS-specific decision in the module lives here.

    Porting note: this is the only file that should need to know whether it is
    running on Windows. Keep it that way.
#>

$script:CredIsWindowsCache = $null

function Test-CredIsWindows {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    # $IsWindows only exists on PowerShell 6+. On 5.1 we are always on Windows.
    if ($null -eq $script:CredIsWindowsCache) {
        $script:CredIsWindowsCache =
            if ($PSVersionTable.PSEdition -eq 'Desktop') { $true }
            else { [bool](Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue) }
    }
    return $script:CredIsWindowsCache
}

function Get-CredHomeDirectory {
    <#
        .SYNOPSIS
        Per-user configuration root: identity key, project registry, settings.

        Precedence: $env:CRED_HOME > platform default.
        Windows default : %APPDATA%\cred
        Unix default    : ${XDG_CONFIG_HOME:-$HOME/.config}/cred
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($env:CRED_HOME) { return [System.IO.Path]::GetFullPath($env:CRED_HOME) }

    if (Test-CredIsWindows) {
        $base = $env:APPDATA
        if (-not $base) { $base = Join-Path $HOME 'AppData\Roaming' }
        return (Join-Path $base 'cred')
    }

    $base = $env:XDG_CONFIG_HOME
    if (-not $base) { $base = Join-Path $HOME '.config' }
    return (Join-Path $base 'cred')
}

function New-CredDirectory {
    <#
        .SYNOPSIS
        Create a directory (if needed) and lock it down to the current user.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, 'Create directory')) {
            $null = New-Item -ItemType Directory -Path $Path -Force
        }
    }
    Protect-CredPath -Path $Path
    return $Path
}

function Protect-CredPath {
    <#
        .SYNOPSIS
        Restrict a file or directory to the current user only.

        Windows: disable ACL inheritance and grant FullControl to the current
                 SID exclusively.
        Unix   : chmod 600 (files) / 700 (directories).

        Best effort by design -- an unusual ACL or a filesystem without
        permission support must not stop the user from managing secrets, so
        failures are reported as verbose output rather than thrown.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    try {
        if (Test-CredIsWindows) {
            $item = Get-Item -LiteralPath $Path -Force
            $me   = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

            # Build a fresh security descriptor rather than editing the existing
            # one. Set-Acl then applies only the sections we touched -- the DACL
            # -- so we never attempt an owner change, which needs a privilege we
            # may not hold and would fail the whole call.
            $acl = if ($item.PSIsContainer) {
                [System.Security.AccessControl.DirectorySecurity]::new()
            } else {
                [System.Security.AccessControl.FileSecurity]::new()
            }
            $acl.SetAccessRuleProtection($true, $false)   # protected, drop inherited ACEs

            $inherit = if ($item.PSIsContainer) {
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
            } else {
                [System.Security.AccessControl.InheritanceFlags]::None
            }
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                $me,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow))

            Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
        }
        else {
            $mode = if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) { '700' } else { '600' }
            & /bin/chmod $mode $Path 2>$null
        }
    }
    catch {
        Write-Verbose "Could not tighten permissions on '$Path': $($_.Exception.Message)"
    }
}

function Test-CredPathIsPrivate {
    <#
        .SYNOPSIS
        True when a path is readable only by the current user (best effort).
        Used by Test-CredHealth; never used to gate an operation.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        if (Test-CredIsWindows) {
            $acl = (Get-Item -LiteralPath $Path -Force).GetAccessControl()
            $me  = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            foreach ($rule in $acl.Access) {
                $sid = try { $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                       catch { $null }
                # LocalSystem and Administrators can read anything anyway;
                # their presence is not a finding.
                if ($sid -and $sid -ne $me -and $sid -notin @('S-1-5-18', 'S-1-5-32-544')) {
                    return $false
                }
            }
            return $true
        }
        $mode = (& /bin/sh -c "ls -ld '$Path' | cut -c1-10") 2>$null
        return ($mode -match '^.rwx?-{6}$' -or $mode -match '^.rw-------$' -or $mode -match '^drwx------$')
    }
    catch { return $false }
}

function ConvertTo-CredWindowsArgumentString {
    <#
        .SYNOPSIS
        Join an argument array into a single Windows command line.

        PowerShell 5.1 targets .NET Framework, which has no
        ProcessStartInfo.ArgumentList, so we implement the CommandLineToArgvW
        quoting rules ourselves. PowerShell 7 uses ArgumentList directly and
        never calls this.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string[]]$ArgumentList)

    if (-not $ArgumentList) { return '' }

    $parts = foreach ($a in $ArgumentList) {
        $s = [string]$a
        if ($s.Length -gt 0 -and $s -notmatch '[\s"]') {
            $s
        }
        else {
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.Append('"')
            for ($i = 0; $i -lt $s.Length; $i++) {
                $slashes = 0
                while ($i -lt $s.Length -and $s[$i] -eq '\') { $slashes++; $i++ }
                if ($i -eq $s.Length) {
                    [void]$sb.Append([string]::new([char]'\', $slashes * 2))  # escape trailing \
                    break
                }
                if ($s[$i] -eq '"') {
                    [void]$sb.Append([string]::new([char]'\', $slashes * 2 + 1))
                    [void]$sb.Append('"')
                }
                else {
                    [void]$sb.Append([string]::new([char]'\', $slashes))
                    [void]$sb.Append($s[$i])
                }
            }
            [void]$sb.Append('"')
            $sb.ToString()
        }
    }
    return ($parts -join ' ')
}
