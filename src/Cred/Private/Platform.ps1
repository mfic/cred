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
            $null = New-Item -ItemType Directory -Path $Path -Force -Confirm:$false
        }
    }
    $null = Protect-CredPath -Path $Path
    return $Path
}

function Test-CredKeystoreAvailable {
    <#
        .SYNOPSIS
        Can this machine wrap the identity key with an OS keystore?

        Windows: DPAPI, bound to the current user account.
        Elsewhere: not yet (Keychain and libsecret are the obvious next two),
        so the key stays a permission-restricted file.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not (Test-CredIsWindows)) { return $false }
    try {
        $null = [System.Security.Cryptography.ProtectedData]
        return $true
    }
    catch {
        try {
            Add-Type -AssemblyName System.Security -ErrorAction Stop
            $null = [System.Security.Cryptography.ProtectedData]
            return $true
        }
        catch {
            Write-Verbose "DPAPI unavailable: $($_.Exception.Message)"
            return $false
        }
    }
}

function Test-CredClixmlProtectsSecrets {
    <#
        .SYNOPSIS
        Does Export-Clixml encrypt a SecureString on this platform?

        .DESCRIPTION
        On Windows a SecureString is written as a DPAPI blob, openable only by
        the account that wrote it. Everywhere else PowerShell has no DPAPI and
        Export-Clixml writes the secret as plain text -- silently, which is why
        Export-Cred refuses without -Force there.

        Named rather than asked as `Test-CredIsWindows` at the call site,
        because the caller's question is about the format, not the platform:
        rule 3 keeps "what OS is this" in this file.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return (Test-CredIsWindows)
}

function Get-CredKeystoreName {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if (Test-CredIsWindows) { return 'dpapi-currentuser' }
    return 'none'
}

function Protect-CredSecretBytes {
    <#
        .SYNOPSIS
        Wrap bytes with the OS keystore. The result is useless to any other
        user account, and on Windows to any other machine.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [byte[]]$Entropy
    )

    if (-not (Test-CredKeystoreAvailable)) {
        throw (New-CredErrorRecord -Code 'ProviderMissing' `
            -Message 'No OS keystore is available on this platform.' `
            -Next @("Leave the key as a permission-restricted file, or",
                    "protect the key file itself with age: age -p identity.txt"))
    }
    return [System.Security.Cryptography.ProtectedData]::Protect(
        $Bytes, $Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}

function Unprotect-CredSecretBytes {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [byte[]]$Entropy
    )

    if (-not (Test-CredKeystoreAvailable)) {
        throw (New-CredErrorRecord -Code 'NoIdentity' `
            -Message 'This key is wrapped with an OS keystore that is not available here.' `
            -Next "Unwrap it on the machine and account that wrapped it: cred key unprotect")
    }
    try {
        return [System.Security.Cryptography.ProtectedData]::Unprotect(
            $Bytes, $Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    }
    catch {
        throw (New-CredErrorRecord -Code 'NoIdentity' `
            -Message 'The OS keystore refused to unwrap your key.' `
            -Next @("A DPAPI-wrapped key only opens for the Windows account that wrapped it, on that machine.",
                    "If you have moved machine or account, restore the key from your backup and re-wrap it:",
                    "  cred keygen --protect") `
            -InnerException $_.Exception)
    }
}

function Get-CredAcl {
    <#
        .SYNOPSIS
        Read a path's security descriptor without depending on Get-Acl.

        Get-Acl lives in Microsoft.PowerShell.Security, which is not guaranteed
        to autoload -- on a locked-down or sandboxed 5.1 host it simply is not
        there. FileInfo.GetAccessControl() is the .NET Framework equivalent;
        FileSystemAclExtensions is the .NET 5+ one. Try the cmdlet, then fall
        back, so file permissions work on every host we support.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (Get-Command -Name Get-Acl -ErrorAction SilentlyContinue) {
        return Get-Acl -LiteralPath $Path -ErrorAction Stop
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    return $item.GetAccessControl()
}

function Get-CredUnreadableNext {
    <#
        .SYNOPSIS
        What to tell someone whose own config file will not open for them.

        Nearly always an ownership accident rather than damage: a file written
        by an elevated shell gets the admin token's descriptor -- owner
        BUILTIN\Administrators, no ACE for the human -- and from then on the
        unelevated user cannot read it, or even read its ACL.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$Path)

    if (Test-CredIsWindows) {
        $me = if ($env:USERNAME) { $env:USERNAME } else { '<you>' }
        return @(
            "See who owns it: icacls `"$Path`""
            "Take it back:    takeown /f `"$Path`"; icacls `"$Path`" /inheritance:r /grant:r `"${me}:(F)`""
            "A file written by an elevated shell belongs to Administrators, not to you."
        )
    }
    return @(
        "See the mode:  ls -l '$Path'"
        "Take it back:  chown `"`$USER`" '$Path'; chmod 600 '$Path'"
    )
}

function Invoke-CredIcacls {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string[]]$Arguments)

    try {
        $null = & icacls @Arguments 2>&1
        return ($LASTEXITCODE -eq 0)
    }
    catch { return $false }
}

function Set-CredPrivateDacl {
    <#
        .SYNOPSIS
        Give a path a protected DACL naming only the current user's SID.
        Returns $true when it worked.

        .DESCRIPTION
        Two icacls calls, because no single one does this -- icacls rejects
        /reset and /inheritance:r in the same invocation:

            /reset                     drop every explicit ACE, back to inherited
            /inheritance:r /grant:r    drop the inherited ones, name our SID

        This replaces Set-CredAcl, which built a fresh descriptor and handed it
        to Set-Acl. That works on a file whose DACL is not yet protected, and
        fails with SeSecurityPrivilege -- a privilege an unelevated user does
        not hold -- on one that is. Since protecting a file is precisely what
        this function does, the second call on any given path failed: writing
        over an existing store, keygen on an existing key, and `doctor --repair`
        run twice all hit it. Measured across four cases (fresh file in a plain
        directory, fresh file in a protected directory, already-protected file,
        file carrying extra explicit ACEs), icacls handled all four and the
        .NET route handled three.

        Between the two calls the path carries its parent's inheritable ACEs.
        For the directories cred owns that is narrower than what it replaces,
        and a staged file is not published yet, so this does not widen
        anything.

        Peer of _windows_restrict in cred_store.py.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path)

    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    # A directory has to hand the same single ACE to whatever is created in it.
    $rights = if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) { '(OI)(CI)F' } else { '(F)' }

    if (-not (Invoke-CredIcacls -Arguments @($Path, '/reset'))) { return $false }
    return (Invoke-CredIcacls -Arguments @($Path, '/inheritance:r', '/grant:r', "*${sid}:$rights"))
}

function Protect-CredPath {
    <#
        .SYNOPSIS
        Restrict a file or directory to the current user only.

        Windows: a protected DACL naming only the current user's SID.
        Unix   : chmod 600 (files) / 700 (directories).

        Returns $true when the path is now restricted. A failure never throws
        -- an unusual ACL or a filesystem without permission support must not
        stop someone managing their secrets -- but it is reported with
        Write-Warning rather than Write-Verbose, and -Quiet is for the callers
        that will report it themselves. Verbose-only meant a failure was
        indistinguishable from success, so `cred doctor --repair` printed a
        clean table having changed nothing at all -- which is how both editions
        hid a broken permission write for as long as they did.

        Peer of restrict_path in cred_store.py.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Quiet
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $false }

    $ok     = $false
    $reason = $null
    try {
        if (Test-CredIsWindows) {
            $ok = Set-CredPrivateDacl -Path $Path
        }
        else {
            $mode = if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) { '700' } else { '600' }
            & /bin/chmod $mode $Path 2>$null
            $ok = ($LASTEXITCODE -eq 0)
        }
    }
    catch {
        $reason = $_.Exception.Message
    }

    if (-not $ok -and -not $Quiet) {
        $suffix = if ($reason) { ": $reason" } else { '.' }
        Write-Warning "Could not tighten permissions on '$Path'$suffix"
    }
    return $ok
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
            # Via Get-CredAcl, which works whether or not Get-Acl exists.
            # FileInfo.GetAccessControl() alone was removed in .NET 5+, so on
            # PowerShell 7 it threw and -- before this was noticed -- the catch
            # below turned that into a permanent, wrong "other principals can
            # read your key" warning.
            $acl = Get-CredAcl -Path $Path
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
        return ($mode -match '^.rw-------$' -or $mode -match '^drwx------$')
    }
    catch {
        # Report the reason rather than swallowing it: a check that quietly
        # fails closed produces a warning the user cannot act on.
        Write-Verbose "Could not read permissions for '$Path': $($_.Exception.Message)"
        return $false
    }
}

function Remove-CredForeignAccess {
    <#
        .SYNOPSIS
        Drop explicit grants held by anyone but the current user.

        .DESCRIPTION
        Protect-CredPath replaces this user's entry and drops inherited ones,
        but an explicit grant made to somebody else survives it -- and on a path
        whose DACL is already protected, building a fresh descriptor fails with
        SeSecurityPrivilege and is swallowed as verbose output, so
        `cred doctor --repair` silently did nothing in the one situation it
        exists for. icacls does the job either way.

        LocalSystem and Administrators are left alone: they can read anything on
        the machine anyway, so removing them buys nothing. Peer of
        drop_foreign_access in python/cred_store.py.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-CredIsWindows)) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }

    try {
        $me      = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $acl     = Get-CredAcl -Path $Path
        $foreign = @()
        foreach ($rule in $acl.Access) {
            $sid = try { $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                   catch { $null }
            if ($sid -and $sid -ne $me -and
                $sid -notin @('S-1-5-18', 'S-1-5-32-544') -and $sid -notin $foreign) {
                $foreign += $sid
            }
        }
        if (-not $foreign) { return }

        $icaclsArgs = @($Path)
        foreach ($sid in $foreign) { $icaclsArgs += @('/remove:g', "*$sid") }
        $null = Invoke-CredIcacls -Arguments $icaclsArgs
    }
    catch {
        Write-Verbose "Could not drop foreign access on '$Path': $($_.Exception.Message)"
    }
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
