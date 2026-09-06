#requires -Version 5.1
<#
    Json.ps1 -- UTF-8 (no BOM) file I/O and JSON helpers that behave the same
    on Windows PowerShell 5.1 and PowerShell 7.

    Why this exists: 5.1's Set-Content -Encoding UTF8 writes a BOM, its
    ConvertTo-Json defaults to -Depth 2, and it has no -AsHashtable. All three
    silently corrupt a config file. Route everything through here.
#>

$script:CredUtf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Move-CredTempIntoPlace {
    <#
        .SYNOPSIS
        Swap a freshly written temp file into place atomically.

        File.Replace is the atomic primitive on NTFS and preserves the
        destination's ACL, but every overload demands a backup path -- passing
        $null through PowerShell's marshalling arrives as an empty string. So we
        name a backup next to the file and delete it immediately afterwards.
        If we die in between, what is left behind is the *previous* contents,
        which is the safe direction to fail in.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Temp,
        [Parameter(Mandatory)][string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
        [System.IO.File]::Move($Temp, $Destination)
        return
    }
    $backup = "$Destination.bak$PID-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    try {
        [System.IO.File]::Replace($Temp, $Destination, $backup, $true)
    }
    finally {
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            Remove-Item -LiteralPath $backup -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Get-CredFileText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
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

function Read-CredTextFile {
    <#
        .SYNOPSIS
        Get-CredFileText, but an I/O failure reports itself as one.

        Every caller parses JSON out of the result. Leaving the read inside the
        caller's try meant an access-denied arrived as "not valid JSON", whose
        advice is to delete the file -- so the cure for a permission bit was to
        destroy a perfectly good registry. A missing file is rethrown untouched;
        callers have their own words for that.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$What
    )

    try { return Get-CredFileText -Path $Path }
    catch {
        # A .NET method throws through PowerShell wrapped in a
        # MethodInvocationException; the real cause is underneath.
        $ex = $_.Exception
        while ($ex -is [System.Management.Automation.MethodInvocationException] -and $ex.InnerException) {
            $ex = $ex.InnerException
        }
        if ($ex -is [System.IO.FileNotFoundException] -or $ex -is [System.IO.DirectoryNotFoundException]) {
            throw
        }
        throw (New-CredErrorRecord -Code 'Unreadable' -Category PermissionDenied -Target $Path `
            -Message "Cannot read the $What at '$Path': $($ex.Message)" `
            -Next (Get-CredUnreadableNext -Path $Path) -InnerException $ex)
    }
}

function Set-CredFileText {
    <#
        .SYNOPSIS
        Write text atomically: temp file in the same directory, fsync, replace.

        Callers only ever pass ciphertext or non-secret config through here, so
        the transient temp file never contains plaintext secrets. Anything that
        *is* a secret goes through Write-CredPrivateFileText instead, which pays
        for the permission work this one skips.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write file')) { return }

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force -Confirm:$false
    }
    $tmp = "$Path.tmp$PID-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    try {
        $bytes = $script:CredUtf8NoBom.GetBytes($Text)
        $fs = [System.IO.FileStream]::new($tmp, [System.IO.FileMode]::CreateNew,
                                          [System.IO.FileAccess]::Write,
                                          [System.IO.FileShare]::None)
        try {
            $fs.Write($bytes, 0, $bytes.Length)
            $fs.Flush($true)          # flush to the physical disk
        }
        finally { $fs.Dispose() }

        Move-CredTempIntoPlace -Temp $tmp -Destination $Path
    }
    finally {
        if (Test-Path -LiteralPath $tmp -PathType Leaf) {
            Remove-Item -LiteralPath $tmp -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function New-CredStagedFile {
    <#
        .SYNOPSIS
        Write bytes to a temp file beside Path and return the temp path.

        Split out from Set-CredFileBytes so a caller can inspect what it is
        about to publish -- Write-CredStoreValues decrypts the staged file to
        prove it is readable before that file becomes the store.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force -Confirm:$false
    }
    $tmp = "$Path.tmp$PID-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    $fs = [System.IO.FileStream]::new($tmp, [System.IO.FileMode]::CreateNew,
                                      [System.IO.FileAccess]::Write,
                                      [System.IO.FileShare]::None)
    try {
        $fs.Write($Bytes, 0, $Bytes.Length)
        $fs.Flush($true)
    }
    finally { $fs.Dispose() }
    return $tmp
}

function Set-CredFileBytes {
    <#
        .SYNOPSIS
        Atomic byte-exact write. Used for ciphertext, which may be binary
        depending on the provider.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write file')) { return }

    $tmp = New-CredStagedFile -Path $Path -Bytes $Bytes
    try   { Move-CredTempIntoPlace -Temp $tmp -Destination $Path }
    finally {
        if (Test-Path -LiteralPath $tmp -PathType Leaf) {
            Remove-Item -LiteralPath $tmp -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Write-CredPrivateFile {
    <#
        .SYNOPSIS
        Atomic byte-exact write of secret material, to a file only this user
        can read.

        Set-CredFileBytes with the permission work done in the one order that
        leaves no window:

          1. Restrict the staged file, which nothing has published yet.
          2. Restrict the destination if it already exists. Move-CredTempIntoPlace
             lands on File.Replace there, and Replace keeps the *destination's*
             ACL -- so tightening it after the swap would leave the new secret
             sitting under the old file's permissions until we got to it.
          3. Swap. The bytes become visible already restricted, either way.

        Peer of write_private_file in cred_store.py.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes
    )

    $tmp = New-CredStagedFile -Path $Path -Bytes $Bytes
    try {
        # -Quiet on the two attempts before the swap: the one after it is the
        # published file, and that is the only one worth warning about.
        $null = Protect-CredPath -Path $tmp -Quiet
        if (Test-Path -LiteralPath $Path -PathType Leaf) { $null = Protect-CredPath -Path $Path -Quiet }
        Move-CredTempIntoPlace -Temp $tmp -Destination $Path

        # Protect-CredPath is best effort by design. If it failed on the staged
        # file, this is the published file's second chance.
        $null = Protect-CredPath -Path $Path
    }
    finally {
        if (Test-Path -LiteralPath $tmp -PathType Leaf) {
            Remove-Item -LiteralPath $tmp -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Write-CredPrivateFileText {
    <#
        .SYNOPSIS
        Write-CredPrivateFile for text. UTF-8, no BOM, same as Set-CredFileText.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )

    Write-CredPrivateFile -Path $Path -Bytes $script:CredUtf8NoBom.GetBytes($Text)
}

function ConvertTo-CredHashtable {
    <#
        .SYNOPSIS
        Recursively turn ConvertFrom-Json output into ordered hashtables so the
        same manipulation code works on 5.1 and 7.
    #>
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)][object]$InputObject)

    process {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IDictionary]) {
            $out = [ordered]@{}
            foreach ($k in $InputObject.Keys) { $out[[string]$k] = ConvertTo-CredHashtable $InputObject[$k] }
            return $out
        }
        if ($InputObject -is [psobject] -and $InputObject.PSObject.TypeNames -contains 'System.Management.Automation.PSCustomObject') {
            $out = [ordered]@{}
            foreach ($p in $InputObject.PSObject.Properties) { $out[$p.Name] = ConvertTo-CredHashtable $p.Value }
            return $out
        }
        if ($InputObject -is [string]) { return $InputObject }
        if ($InputObject -is [System.Collections.IEnumerable]) {
            # The comma matters. `return @(...)` from a process block hands the
            # array to the pipeline, which unrolls it: an empty array emits
            # nothing at all and arrives as $null, and a one-element array
            # arrives as the bare element. That is why "recipients": [] used to
            # come back as null and get rewritten as null, and why both
            # Read-CredConfig and Write-CredConfig carry an @() around
            # recipients to put the array back afterwards.
            return ,@(foreach ($i in $InputObject) { ConvertTo-CredHashtable $i })
        }
        return $InputObject
    }
}

function ConvertFrom-CredJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    return (ConvertTo-CredHashtable ($Json | ConvertFrom-Json))
}

function Format-CredJson {
    <#
        .SYNOPSIS
        Re-indent compact JSON into the canonical two-space form.

        .DESCRIPTION
        ConvertTo-Json's pretty printer is not the same program on the two
        editions. PowerShell 7 indents by two and writes "key": value;
        Windows PowerShell 5.1 indents by four, puts two spaces after the
        colon, and hangs nested objects off the key's column, which for the
        same registry is 176 bytes against 82. -Compress, on the other hand,
        agrees everywhere -- same escaping, same number formatting -- so the
        compact form is the common ground and the layout is ours to impose.

        Matches json.dumps(indent=2) on the Python side, empty containers
        included: those stay on one line as {} and [].
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Compact)

    $sb     = [System.Text.StringBuilder]::new()
    $depth  = 0
    $inStr  = $false
    $esc    = $false

    for ($i = 0; $i -lt $Compact.Length; $i++) {
        $ch = $Compact[$i]

        if ($inStr) {
            $null = $sb.Append($ch)
            if     ($esc)        { $esc = $false }
            elseif ($ch -eq '\') { $esc = $true }
            elseif ($ch -eq '"') { $inStr = $false }
            continue
        }

        switch ($ch) {
            '"' { $inStr = $true; $null = $sb.Append($ch) }
            ':' { $null = $sb.Append(': ') }
            ',' { $null = $sb.Append(',').Append("`n").Append('  ' * $depth) }
            { $_ -eq '{' -or $_ -eq '[' } {
                $close = if ($ch -eq '{') { '}' } else { ']' }
                if ($i + 1 -lt $Compact.Length -and $Compact[$i + 1] -eq $close) {
                    $null = $sb.Append($ch).Append($close)   # {} and [] stay inline
                    $i++
                }
                else {
                    $depth++
                    $null = $sb.Append($ch).Append("`n").Append('  ' * $depth)
                }
            }
            { $_ -eq '}' -or $_ -eq ']' } {
                $depth--
                $null = $sb.Append("`n").Append('  ' * $depth).Append($ch)
            }
            default { $null = $sb.Append($ch) }
        }
    }
    return $sb.ToString()
}

function ConvertTo-CredJson {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][object]$InputObject, [switch]$Compress)

    # Always serialise compact, then lay it out ourselves. Two reasons the
    # edition's own pretty printer will not do: 5.1 and 7 disagree about
    # indentation entirely, and both emit CRLF on Windows where json.dumps
    # emits LF. .creds/config.json is meant to be committed, so either
    # difference turns a switch of edition into a rewrite of every line.
    $json = $InputObject | ConvertTo-Json -Depth 20 -Compress
    if ($Compress) { return $json }
    return (Format-CredJson -Compact $json)
}
