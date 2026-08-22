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
            Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-CredFileText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
}

function Set-CredFileText {
    <#
        .SYNOPSIS
        Write text atomically: temp file in the same directory, fsync, replace.

        Callers only ever pass ciphertext or non-secret config through here, so
        the transient temp file never contains plaintext secrets.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write file')) { return }

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
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
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
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

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }
    $tmp = "$Path.tmp$PID-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    try {
        $fs = [System.IO.FileStream]::new($tmp, [System.IO.FileMode]::CreateNew,
                                          [System.IO.FileAccess]::Write,
                                          [System.IO.FileShare]::None)
        try {
            $fs.Write($Bytes, 0, $Bytes.Length)
            $fs.Flush($true)
        }
        finally { $fs.Dispose() }

        Move-CredTempIntoPlace -Temp $tmp -Destination $Path
    }
    finally {
        if (Test-Path -LiteralPath $tmp -PathType Leaf) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
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
            return @(foreach ($i in $InputObject) { ConvertTo-CredHashtable $i })
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

function ConvertTo-CredJson {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][object]$InputObject, [switch]$Compress)
    return ($InputObject | ConvertTo-Json -Depth 20 -Compress:$Compress)
}
