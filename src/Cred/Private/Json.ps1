#requires -Version 5.1
<#
    Json.ps1 -- JSON that behaves the same on Windows PowerShell 5.1 and
    PowerShell 7, and formats identically to Python's json.dumps.

    Why this exists: 5.1's ConvertTo-Json defaults to -Depth 2 and truncates
    deeper structures without a word, and ConvertFrom-Json has no -AsHashtable.
    Both silently corrupt a config file. Route every conversion through here.

    File I/O moved to FileIo.ps1; the advice for a file that will not open is
    in Platform.ps1, because it names icacls and chmod.
#>

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
