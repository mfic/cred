#requires -Version 5.1
<#
    Errors.ps1 -- every failure the user can hit says what to do next.

    Rule for this file: an error message never contains a secret value. It may
    name a project or a credential key (those live in plaintext config anyway),
    never a value, and never the contents of an identity file.
#>

# Code -> process exit code. The CLI maps these; the module only throws codes.
$script:CredExitCodes = @{
    'Ok'              = 0
    'General'         = 1
    'Usage'           = 2
    'NoProject'       = 3
    'NoCredential'    = 3
    'NoIdentity'      = 4
    'DecryptFailed'   = 4
    'ProviderMissing' = 5
    'StoreCorrupt'    = 6
    'StoreLocked'     = 7
    'CommandFailed'   = 8
}

function New-CredErrorRecord {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [string[]]$Next,
        [System.Management.Automation.ErrorCategory]$Category = 'InvalidOperation',
        [object]$Target,
        [System.Exception]$InnerException
    )

    $text = $Message
    if ($Next) {
        $text += [Environment]::NewLine + [Environment]::NewLine + 'Next:'
        foreach ($n in $Next) { $text += [Environment]::NewLine + '  ' + $n }
    }

    $ex = if ($InnerException) {
        [System.InvalidOperationException]::new($text, $InnerException)
    } else {
        [System.InvalidOperationException]::new($text)
    }

    $record = [System.Management.Automation.ErrorRecord]::new($ex, "Cred.$Code", $Category, $Target)
    # Stash the code where the CLI can find it without parsing the message.
    $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($text)
    Add-Member -InputObject $record -NotePropertyName CredCode -NotePropertyValue $Code -Force
    return $record
}

function New-CredBinaryContentError {
    <#
        .SYNOPSIS
        The refusal every text-shaped read path gives for a binary credential.

        .DESCRIPTION
        Three callers ask the same question -- Get-Cred, Get-CredCredential and
        the CLI's 'get' -- and the answer has to name the same two escape
        hatches every time, or the user learns one of them and not the other.
        Noun is what the caller was about to pretend the bytes were.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)][string]$ProjectName,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Noun
    )

    return (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument -Target $Key `
        -Message "'$ProjectName/$Key' holds binary content, which is not $Noun." `
        -Next @("Write it to a file: Export-CredFile $ProjectName/$Key -OutFile <path>",
                "Or from the CLI:    cred get $ProjectName/$Key --out <path>"))
}

function Get-CredExitCode {
    <#
        .SYNOPSIS
        The process exit code for an error this module threw.

        .DESCRIPTION
        Exported because the CLI needs it. It used to be private, so
        bin/cred-ps.ps1 carried its own copy of the table and the module's
        version had no caller outside the tests. One table, one place to
        change it.

        Anything unrecognised is 1, so a new code cannot silently become a
        success.

        .EXAMPLE
        try { Get-Cred acme-api/db } catch { exit (Get-CredExitCode -ErrorRecord $_) }
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([object]$ErrorRecord)

    $code = $null
    if ($ErrorRecord) {
        if ($ErrorRecord.PSObject.Properties['CredCode']) { $code = $ErrorRecord.CredCode }
        elseif ($ErrorRecord.FullyQualifiedErrorId -match '^Cred\.([A-Za-z]+)') { $code = $Matches[1] }
    }
    if ($code -and $script:CredExitCodes.ContainsKey($code)) { return $script:CredExitCodes[$code] }
    return 1
}
