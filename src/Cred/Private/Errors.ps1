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

function Get-CredExitCode {
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
