#requires -Version 5.1
<#
    Secrets.ps1 -- moving secret values between the shapes callers want.

    Honest limitation, stated once here and again in ARCHITECTURE.md: .NET
    strings are immutable and garbage collected, so a secret that becomes a
    [string] cannot be reliably scrubbed from process memory. We keep values as
    SecureString wherever we can, unmanaged-marshal them only for the moment
    they are needed, and always free the unmanaged copy. That is the ceiling for
    a PowerShell-hosted tool; anything stronger would be theatre.
#>

function ConvertFrom-CredSecureString {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Security.SecureString]$SecureString)

    $ptr = [IntPtr]::Zero
    try {
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
    }
    finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
        }
    }
}

function ConvertTo-CredSecureString {
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$PlainText)

    $ss = [System.Security.SecureString]::new()
    foreach ($c in $PlainText.ToCharArray()) { $ss.AppendChar($c) }
    $ss.MakeReadOnly()
    return $ss
}

function Resolve-CredSecretInput {
    <#
        .SYNOPSIS
        Turn whatever the caller supplied into a plain string, prompting only
        when nothing was supplied and we have a terminal.

        Accepts [string], [SecureString] or [pscredential]. Prompting keeps the
        value off the command line, which keeps it out of shell history and out
        of the Windows process list.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [object]$Value,
        [string]$Prompt = 'Secret',
        [switch]$FromStdin,
        [switch]$AllowEmpty
    )

    # "Not supplied" and "supplied as an empty string" are different intents and
    # get different treatment: the first prompts, the second is an error unless
    # the caller asked for empties.
    if ($FromStdin) {
        # Read raw bytes and decode UTF-8 ourselves rather than using
        # [Console]::In, whose encoding follows the console code page. On
        # Windows PowerShell 5.1 that is an OEM page which silently destroys
        # anything outside ASCII.
        $stdin = [Console]::OpenStandardInput()
        $buf   = [System.IO.MemoryStream]::new()
        try {
            $stdin.CopyTo($buf)
            $plain = [System.Text.Encoding]::UTF8.GetString($buf.ToArray())
        }
        finally { $buf.Dispose(); $stdin.Dispose() }

        # A trailing newline is an artefact of the pipe, not part of the secret.
        $plain = $plain -replace '\r?\n\z', ''
    }
    elseif ($null -ne $Value) {
        $plain = if ($Value -is [System.Security.SecureString]) {
            ConvertFrom-CredSecureString -SecureString $Value
        }
        elseif ($Value -is [System.Management.Automation.PSCredential]) {
            $Value.GetNetworkCredential().Password
        }
        else {
            [string]$Value
        }
    }
    else {
        if ([Console]::IsInputRedirected) {
            throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument `
                -Message 'No value was supplied and there is no terminal to prompt on.' `
                -Next @("Pipe it in:  Get-Content secret.txt | cred add <project>/<key> --stdin",
                        "Or pass it:  cred add <project>/<key> --value '<value>'   (beware shell history)"))
        }
        $ss = Read-Host -Prompt $Prompt -AsSecureString
        $plain = ConvertFrom-CredSecureString -SecureString $ss
        $ss.Dispose()
    }

    if (-not $AllowEmpty -and [string]::IsNullOrEmpty($plain)) {
        throw (New-CredErrorRecord -Code 'Usage' -Category InvalidArgument `
            -Message 'An empty value was given.' `
            -Next "Provide a value, or pass -AllowEmpty / --allow-empty if an empty string is genuinely what you want.")
    }
    return $plain
}

# Writing a secret to the real stdout handle is a CLI concern, and the CLI does
# it in Write-CredSecret (bin/cred-ps.ps1). A second copy lived here with no
# caller; a dead function that mirrors live code is a trap for the next reader.

# Everything about what a credential entry IS -- its kind, its exact bytes, the
# environment variables it becomes, the file it came from -- now lives in
# Private/Entry.ps1. This file is about turning input into a secret and back.
