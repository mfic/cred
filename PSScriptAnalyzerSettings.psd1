@{
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # Get-CredList, Get-CredRecipient, Get-CredProvider and friends return
        # collections. The plural reads correctly at the call site, which matters
        # more here than the rule.
        'PSUseSingularNouns'

        # cred writes secrets to [Console]::Out deliberately: the PowerShell
        # pipeline is captured by Start-Transcript and a secret must not be.
        # See Write-CredSecret in bin/cred-ps.ps1 and Secrets.ps1.
        'PSAvoidUsingWriteHost'

        # Systematically wrong for this codebase. Most "unused" parameters are
        # either (a) part of the provider contract, which a given backend may
        # legitimately ignore, or (b) read inside an -Mutate scriptblock, which
        # the analyzer cannot follow across the closure.
        'PSReviewUnusedParameter'

        # Fires on internal helpers -- New-CredDefinition and New-CredErrorRecord
        # construct objects and change nothing, while Update-CredStoreValues and
        # Start-CredChildProcess are called only from exported functions that
        # already implement ShouldProcess themselves.
        'PSUseShouldProcessForStateChangingFunctions'

        # Matches any parameter whose name contains "Cred" -- which in a tool
        # called cred is most of them. $CredsDir is a directory path.
        'PSAvoidUsingPlainTextForPassword'
    )

    Rules = @{
        PSPlaceOpenBrace           = @{ Enable = $true; OnSameLine = $true }
        PSUseConsistentIndentation = @{ Enable = $false }   # aligned continuations read better
    }
}
