#requires -Version 5.1

function Invoke-CredCommand {
    <#
        .SYNOPSIS
        Run a command with a project's credentials injected as environment
        variables.

        .DESCRIPTION
        The child process inherits this console's stdin, stdout and stderr, so
        it behaves exactly as if you had typed it yourself. Nothing is written
        to disk and the variables exist only for the lifetime of that process.

        The command's exit code becomes this function's $LASTEXITCODE and, via
        the CLI, the exit code of `cred exec`.

        .EXAMPLE
        Invoke-CredCommand acme-api -Command npm -ArgumentList run, deploy

        .EXAMPLE
        cred exec acme-api -- psql -h db01 -U $env:DB_USER
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Position = 0)][string]$Project,
        [Parameter(Mandatory)][string]$Command,
        [string[]]$ArgumentList = @(),
        [string[]]$Only,
        [string[]]$Exclude,
        [string]$Prefix,
        [string]$Path,
        [switch]$PassThru
    )

    # One decryption gives both the variables and the file credentials left
    # out of them, so saying what was skipped costs nothing extra.
    $store = Open-CredStore -Project $Project -Path $Path
    $ctx   = $store.Context
    $projected = Get-CredStoreEnvironment -Store $store -Only $Only -Exclude $Exclude -Prefix $Prefix
    $secrets   = $projected.Variables
    if ($projected.Skipped.Count -gt 0) {
        [Console]::Error.WriteLine(
            "Not injected (file credentials): $($projected.Skipped -join ', '). " +
            "Read one with: cred get $($ctx.Name)/$($projected.Skipped[0]) --out <path>")
    }

    # Start from this process's environment so the child still sees PATH etc.
    $envTable = @{}
    foreach ($e in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $envTable[[string]$e.Key] = [string]$e.Value
    }
    foreach ($k in $secrets.Keys) { $envTable[$k] = $secrets[$k] }

    # Breadcrumbs so a child (a script, or a Claude Code session) knows which
    # project it was handed without being able to see anything extra.
    $envTable['CRED_PROJECT']      = $ctx.Name
    $envTable['CRED_PROJECT_ROOT'] = $ctx.Root
    $envTable['CRED_INJECTED']     = (@($secrets.Keys) | Sort-Object) -join ','

    Write-Verbose "Injecting $($secrets.Count) variable(s) into '$Command'."

    $exit = Start-CredChildProcess -Command $Command -ArgumentList $ArgumentList `
                                   -Environment $envTable -WorkingDirectory (Get-Location).ProviderPath

    $global:LASTEXITCODE = $exit
    if ($PassThru) { return $exit }
}
