@echo off
REM cred-ps -- the PowerShell implementation. The default `cred` is Python.
REM Prefers PowerShell 7; falls back to Windows PowerShell 5.1.
setlocal
set "CRED_SCRIPT=%~dp0cred-ps.ps1"
where pwsh.exe >nul 2>&1
if %ERRORLEVEL%==0 (
    pwsh.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CRED_SCRIPT%" %*
) else if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" (
    "%ProgramFiles%\PowerShell\7\pwsh.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CRED_SCRIPT%" %*
) else (
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CRED_SCRIPT%" %*
)
exit /b %ERRORLEVEL%
