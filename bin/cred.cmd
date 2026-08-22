@echo off
REM cred -- per-repository encrypted credentials (Python implementation).
REM The PowerShell one is cred-ps.cmd; both read and write the same stores.
setlocal
where python >nul 2>&1
if %ERRORLEVEL%==0 (
    python "%~dp0..\python\cred.py" %*
) else (
    where py >nul 2>&1
    if %ERRORLEVEL%==0 (
        py -3 "%~dp0..\python\cred.py" %*
    ) else (
        echo cred: Python 3.8+ was not found. 1>&2
        echo. 1>&2
        echo Next: 1>&2
        echo   Install Python 3, or use the PowerShell implementation: cred-ps 1>&2
        exit /b 5
    )
)
exit /b %ERRORLEVEL%
