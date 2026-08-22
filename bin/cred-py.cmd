@echo off
REM cred-py -- the Python implementation of cred, for cmd.exe and PATHEXT.
setlocal
where python >nul 2>&1
if %ERRORLEVEL%==0 (
    python "%~dp0..\python\cred.py" %*
) else (
    py -3 "%~dp0..\python\cred.py" %*
)
exit /b %ERRORLEVEL%
