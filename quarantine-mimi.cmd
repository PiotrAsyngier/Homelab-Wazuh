@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
if defined WAZUH_PYTHON set "PYTHON=%WAZUH_PYTHON%"
if not defined PYTHON set "PYTHON=py.exe"

"%PYTHON%" "%SCRIPT_DIR%quarantine-mimi.py"
exit /b %ERRORLEVEL%
