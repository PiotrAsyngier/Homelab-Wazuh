@echo off
setlocal enableDelayedExpansion

:: Active Response EDR Script - Neutralizacja Mimikatz (Rule ID: 100005)
:: Lokalizacja docelowa: C:\Program Files (x86)\ossec-agent\active-response\bin\kill-mimi.cmd

:: 1. Natychmiastowe zakonczenie procesu mimikatz.exe
taskkill /F /IM mimikatz.exe /T >nul 2>&1

:: 2. Usuniecie plikow i katalogow narzedzia przy uzyciu PowerShell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path 'C:\Users\*\Downloads\*mimikatz*', 'C:\Temp\*mimikatz*' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue"

:: 3. Logowanie wykonania akcji w pliku active-responses.log
echo %date% %time% Active Response [win_kill_mimi]: Zneutralizowano proces i usunieto pliki Mimikatz (Rule 100005) >> "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

exit /b 0
