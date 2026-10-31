taskkill /F /IM mimikatz.exe
powershell.exe -ExecutionPolicy Bypass -command "Remove-Item -Path 'C:\mimikatz*' -Recurse -Force"
pause
