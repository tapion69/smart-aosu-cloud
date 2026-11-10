@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0AOSU_CP_SANS_ROOT.ps1"
echo.
pause
