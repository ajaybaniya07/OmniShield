@echo off
setlocal
set "SC_SELF=%~f0"
net session >nul 2>&1
if errorlevel 1 goto :elevate
goto :main

:elevate
echo Asking Windows for administrator permission...
powershell -NoProfile -Command "try { Start-Process -FilePath $env:SC_SELF -Verb RunAs -ErrorAction Stop } catch { Write-Host 'Administrator permission is required.' -ForegroundColor Red; exit 1 }"
if errorlevel 1 pause
exit /b

:main
cd /d "%~dp0"
title Security Console - Uninstall
echo This removes Security Console (C:\SecurityConsole, including history, quarantine and blocked programs).
echo.
choice /C YN /M "Continue"
if errorlevel 2 exit /b
echo.
choice /C YN /M "Also remove ClamAV, osquery and Sysmon"
set "EXTRA="
if not errorlevel 2 set "EXTRA=-RemoveTools"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\uninstall.ps1" %EXTRA%
echo.
echo Done. Press any key to close.
pause >nul
