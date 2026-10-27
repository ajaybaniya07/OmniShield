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
title Security Console - Install add-on 1.9
echo === Security Console add-on 1.9: User activity, Security checkup and VirusTotal ===
echo.
if not exist "%~dp0installer\setup-all.ps1" (
  echo This folder doesn't contain Security Console 1.7.
  echo Extract the add-on into your Security Console folder, for example C:\Build\SecurityConsole, and run this again.
  pause
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\apply-addon.ps1"
if errorlevel 1 (
  echo.
  echo The add-on couldn't be connected. Read the message above.
  pause
  exit /b
)
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\setup-all.ps1" -UpdateOnly
echo.
echo ------------------------------------------------------------
echo  Finished. Read the messages above, then press any key.
echo  In the dashboard press Ctrl+F5 once to load the new pages.
echo ------------------------------------------------------------
pause >nul
