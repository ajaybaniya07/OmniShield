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
title OmniShield - Add-on Sync & Update
echo =========================================================================
echo   OmniShield: Add-on Sync & In-Place Update
echo =========================================================================
echo  Notice: INSTALL.bat now installs both Core and Add-ons in one step!
echo  Use this script to re-apply, sync, or update add-ons at any time.
echo.
if not exist "%~dp0installer\setup-all.ps1" (
  echo Error: installer\setup-all.ps1 not found in this directory.
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
