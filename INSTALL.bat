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
title OmniShield - Unified Installation (Core + Addons)
echo ============================================================
echo   OmniShield 2.0: Unified Installation (Core + Add-ons)
echo ============================================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\setup-all.ps1"
echo.
echo ------------------------------------------------------------
echo  Finished. Read the messages above, then press any key.
echo  In the dashboard press Ctrl+F5 once to load the new pages.
echo ------------------------------------------------------------
pause >nul
