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
if errorlevel 1 goto :has_error
goto :success

:has_error
echo.
echo ============================================================
echo  Setup encountered an issue or warning.
echo  Please review the details above.
echo ============================================================
pause
exit /b 1

:success
echo.
echo ============================================================
echo  OmniShield installed and started successfully!
echo  Closing this window automatically...
echo ============================================================
timeout /t 3 >nul 2>&1 || ping -n 3 127.0.0.1 >nul 2>&1
exit /b 0

