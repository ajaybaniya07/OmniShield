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
title OmniShield - Update
if exist "%~dp0SHA256SUMS" (
    echo Verifying release integrity...
    powershell -NoProfile -Command "Get-Content '%~dp0SHA256SUMS' | ForEach-Object { $p = $_ -split '\s+', 2; if ($p.Length -eq 2 -and (Test-Path $p[1])) { $h = (Get-FileHash -Path $p[1] -Algorithm SHA256).Hash.ToLower(); if ($h -ne $p[0].ToLower()) { Write-Host ('Integrity check FAILED for ' + $p[1]) -ForegroundColor Red; exit 1 } } }; Write-Host 'All SHA-256 hashes verified.' -ForegroundColor Green"
    if errorlevel 1 (
        echo Update aborted: file integrity check failed.
        pause
        exit /b 1
    )
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\setup-all.ps1" -UpdateOnly
if errorlevel 1 goto :has_error
goto :success

:has_error
echo.
echo ============================================================
echo  Update encountered an issue or warning.
echo  Please review the details above.
echo ============================================================
pause
exit /b 1

:success
echo.
echo ============================================================
echo  OmniShield updated successfully!
echo  Closing this window automatically...
echo ============================================================
timeout /t 3 >nul 2>&1 || ping -n 3 127.0.0.1 >nul 2>&1
exit /b 0

