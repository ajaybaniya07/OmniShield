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
title Security Console - Update
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
echo.
echo ------------------------------------------------------------
echo  Finished. Read the messages above, then press any key.
echo ------------------------------------------------------------
pause >nul
