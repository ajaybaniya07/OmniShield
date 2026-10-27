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
title Security Console - Fix ClamAV
echo === Repairing ClamAV (Antivirus) ===
echo.
if not exist "%~dp0installer\app\config\clamd.conf" (
  mkdir "%~dp0installer\app" 2>nul
  xcopy /E /I /Y "%~dp0config" "%~dp0installer\app\config" >nul
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { & '%~dp0installer\clamav.ps1' -Payload '%~dp0installer\payload' -App '%~dp0installer\app' -Force; Write-Host ''; Write-Host 'Done. Refresh the dashboard (Ctrl+F5).' -ForegroundColor Green } catch { Write-Host ''; Write-Host ('FAILED: ' + $_.Exception.Message) -ForegroundColor Red }"
echo.
echo ------------------------------------------------------------
echo  Finished. Read the messages above, then press any key.
echo ------------------------------------------------------------
pause >nul
