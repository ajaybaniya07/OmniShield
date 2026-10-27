<#  Opens OmniShield. Starts the background program first if it isn't running.  #>
$ErrorActionPreference = "Continue"
$Home_ = "C:\SecurityConsole"; $exe = "$Home_\backend\backend.exe"; $url = "http://127.0.0.1:8080"
function Test-Up { try { Invoke-RestMethod "$url/api/status" -TimeoutSec 3 | Out-Null; $true } catch { $false } }
function Wait-Key { Write-Host "`nPress Enter to close."; [void](Read-Host) }
function Get-LaunchUrl {
    $bootFile = "$Home_\config\.auth_bootstrap"
    if (Test-Path $bootFile) {
        try {
            $token = (Get-Content $bootFile -Raw).Trim()
            $res = Invoke-RestMethod "$url/api/auth/code" -Method Post -Headers @{ "Authorization" = "Bearer $token" } -TimeoutSec 3
            if ($res.code) { return "$url/#code=$($res.code)" }
        } catch { Write-Host "Handshake code exchange: $($_.Exception.Message)" -ForegroundColor DarkGray }
    }
    return $url
}

if (Test-Up) { $launch = Get-LaunchUrl; & "$PSScriptRoot\shortcut.ps1" -Open -Url $launch; exit 0 }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host "Starting OmniShield (Windows will ask for permission)..."
    try { Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -ErrorAction Stop }
    catch { Write-Host "Administrator permission is needed to start it." -ForegroundColor Red; Wait-Key }
    exit
}
if (-not (Test-Path $exe)) { Write-Host "OmniShield isn't installed yet. Double-click INSTALL.bat first." -ForegroundColor Red; Wait-Key; exit 1 }

Write-Host "Starting OmniShield..."
$svc = Get-Service SecurityConsole -ErrorAction SilentlyContinue
$task = Get-ScheduledTask -TaskName SecurityConsole -ErrorAction SilentlyContinue
if ($svc) { Start-Service SecurityConsole -ErrorAction SilentlyContinue }
elseif ($task) { Start-ScheduledTask -TaskName SecurityConsole }
else {
    $a = New-ScheduledTaskAction -Execute $exe -WorkingDirectory "$Home_\backend"
    $t = New-ScheduledTaskTrigger -AtStartup
    $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName SecurityConsole -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
    Start-ScheduledTask -TaskName SecurityConsole
}
for ($i = 0; $i -lt 30; $i++) { if (Test-Up) { Write-Host "Running. Opening it..." -ForegroundColor Green; $launch = Get-LaunchUrl; & "$PSScriptRoot\shortcut.ps1" -Open -Url $launch; exit 0 }; Start-Sleep 1 }

Write-Host "`nOmniShield didn't start. The error is below:" -ForegroundColor Red
$env:SC_HOME = $Home_
& cmd.exe /c "`"$exe`" 2>&1" | Select-Object -First 40
Write-Host "`n--- last lines of backend.log ---"
Get-Content "$Home_\logs\backend.log" -Tail 15 -ErrorAction SilentlyContinue
Write-Host "`nTake a screenshot of this window and send it in the chat." -ForegroundColor Yellow
Wait-Key
