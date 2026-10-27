#Requires -RunAsAdministrator
<#
  OmniShield - installer. Normally started by INSTALL.bat.
  Every step runs even if an earlier one fails; problems are listed at the end.
  Exit code = number of steps that had problems.
#>
param([switch]$SkipSysmon, [switch]$NoBrowser, [int]$Port = 8080, [switch]$Pause)
$ErrorActionPreference = "Stop"
$Problems = [System.Collections.Generic.List[string]]::new()
$Here    = $PSScriptRoot
$Payload = Join-Path $Here "payload"
$App     = Join-Path $Here "app"
$Home_   = "C:\SecurityConsole"
$LogFile = Join-Path $env:TEMP "SecurityConsole-install.log"
$url     = "http://127.0.0.1:$Port"
Start-Transcript -Path $LogFile -Force | Out-Null

function Step($n, $msg) { Write-Host "`n[$n/9] $msg" -ForegroundColor Cyan }
function Run($name, [scriptblock]$body) {
    try { & $body } catch { Write-Host "   FAILED: $($_.Exception.Message)" -ForegroundColor Red; $script:Problems.Add("${name}: $($_.Exception.Message)") }
}
function Msi($file) {
    if (-not (Test-Path $file)) { throw "$file is missing" }
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$file`" /qn /norestart"
    if ($p.ExitCode -notin 0, 1638, 3010) { throw "$file failed with exit code $($p.ExitCode)" }
}
function Stop-Backend {
    if (Get-Service SecurityConsole -ErrorAction SilentlyContinue) { Stop-Service SecurityConsole -Force -ErrorAction SilentlyContinue }
    if (Get-ScheduledTask -TaskName SecurityConsole -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName SecurityConsole -ErrorAction SilentlyContinue }
    Get-Process backend -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$Home_*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep 2
}

Step 1 "Copying OmniShield files to $Home_"
Stop-Backend
New-Item -ItemType Directory -Force -Path "$Home_\tools\yara", "$Home_\tools\hayabusa", "$Home_\data", "$Home_\logs", "$Home_\quarantine", "$Home_\config" | Out-Null
Copy-Item "$App\backend", "$App\ui", "$App\rules" $Home_ -Recurse -Force
if (-not (Test-Path "$Home_\config\console.json")) { Copy-Item "$App\config\console.json" "$Home_\config\" -Force }
icacls "$Home_\quarantine" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
icacls "$Home_\data"       /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

Step 2 "Installing ClamAV"
Step 3 "Virus signatures and the ClamAV scanner service (a few minutes)"
Run "ClamAV" { & "$Here\clamav.ps1" -Payload $Payload -App $App -Home_ $Home_ }

Step 4 "Installing osquery"
Run "osquery" { if (Test-Path "C:\Program Files\osquery\osqueryi.exe") { Write-Host "   Already installed." } else { Msi "$Payload\osquery.msi" } }

Step 5 "Installing Sysmon"
Run "Sysmon" {
    if ($SkipSysmon) { Write-Host "   skipped" }
    elseif (Get-Service Sysmon64 -ErrorAction SilentlyContinue) { & "$Payload\Sysmon64.exe" -c "$Payload\sysmonconfig.xml" | Out-Null }
    else { & "$Payload\Sysmon64.exe" -accepteula -i "$Payload\sysmonconfig.xml" | Out-Null }
}

Step 6 "Installing YARA and Hayabusa (Sigma)"
Run "YARA / Hayabusa" {
    if (-not (Test-Path "$Payload\yara\yara64.exe")) { throw "yara64.exe is missing from the installer files" }
    Copy-Item "$Payload\yara\yara64.exe" "$Home_\tools\yara\" -Force
    if (Test-Path "$Payload\yara\yarac64.exe") { Copy-Item "$Payload\yara\yarac64.exe" "$Home_\tools\yara\" -Force }
    if (Test-Path "$Payload\hayabusa.zip") {
        & "$env:SystemRoot\System32\tar.exe" -x -f "$Payload\hayabusa.zip" -C "$Home_\tools\hayabusa"
    } else {
        robocopy "$Payload\hayabusa" "$Home_\tools\hayabusa" /E /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { Write-Warning "Some Hayabusa files couldn't be copied." }
    }
    if (-not (Test-Path "$Home_\tools\hayabusa\hayabusa.exe")) { throw "hayabusa.exe is missing - Microsoft Defender may have removed it (check Protection history)." }
    Push-Location "$Home_\tools\hayabusa"
    try { & .\hayabusa.exe update-rules -q 2>&1 | Out-Null } catch { Write-Warning "Hayabusa rule update failed (offline?) - bundled rules will be used." }
    Pop-Location
}

Step 7 "Registering the OmniShield background service"
Run "Backend service" {
    $exe = "$Home_\backend\backend.exe"
    if (-not (Test-Path $exe)) { throw "backend.exe is missing from $Home_\backend" }
    if (Get-Service SecurityConsole -ErrorAction SilentlyContinue) {
        Stop-Service SecurityConsole -Force -ErrorAction SilentlyContinue
        if (Test-Path "$Home_\tools\nssm.exe") { & "$Home_\tools\nssm.exe" remove SecurityConsole confirm | Out-Null } else { sc.exe delete SecurityConsole | Out-Null }
        Start-Sleep 2
    }
    if (Get-ScheduledTask -TaskName SecurityConsole -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName SecurityConsole -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName SecurityConsole -Confirm:$false
    }
    if (Test-Path "$Payload\nssm.exe") {
        Write-Host "   Using a Windows service (NSSM)"
        Copy-Item "$Payload\nssm.exe" "$Home_\tools\" -Force
        $nssm = "$Home_\tools\nssm.exe"
        & $nssm install SecurityConsole $exe | Out-Null
        & $nssm set SecurityConsole AppDirectory "$Home_\backend" | Out-Null
        & $nssm set SecurityConsole AppEnvironmentExtra "SC_HOME=$Home_" | Out-Null
        & $nssm set SecurityConsole DisplayName "OmniShield" | Out-Null
        & $nssm set SecurityConsole Description "Orchestrates ClamAV, YARA, osquery, Sysmon and Sigma (Hayabusa)" | Out-Null
        & $nssm set SecurityConsole Start SERVICE_AUTO_START | Out-Null
        & $nssm set SecurityConsole AppStdout "$Home_\logs\service.log" | Out-Null
        & $nssm set SecurityConsole AppStderr "$Home_\logs\service.log" | Out-Null
        & $nssm set SecurityConsole AppRotateFiles 1 | Out-Null
        & $nssm set SecurityConsole AppRotateBytes 10485760 | Out-Null
        Start-Service SecurityConsole
    } else {
        Write-Host "   Using a Windows startup task (runs as SYSTEM, restarts if it stops)"
        $action    = New-ScheduledTaskAction -Execute $exe -WorkingDirectory "$Home_\backend"
        $trigger   = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                       -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName SecurityConsole -TaskPath "\" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "OmniShield backend" | Out-Null
        Start-ScheduledTask -TaskName SecurityConsole
    }
}

Step 8 "Creating shortcuts"
Run "Shortcuts" { & "$Here\shortcut.ps1" -Create -Url $url }

Step 9 "Health check"
Start-Sleep 8
$svcState = { param($exeName) (Get-CimInstance Win32_Service | Where-Object { $_.PathName -match "\\$exeName" } | Select-Object -First 1).State }
$checks = [ordered]@{
    "ClamAV scanner"          = & $svcState "clamd\.exe"
    "ClamAV updater"          = & $svcState "freshclam\.exe"
    "Sysmon"                  = (Get-Service Sysmon64 -ErrorAction SilentlyContinue).Status
    "osquery"                 = if (Test-Path "C:\Program Files\osquery\osqueryi.exe") { "Installed" } else { "MISSING" }
    "YARA"                    = if (Test-Path "$Home_\tools\yara\yara64.exe") { "Installed" } else { "MISSING" }
    "Hayabusa (Sigma)"        = if (Test-Path "$Home_\tools\hayabusa\hayabusa.exe") { "Installed" } else { "MISSING" }
    "OmniShield"        = if (Get-Service SecurityConsole -ErrorAction SilentlyContinue) { (Get-Service SecurityConsole).Status }
                                elseif (Get-ScheduledTask -TaskName SecurityConsole -ErrorAction SilentlyContinue) { (Get-ScheduledTask -TaskName SecurityConsole).State }
}
$up = $false
for ($i = 0; $i -lt 15 -and -not $up; $i++) { try { Invoke-RestMethod "$url/api/status" -TimeoutSec 3 | Out-Null; $up = $true } catch { Start-Sleep 2 } }
$checks["Dashboard ($url)"] = if ($up) { "Responding" } else { "NOT responding - see $Home_\logs\backend.log" }
$checks.GetEnumerator() | ForEach-Object {
    $ok = "$($_.Value)" -match "Running|Installed|Responding|Ready"
    Write-Host ("   {0,-28} {1}" -f $_.Key, $(if ($_.Value) { $_.Value } else { "not installed" })) -ForegroundColor $(if ($ok) { "Green" } else { "Yellow" })
}
if ($Problems.Count) { Write-Host "`nSome steps had problems:" -ForegroundColor Yellow; $Problems | ForEach-Object { Write-Host "   - $_" -ForegroundColor Yellow } }
Stop-Transcript | Out-Null
Write-Host "`nInstall log: $LogFile"
if (-not $NoBrowser) { & "$Here\shortcut.ps1" -Open -Url $url }
if ($Pause) { Write-Host "`nPress Enter to close."; [void](Read-Host) }
exit $Problems.Count
