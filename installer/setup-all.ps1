<#
  OmniShield - complete setup. Started by INSTALL.bat / UPDATE.bat (as administrator).
  INSTALL: 1 Python  2 Download tools  3 Build backend.exe  4 Install everything  5 Start + check
  UPDATE (-UpdateOnly): 1 Python  3 Build  then replace the program files and restart.
#>
param([switch]$UpdateOnly)
$ErrorActionPreference = "Stop"
$Inst  = $PSScriptRoot
$Root  = Split-Path $Inst -Parent
$Log   = Join-Path $Root $(if ($UpdateOnly) { "update-log.txt" } else { "install-log.txt" })
$Url   = "http://127.0.0.1:8080"
$Home_ = "C:\SecurityConsole"
Start-Transcript -Path $Log -Force | Out-Null

function Head($n, $t) { Write-Host "`n==== Step $n of 5: $t ====" -ForegroundColor Cyan }
function Stop-Setup($msg) { Write-Host "`nSTOPPED: $msg" -ForegroundColor Red; Write-Host "Details are saved in: $Log"; Stop-Transcript | Out-Null; exit 1 }
function Find-Python {
    $tries = @()
    foreach ($c in "py", "python", "python3") { $g = Get-Command "$c.exe" -ErrorAction SilentlyContinue; if ($g -and $g.Source -notlike "*WindowsApps*") { $tries += $g.Source } }
    $tries += Get-ChildItem "$env:ProgramFiles\Python3*\python.exe", "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | ForEach-Object FullName
    foreach ($t in $tries) {
        $pa = if ((Split-Path $t -Leaf) -eq "py.exe") { @("-3", "-c") } else { @("-c") }
        try { $exe = & $t @pa "import sys; print(sys.executable if sys.version_info >= (3,10) else '')" 2>$null } catch { continue }
        if ($exe -and (Test-Path "$exe".Trim())) { return "$exe".Trim() }
    }
    return $null
}
function Wait-Up { for ($i = 0; $i -lt 45; $i++) { try { return Invoke-RestMethod "$Url/api/status" -TimeoutSec 3 } catch { Start-Sleep 2 } }; return $null }

Write-Host $(if ($UpdateOnly) { "=== OmniShield update ===" } else { "=== OmniShield setup ===" }) -ForegroundColor Green
Write-Host "Folder: $Root"
if ($Root.Length -gt 40) { Write-Host "Tip: this folder path is long. If a step fails, move the folder to C:\Build\SecurityConsole and run it again." -ForegroundColor Yellow }
Get-ChildItem $Root -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue

try {
    Head 1 "Checking Python"
    $py = Find-Python
    if (-not $py) {
        Write-Host "Python not found - installing Python 3.12 with winget..."
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { Stop-Setup "Python isn't installed and winget isn't available. Install Python 3.12 from python.org (tick 'Add to PATH'), then run this again." }
        winget install -e --id Python.Python.3.12 --scope machine --silent --accept-package-agreements --accept-source-agreements
        $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
        $py = Find-Python
        if (-not $py) { Stop-Setup "Python was installed but can't be found yet. Close this window and run it again." }
    }
    Write-Host "Using Python: $py" -ForegroundColor Green

    if (-not $UpdateOnly) {
        Head 2 "Downloading the security tools (skips anything already downloaded)"
        & "$Inst\get-payload.ps1"
        $need = "clamav.msi", "osquery.msi", "yara\yara64.exe", "hayabusa\hayabusa.exe", "Sysmon64.exe", "sysmonconfig.xml"
        $missing = $need | Where-Object { -not (Test-Path (Join-Path "$Inst\payload" $_)) }
        if ($missing) { Stop-Setup "These files are missing from installer\payload: $($missing -join ', '). Check Windows Security > Protection history, then run INSTALL.bat again." }
        Write-Host "All tools downloaded." -ForegroundColor Green
    } else {
        Head 2 "Downloading tools - skipped (update only)"
        if (-not (Test-Path "$Inst\payload\fonts\InterVariable.woff2")) { try { & "$Inst\get-payload.ps1" | Out-Null } catch {} }
    }

    # Integrate add-ons (User Activity, Security Checkup, NIST CSF 2.0, VirusTotal)
    if (Test-Path "$Inst\apply-addon.ps1") {
        try {
            Write-Host "Integrating Add-ons (User Activity, Security Checkup, VirusTotal)..." -ForegroundColor Cyan
            & "$Inst\apply-addon.ps1" | Out-Null
        } catch {
            Write-Host "Notice: Add-on integration check: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Head 3 "Building the OmniShield program (first time takes a few minutes)"
    $be = "$Root\backend"; $dist = "$be\dist\backend.exe"
    $srcTime = @((Get-Item "$be\main.py").LastWriteTime, (Get-Item "$be\requirements.txt").LastWriteTime) | Sort-Object | Select-Object -Last 1
    if ((Test-Path $dist) -and ((Get-Item $dist).LastWriteTime -gt $srcTime)) {
        Write-Host "backend.exe is already up to date - skipping."
    } else {
        $vpy = "$be\.venv\Scripts\python.exe"
        if (-not (Test-Path $vpy)) { & $py -m venv "$be\.venv"; if (-not (Test-Path $vpy)) { Stop-Setup "Couldn't create the Python environment in $be\.venv" } }
        & $vpy -m pip install --disable-pip-version-check -q -r "$be\requirements.txt"
        if ($LASTEXITCODE -ne 0) { Stop-Setup "Installing the Python packages failed (internet or proxy problem?)." }
        Remove-Item $dist -Force -ErrorAction SilentlyContinue
        Push-Location $be
        & $vpy -m PyInstaller --noconfirm --onefile --name backend --collect-submodules uvicorn --collect-submodules watchdog `
            --hidden-import fastapi --hidden-import psutil --hidden-import win32evtlog --hidden-import win32timezone `
            --hidden-import addon_reports --hidden-import addon_vt main.py
        Pop-Location
        if (-not (Test-Path $dist)) { Stop-Setup "backend.exe wasn't created. Check Windows Security > Protection history - Defender sometimes removes newly built programs." }
    }
    $app = "$Inst\app"
    Remove-Item $app -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path "$app\backend" | Out-Null
    Copy-Item $dist "$app\backend\"
    Copy-Item "$Root\ui", "$Root\config", "$Root\rules" $app -Recurse -Force
    if (Test-Path "$Inst\payload\fonts") { Copy-Item "$Inst\payload\fonts" "$app\ui\" -Recurse -Force }
    Write-Host "Program ready." -ForegroundColor Green

    $installProblems = 0
    if ($UpdateOnly) {
        Head 4 "Replacing the program files (settings, history, blocked programs and quarantine are kept)"
        if (-not (Test-Path "$Home_\backend\backend.exe")) { Stop-Setup "OmniShield isn't installed yet. Run INSTALL.bat first." }
        $svc = Get-Service SecurityConsole -ErrorAction SilentlyContinue
        $task = Get-ScheduledTask -TaskName SecurityConsole -ErrorAction SilentlyContinue
        if ($svc) { Stop-Service SecurityConsole -Force -ErrorAction SilentlyContinue }
        if ($task) { Stop-ScheduledTask -TaskName SecurityConsole -ErrorAction SilentlyContinue }
        Get-Process backend -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$Home_*" } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
        Copy-Item "$app\backend", "$app\ui", "$app\rules" $Home_ -Recurse -Force
        try { & "$Inst\clamav.ps1" -Payload "$Inst\payload" -App $app -Home_ $Home_ } catch { Write-Host "   ClamAV: $($_.Exception.Message)" -ForegroundColor Yellow; $installProblems++ }
        & "$Inst\shortcut.ps1" -Create -Url $Url
        if ($svc) { Start-Service SecurityConsole } elseif ($task) { Start-ScheduledTask -TaskName SecurityConsole } else { Stop-Setup "The background service isn't registered. Run INSTALL.bat instead." }
    } else {
        Head 4 "Installing ClamAV, osquery, Sysmon, YARA, Hayabusa and OmniShield"
        Write-Host "This takes 5-10 minutes (ClamAV downloads its virus signatures)." -ForegroundColor Yellow
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$Inst\install.ps1" -NoBrowser
        $installProblems = $LASTEXITCODE
    }

    Head 5 "Starting OmniShield"
    $st = Wait-Up
    if (-not $st) { Stop-Setup "OmniShield didn't start. Double-click 'START OmniShield.bat' - if that fails too, send the file $(Split-Path $Log -Leaf)." }
    $names = @{ clamav = "Antivirus (ClamAV)"; freshclam = "Virus definitions"; yara = "Pattern rules (YARA)"; sigma = "Behavior detection (Sigma)"; sysmon = "Activity monitor (Sysmon)"; osquery = "System inspector (osquery)" }
    Write-Host ""
    foreach ($p in $st.engines.PSObject.Properties) {
        $ok = $p.Value -in "running", "ready"
        Write-Host ("   {0,-30} {1}" -f $names[$p.Name], $(if ($ok) { "Active" } else { $p.Value })) -ForegroundColor $(if ($ok) { "Green" } else { "Yellow" })
    }
    Write-Host "`nOmniShield $($st.version) is ready: $Url" -ForegroundColor Green
    if ($installProblems) { Write-Host "Some parts had problems (yellow above). If only the Antivirus is yellow, wait 5 minutes - it may still be loading virus signatures." -ForegroundColor Yellow }
    & "$Inst\shortcut.ps1" -Open -Url $Url
} catch { Stop-Setup $_.Exception.Message }
Stop-Transcript | Out-Null
exit 0
