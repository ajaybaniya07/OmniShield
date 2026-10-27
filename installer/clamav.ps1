<#
  Installs (or repairs) ClamAV for Security Console.
  If ClamAV is already installed and running, only the config and service names are refreshed
  (use -Force to reinstall anyway; FIX-ClamAV.bat does that).
#>
param(
    [string]$Payload = (Join-Path $PSScriptRoot "payload"),
    [string]$App     = (Join-Path $PSScriptRoot "app"),
    [string]$Home_   = "C:\SecurityConsole",
    [switch]$Force
)
$ErrorActionPreference = "Stop"
$ClamDir = "C:\Program Files\ClamAV"
$MsiLog  = "$Home_\logs\clamav-msi.log"
New-Item -ItemType Directory -Force -Path "$Home_\logs" | Out-Null

function Get-ClamServices { Get-CimInstance Win32_Service | Where-Object { $_.PathName -match '\\(clamd|freshclam)\.exe' } }
function Save-ServiceNames($clamd, $fresh) {
    $cfgPath = "$Home_\config\console.json"
    if (Test-Path $cfgPath) {
        $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
        $cfg.services.clamav = $clamd
        if ($fresh) { $cfg.services.freshclam = $fresh }
        [IO.File]::WriteAllText($cfgPath, ($cfg | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding $false))
    }
}

$svcs  = Get-ClamServices
$clamd = $svcs | Where-Object { $_.PathName -match '\\clamd\.exe' } | Select-Object -First 1
$fresh = $svcs | Where-Object { $_.PathName -match '\\freshclam\.exe' } | Select-Object -First 1
if (-not $Force -and $clamd -and $clamd.State -eq "Running" -and (Test-Path "$ClamDir\clamd.exe")) {
    Write-Host "   ClamAV is already installed and running - keeping it."
    Copy-Item "$App\config\clamd.conf", "$App\config\freshclam.conf" $ClamDir -Force
    Save-ServiceNames $clamd.Name $(if ($fresh) { $fresh.Name })
    Restart-Service $clamd.Name -ErrorAction SilentlyContinue
    return
}

foreach ($s in $svcs) {
    Write-Host "   Stopping old service: $($s.Name)"
    Stop-Service $s.Name -Force -ErrorAction SilentlyContinue
    sc.exe delete $s.Name | Out-Null
}
Get-Process clamd, freshclam, clamscan, clamdscan -ErrorAction SilentlyContinue | Stop-Process -Force
if ($svcs) { Start-Sleep 3 }

$keys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
foreach ($p in Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "ClamAV*" }) {
    Write-Host "   Removing previous install: $($p.DisplayName) $($p.DisplayVersion)"
    if ($p.PSChildName -like "{*}") { Start-Process msiexec.exe -Wait -ArgumentList "/x $($p.PSChildName) /qn /norestart" | Out-Null }
}
if (Test-Path $ClamDir) { Get-ChildItem $ClamDir -Exclude database -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host "   Installing ClamAV..."
$msi = Join-Path $Payload "clamav.msi"
if (-not (Test-Path $msi)) { throw "clamav.msi is missing from $Payload" }
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$msi`" /qn /norestart /l*v `"$MsiLog`""
if ($p.ExitCode -notin 0, 3010) {
    if (Test-Path $MsiLog) {
        $lines = Get-Content $MsiLog -Encoding Unicode -ErrorAction SilentlyContinue
        if (-not $lines) { $lines = Get-Content $MsiLog }
        $i = ($lines | Select-String -SimpleMatch "Return value 3" | Select-Object -First 1).LineNumber
        if ($i) { Write-Host "`n   --- Reason from the ClamAV installer log ---`n$($lines[[Math]::Max(0, $i - 12)..($i - 1)] -join "`n")`n" -ForegroundColor DarkYellow }
    }
    $hint = if ($p.ExitCode -eq 1618) { "Another installation is running. Wait a minute and try again." } elseif ($p.ExitCode -eq 1603) { "Restart the PC and run FIX-ClamAV.bat." } else { "" }
    throw "ClamAV installer failed with exit code $($p.ExitCode). $hint Full log: $MsiLog"
}
if (-not (Test-Path "$ClamDir\clamd.exe")) { throw "ClamAV installed, but clamd.exe isn't in $ClamDir" }

Copy-Item "$App\config\clamd.conf", "$App\config\freshclam.conf" $ClamDir -Force
New-Item -ItemType Directory -Force -Path "$ClamDir\database" | Out-Null
Write-Host "   Downloading virus signatures (a few minutes)..."
& "$ClamDir\freshclam.exe" --config-file="$ClamDir\freshclam.conf"
$haveDb = Get-ChildItem "$ClamDir\database" -Include *.cvd, *.cld, *.cud -Recurse -ErrorAction SilentlyContinue

Push-Location $ClamDir
& .\freshclam.exe --install-service | Out-Null
& .\clamd.exe --install-service | Out-Null
Pop-Location
Start-Sleep 2
$svcs = Get-ClamServices
$clamdName = ($svcs | Where-Object { $_.PathName -match '\\clamd\.exe' } | Select-Object -First 1).Name
$freshName = ($svcs | Where-Object { $_.PathName -match '\\freshclam\.exe' } | Select-Object -First 1).Name
if (-not $clamdName) { throw "The ClamAV scan service (clamd) wasn't created." }
Write-Host "   Services: $clamdName, $freshName"
Save-ServiceNames $clamdName $freshName
Set-Service $clamdName -StartupType Automatic
if ($freshName) { Set-Service $freshName -StartupType Automatic; Start-Service $freshName -ErrorAction SilentlyContinue }
if (-not $haveDb) { throw "Virus signatures didn't download (internet, proxy or firewall blocking database.clamav.net). The updater will keep trying." }
Start-Service $clamdName
Write-Host "   ClamAV is running." -ForegroundColor Green
