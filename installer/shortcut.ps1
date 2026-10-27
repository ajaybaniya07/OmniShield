<#
  Creates the "OmniShield" shortcuts and opens the dashboard.
  Browser Priority:
    1. Google Chrome (preferred) -> opens as native app window (--app=$Url --start-maximized)
    2. Microsoft Edge (if Chrome not available) -> opens as native app window (--app=$Url --start-maximized)
    3. Any default system browser (if neither found) -> opens via Windows shell
#>
param([switch]$Create, [switch]$Open, [string]$Url = "http://127.0.0.1:8080")

# 1. Look for Google Chrome first
$chromePaths = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LocalAppData\Google\Chrome\Application\chrome.exe"
)
$chrome = $chromePaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

# 2. Look for Microsoft Edge as fallback
$edgePaths = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "$env:LocalAppData\Microsoft\Edge\Application\msedge.exe"
)
$edge = $edgePaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

# Preferred target browser
$targetBrowser = if ($chrome) { $chrome } elseif ($edge) { $edge } else { $null }

$dirs = @(
    [Environment]::GetFolderPath("Desktop"),
    [Environment]::GetFolderPath("CommonDesktopDirectory"),
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
    "$env:AppData\Microsoft\Windows\Start Menu\Programs"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

$icon = "C:\SecurityConsole\ui\shield.ico"

if ($Create) {
    foreach ($d in $dirs) {
        try {
            Remove-Item "$d\OmniShield.url", "$d\OmniShield.lnk" -ErrorAction SilentlyContinue
            if ($targetBrowser) {
                $s = (New-Object -ComObject WScript.Shell).CreateShortcut("$d\OmniShield.lnk")
                $s.TargetPath = $targetBrowser
                $s.Arguments = "--app=$Url --start-maximized"
                $s.Description = "OmniShield - Endpoint Defense"
                $s.WindowStyle = 3   # maximized
                if (Test-Path $icon) { $s.IconLocation = $icon } else { $s.IconLocation = "$env:SystemRoot\System32\imageres.dll,-1028" }
                $s.Save()
            } else {
                Set-Content -Path "$d\OmniShield.url" -Value "[InternetShortcut]`r`nURL=$Url`r`n"
            }
        } catch {}
    }
}

if ($Open) {
    if ($targetBrowser) {
        try {
            Start-Process $targetBrowser -ArgumentList "--app=$Url --start-maximized" -ErrorAction Stop
        } catch {
            Start-Process explorer.exe -ArgumentList "`"$Url`""
        }
    } else {
        Start-Process explorer.exe -ArgumentList "`"$Url`""
    }
}
