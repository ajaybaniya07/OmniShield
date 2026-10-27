<#
  Downloads the third-party tools into .\payload (already-downloaded files are skipped).
  - If a project's newest release has no Windows download (YARA 4.5.6+ ships source only),
    the newest release that has one is used.
  - Use -Force to download everything again.
#>
param([switch]$Force)
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = "SilentlyContinue"
$P = Join-Path $PSScriptRoot "payload"
New-Item -ItemType Directory -Force -Path $P, "$P\tmp" | Out-Null
$failed = @()

function Get-GitHubAsset($repo, $pattern, $outFile) {
    Write-Host "-> $repo" -ForegroundColor Cyan
    $releases = Invoke-RestMethod "https://api.github.com/repos/$repo/releases?per_page=30" -Headers @{ "User-Agent" = "SecurityConsole" }
    foreach ($rel in $releases | Where-Object { -not $_.draft -and -not $_.prerelease }) {
        $asset = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
        if ($asset) {
            if ($rel -ne $releases[0]) { Write-Host "   Newest release ($($releases[0].tag_name)) has no Windows download; using $($rel.tag_name)" -ForegroundColor Yellow }
            Write-Host "   $($asset.name)"
            Invoke-WebRequest $asset.browser_download_url -OutFile $outFile
            return
        }
    }
    throw "No release of $repo has a file matching '$pattern'"
}
function Verify-FileHash($outFile, $expectedHash) {
    if (-not (Test-Path $outFile)) { throw "File $outFile was not found for hash verification." }
    $actual = (Get-FileHash -Path $outFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expectedHash -and ($actual -ne $expectedHash.ToLowerInvariant().Trim())) {
        Remove-Item -Path $outFile -Force -ErrorAction SilentlyContinue
        throw "Tampered payload or supply-chain corruption detected! SHA-256 mismatch for $outFile. Expected $expectedHash, got $actual"
    }
    Write-Host "   [OK] SHA-256 verified ($actual)" -ForegroundColor DarkGreen
}
function Step($name, $doneFile, [scriptblock]$action, $expectedHash = $null) {
    if (-not $Force -and (Test-Path $doneFile)) {
        if ($expectedHash) {
            try { Verify-FileHash $doneFile $expectedHash } catch { Write-Host "   Tampered existing payload: $($_.Exception.Message)" -ForegroundColor Red; $script:failed += $name; return }
        }
        Write-Host "-> $name already downloaded and verified, skipping" -ForegroundColor DarkGray; return
    }
    try {
        & $action
        if ($expectedHash -and (Test-Path $doneFile)) { Verify-FileHash $doneFile $expectedHash }
    } catch { Write-Host "   FAILED: $($_.Exception.Message)" -ForegroundColor Red; $script:failed += $name }
}

Step "ClamAV" "$P\clamav.msi" { Get-GitHubAsset "Cisco-Talos/clamav" 'win\.x64\.msi$' "$P\clamav.msi" }
Step "osquery" "$P\osquery.msi" { Get-GitHubAsset "osquery/osquery" '\.msi$' "$P\osquery.msi" }

Step "YARA" "$P\yara\yara64.exe" {
    Get-GitHubAsset "VirusTotal/yara" 'win64\.zip$' "$P\tmp\yara.zip"
    Remove-Item "$P\yara" -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive "$P\tmp\yara.zip" "$P\yara" -Force
    foreach ($exe in "yara64.exe", "yarac64.exe") {
        Get-ChildItem "$P\yara" -Recurse -Filter $exe | Select-Object -First 1 |
            ForEach-Object { if ($_.DirectoryName -ne "$P\yara") { Copy-Item $_.FullName "$P\yara\$exe" -Force } }
    }
    if (-not (Test-Path "$P\yara\yara64.exe")) { throw "yara64.exe not found inside the zip" }
}

if ((Test-Path "$P\hayabusa") -and (Get-ChildItem "$P\hayabusa" -Recurse -Filter "*live-response*" -ErrorAction SilentlyContinue)) {
    Write-Host "-> Removing the live-response Hayabusa package downloaded earlier" -ForegroundColor Yellow
    Remove-Item "$P\hayabusa" -Recurse -Force
}
Step "Hayabusa" "$P\hayabusa\hayabusa.exe" {
    Get-GitHubAsset "Yamato-Security/hayabusa" '^hayabusa-[\d.]+-win-x64\.zip$' "$P\tmp\hayabusa.zip"
    Remove-Item "$P\hayabusa" -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path "$P\hayabusa" | Out-Null
    & "$env:SystemRoot\System32\tar.exe" -x -f "$P\tmp\hayabusa.zip" -C "$P\hayabusa"
    $exe = Get-ChildItem "$P\hayabusa" -Recurse -Filter "hayabusa*.exe" | Select-Object -First 1
    if (-not $exe) { throw "hayabusa exe not found inside the zip" }
    if ($exe.DirectoryName -ne "$P\hayabusa") {
        Get-ChildItem $exe.DirectoryName | Move-Item -Destination "$P\hayabusa" -Force
        $exe = Get-Item (Join-Path "$P\hayabusa" $exe.Name)
    }
    if ($exe.Name -ne "hayabusa.exe") { Rename-Item $exe.FullName "hayabusa.exe" }
}

Step "Sysmon" "$P\Sysmon64.exe" {
    Write-Host "-> Sysmon" -ForegroundColor Cyan
    Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$P\tmp\sysmon.zip"
    Expand-Archive "$P\tmp\sysmon.zip" "$P\tmp\sysmon" -Force
    Copy-Item "$P\tmp\sysmon\Sysmon64.exe" $P -Force
}
Step "Sysmon config" "$P\sysmonconfig.xml" {
    Write-Host "-> Sysmon config (SwiftOnSecurity)" -ForegroundColor Cyan
    Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$P\sysmonconfig.xml"
}

# Optional: NSSM (service wrapper). If unavailable, a Windows startup task is used instead.
if ($Force -or -not (Test-Path "$P\nssm.exe")) {
    Write-Host "-> NSSM (optional)" -ForegroundColor Cyan
    $got = $false
    foreach ($u in "https://nssm.cc/release/nssm-2.24.zip", "https://web.archive.org/web/2024id_/https://nssm.cc/release/nssm-2.24.zip") {
        try {
            Invoke-WebRequest $u -OutFile "$P\tmp\nssm.zip" -TimeoutSec 60
            Expand-Archive "$P\tmp\nssm.zip" "$P\tmp\nssm" -Force
            $exe = Get-ChildItem "$P\tmp\nssm" -Recurse -Filter nssm.exe | Where-Object { $_.DirectoryName -like "*win64*" } | Select-Object -First 1
            if ($exe) { Copy-Item $exe.FullName $P -Force; $got = $true; break }
        } catch { Write-Host "   $u : $($_.Exception.Message)" -ForegroundColor DarkYellow }
    }
    if (-not $got) { Write-Host "   NSSM unavailable - that's fine, a Windows startup task will be used." -ForegroundColor Yellow }
}

# Optional: Inter font for a sharper interface (falls back to Segoe UI if missing)
if ($Force -or -not (Test-Path "$P\fonts\InterVariable.woff2")) {
    Write-Host "-> Inter font (optional)" -ForegroundColor Cyan
    try {
        New-Item -ItemType Directory -Force -Path "$P\fonts" | Out-Null
        Invoke-WebRequest "https://cdn.jsdelivr.net/npm/@fontsource-variable/inter@5/files/inter-latin-wght-normal.woff2" -OutFile "$P\fonts\InterVariable.woff2" -TimeoutSec 60
    } catch { Write-Host "   Font not downloaded - Segoe UI will be used instead." -ForegroundColor Yellow }
}

Remove-Item "$P\tmp" -Recurse -Force -ErrorAction SilentlyContinue
if ($failed) {
    Write-Host "`nThese downloads failed: $($failed -join ', ')" -ForegroundColor Red
    Write-Host "Download them by hand into $P (see the file names in this script), then run INSTALL.bat again."
    exit 1
}
Write-Host "`nPayload ready in $P" -ForegroundColor Green
exit 0
