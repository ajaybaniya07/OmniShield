#Requires -RunAsAdministrator
<#  Removes Security Console. -RemoveTools also uninstalls ClamAV, osquery and Sysmon.  #>
param([switch]$RemoveTools, [switch]$KeepData)
$ErrorActionPreference = "Continue"
$Home_ = "C:\SecurityConsole"

if (Get-Service SecurityConsole -ErrorAction SilentlyContinue) {
    Stop-Service SecurityConsole -Force -ErrorAction SilentlyContinue
    if (Test-Path "$Home_\tools\nssm.exe") { & "$Home_\tools\nssm.exe" remove SecurityConsole confirm | Out-Null } else { sc.exe delete SecurityConsole | Out-Null }
}
if (Get-ScheduledTask -TaskName SecurityConsole -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName SecurityConsole -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName SecurityConsole -Confirm:$false
}
Get-Process backend -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$Home_*" } | Stop-Process -Force
# Remove the firewall rules created by "Block internet"
Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "Security Console block*" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Remove-Item "$([Environment]::GetFolderPath("CommonDesktopDirectory"))\Security Console.url", "$([Environment]::GetFolderPath("CommonDesktopDirectory"))\Security Console.lnk" -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Security Console.url", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Security Console.lnk" -ErrorAction SilentlyContinue

if ($RemoveTools) {
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -match '\\(clamd|freshclam)\.exe' } | ForEach-Object { Stop-Service $_.Name -Force -ErrorAction SilentlyContinue; sc.exe delete $_.Name | Out-Null }
    if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) { & Sysmon64.exe -u force | Out-Null }
    $keys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    foreach ($name in "ClamAV", "osquery") {
        Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "$name*" -and $_.PSChildName -like "{*}" } |
            ForEach-Object { Start-Process msiexec.exe -Wait -ArgumentList "/x $($_.PSChildName) /qn /norestart" }
    }
}
if (Test-Path $Home_) {
    if ($KeepData) { Get-ChildItem $Home_ -Exclude data, quarantine | Remove-Item -Recurse -Force } else { Remove-Item $Home_ -Recurse -Force }
}
Write-Host "Security Console removed." -ForegroundColor Green
