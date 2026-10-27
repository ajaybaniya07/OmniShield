<#
  Creates the "Security Console" shortcuts and opens the dashboard.
  -Create : desktop + Start menu shortcuts. With Microsoft Edge they open Security Console
            as its own maximized app window (no tabs or address bar).
  -Open   : opens the dashboard the same way, as the signed-in user (not as administrator).
#>
param([switch]$Create, [switch]$Open, [string]$Url = "http://127.0.0.1:8080")
$edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
        Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
$dirs = @([Environment]::GetFolderPath("CommonDesktopDirectory"), "$env:ProgramData\Microsoft\Windows\Start Menu\Programs")
$icon = "C:\SecurityConsole\ui\shield.ico"

if ($Create) {
    foreach ($d in $dirs) {
        Remove-Item "$d\Security Console.url", "$d\Security Console.lnk" -ErrorAction SilentlyContinue
        if ($edge) {
            $s = (New-Object -ComObject WScript.Shell).CreateShortcut("$d\Security Console.lnk")
            $s.TargetPath = $edge
            $s.Arguments = "--app=$Url --start-maximized"
            $s.Description = "Security Console"
            $s.WindowStyle = 3   # maximized
            if (Test-Path $icon) { $s.IconLocation = $icon } else { $s.IconLocation = "$env:SystemRoot\System32\imageres.dll,-1028" }
            $s.Save()
        } else {
            Set-Content -Path "$d\Security Console.url" -Value "[InternetShortcut]`r`nURL=$Url`r`n"
        }
    }
}
if ($Open) {
    # explorer.exe starts it as the normal user, even from an administrator window
    $lnk = $dirs | ForEach-Object { "$_\Security Console.lnk" } | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($lnk) { Start-Process explorer.exe -ArgumentList "`"$lnk`"" } else { Start-Process explorer.exe -ArgumentList $Url }
}
