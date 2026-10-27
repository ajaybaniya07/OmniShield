<#
  Security Console add-on 1.9 - connects the add-on to your Security Console 1.7 files.
  Safe to run more than once. Started by INSTALL-ADDON.bat.
#>
$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$main = Join-Path $Root "backend\main.py"
$ui   = Join-Path $Root "ui\index.html"
$need = @("backend\addon_reports.py", "backend\addon_vt.py", "ui\addon.js", "ui\addon.css", "ui\addon_vt.js", "ui\addon_vt.css", "backend\main.py", "ui\index.html")
$missing = $need | Where-Object { -not (Test-Path (Join-Path $Root $_)) }
if ($missing) { throw "Missing: $($missing -join ', '). Extract the add-on into the same folder as Security Console 1.7 (for example C:\Build\SecurityConsole)." }
$utf8 = New-Object Text.UTF8Encoding $false

# 1. backend: load the add-on just before the app starts
$m = [IO.File]::ReadAllText($main)
if ($m -notmatch "import addon_reports") {
    $marker = 'if __name__ == "__main__":'
    $i = $m.LastIndexOf($marker)
    if ($i -lt 0) { throw "backend\main.py doesn't look like Security Console 1.7." }
    $hook = "try:`n    import sys as _sys`n    import addon_reports`n    addon_reports.register(app, _sys.modules[__name__])`nexcept Exception:`n    log.exception(`"Add-on failed to load`")`n`n`n"
    $m = $m.Substring(0, $i) + $hook + $m.Substring($i)
    [IO.File]::WriteAllText($main, $m, $utf8)
    Write-Host "   Connected the add-on to the Security Console program." -ForegroundColor Green
} else {
    Write-Host "   The program already loads the add-on."
}
(Get-Item $main).LastWriteTime = Get-Date   # makes UPDATE rebuild backend.exe

# 2. dashboard: load addon.css and addon.js
$h = [IO.File]::ReadAllText($ui)
if ($h -match "addon\.(js|css)\?v=1\.8") {
    $h = $h.Replace("addon.css?v=1.8", "addon.css?v=1.9").Replace("addon.js?v=1.8", "addon.js?v=1.9")
    [IO.File]::WriteAllText($ui, $h, $utf8)
    Write-Host "   Updated the dashboard to load add-on 1.9." -ForegroundColor Green
}
if ($h -notmatch "addon\.js") {
    $h = $h.Replace("</head>", "<link rel=`"stylesheet`" href=`"/static/addon.css?v=1.9`">`n</head>")
    $j = $h.LastIndexOf("</body>")
    if ($j -lt 0) { throw "ui\index.html doesn't look like Security Console 1.7." }
    $h = $h.Substring(0, $j) + "<script src=`"/static/addon.js?v=1.9`"></script>`n" + $h.Substring($j)
    [IO.File]::WriteAllText($ui, $h, $utf8)
    Write-Host "   Added the new pages to the dashboard." -ForegroundColor Green
} else {
    Write-Host "   The dashboard already includes the add-on."
}
