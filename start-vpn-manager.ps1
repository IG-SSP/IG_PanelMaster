$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = "python"
$Port = if ($env:VPN_MANAGER_PORT) { $env:VPN_MANAGER_PORT } else { "8765" }
$LogDir = Join-Path $Root "build\logs"
$LogPath = Join-Path $LogDir "vpn-manager.log"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Write-Host "Starting VPN Manager on http://127.0.0.1:$Port/"
Write-Host "Log: $LogPath"
Set-Location $Root
$env:PYTHONIOENCODING = "utf-8"
& $Python -u ".\app\vpn_manager_app.py" 2>&1 | Tee-Object -FilePath $LogPath -Append
