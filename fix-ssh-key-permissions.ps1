param(
    [string]$KeyPath = ".vpn-secrets\ssh-key"
)

$ErrorActionPreference = "Stop"

$resolved = Resolve-Path -LiteralPath $KeyPath -ErrorAction Stop
$fullPath = $resolved.Path
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

Write-Host "Fixing SSH key permissions:"
Write-Host "  Key:  $fullPath"
Write-Host "  User: $currentUser"

& icacls $fullPath /inheritance:r | Out-Host
& icacls $fullPath /grant:r "$currentUser`:F" | Out-Host
& icacls $fullPath /grant:r "NT AUTHORITY\СИСТЕМА:F" | Out-Host

$removeAccounts = @(
    "Everyone",
    "BUILTIN\Users",
    "BUILTIN\Администраторы",
    "NT AUTHORITY\Authenticated Users",
    "NT AUTHORITY\Прошедшие проверку"
)

foreach ($account in $removeAccounts) {
    & icacls $fullPath /remove:g $account 2>$null | Out-Null
}

try {
    & icacls $fullPath /setowner $currentUser | Out-Host
} catch {
    Write-Host "Could not set owner automatically. If SSH still reports bad permissions, run this script as Administrator." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Result:"
& icacls $fullPath | Out-Host
