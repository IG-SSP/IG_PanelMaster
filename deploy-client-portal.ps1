param(
    [string]$HostName = "193.233.91.195",
    [string]$User = "root",
    [string]$RemotePath = "/opt/client-portal/client-portal.py",
    [string]$ServiceName = "client-portal.service",
    [string]$IdentityFile = "",
    [string]$SshExe = "ssh"
)

$ErrorActionPreference = "Stop"

$localFile = Join-Path $PSScriptRoot "client-portal.py"
if (-not (Test-Path -LiteralPath $localFile)) {
    throw "Local client-portal.py not found: $localFile"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$remote = "$User@$HostName"
$backup = "$RemotePath.$stamp.bak"
$sshOptions = @("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15")
if ($IdentityFile) {
    $resolvedIdentity = Resolve-Path -LiteralPath $IdentityFile
    $sshOptions += @("-i", $resolvedIdentity.Path)
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

Write-Host "Uploading $localFile to ${remote}:$RemotePath"
Invoke-NativeChecked $SshExe @sshOptions $remote "test -f '$RemotePath' && cp '$RemotePath' '$backup' || true"
Get-Content -Raw -LiteralPath $localFile | & $SshExe @sshOptions $remote "cat > /tmp/client-portal.py"
if ($LASTEXITCODE -ne 0) {
    throw "$SshExe upload failed with exit code $LASTEXITCODE"
}
Invoke-NativeChecked $SshExe @sshOptions $remote "install -m 0755 /tmp/client-portal.py '$RemotePath' && python3 -m py_compile '$RemotePath' && systemctl restart '$ServiceName' && systemctl --no-pager --full status '$ServiceName'"

Write-Host "Done. Backup on server: $backup"
Write-Host "Check: https://space.indiangolf.ru/portal/"
