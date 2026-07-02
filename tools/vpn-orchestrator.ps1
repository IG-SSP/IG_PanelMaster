param(
    [ValidateSet("menu", "init", "add-exit", "render", "deploy")]
    [string]$Command = "menu",
    [string]$ManifestPath = ".vpn-state/network.json",
    [string]$SecretsPath = ".vpn-secrets/network.secrets.json",
    [string]$OutputDir = "build/generated"
)

$ErrorActionPreference = "Stop"

function Read-Value {
    param(
        [string]$Prompt,
        [string]$Default = "",
        [switch]$Required
    )
    while ($true) {
        $suffix = if ($Default) { " [$Default]" } else { "" }
        $value = Read-Host "$Prompt$suffix"
        if ([string]::IsNullOrWhiteSpace($value)) {
            $value = $Default
        }
        if (-not $Required -or -not [string]::IsNullOrWhiteSpace($value)) {
            return $value.Trim()
        }
        Write-Host "Value is required." -ForegroundColor Yellow
    }
}

function Read-IntValue {
    param([string]$Prompt, [int]$Default)
    while ($true) {
        $raw = Read-Value -Prompt $Prompt -Default ([string]$Default)
        $parsed = 0
        if ([int]::TryParse($raw, [ref]$parsed)) {
            return $parsed
        }
        Write-Host "Enter a number." -ForegroundColor Yellow
    }
}

function Ensure-ParentDir {
    param([string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
}

function Save-Json {
    param([object]$Data, [string]$Path)
    Ensure-ParentDir $Path
    $json = $Data | ConvertTo-Json -Depth 20
    Write-TextFile -Path $Path -Value $json
}

function Write-TextFile {
    param([string]$Path, [string]$Value)
    Ensure-ParentDir $Path
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($fullPath, $Value, $encoding)
}

function Load-Json {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        return $null
    }
    return Get-Content -Raw -Encoding UTF8 -Path $Path | ConvertFrom-Json
}

function New-EmptySecrets {
    $data = [ordered]@{
        wireguard = [ordered]@{
            ingress = [ordered]@{
                privateKey = ""
                publicKey = ""
            }
            exits = [ordered]@{}
        }
        telegram = [ordered]@{
            botToken = ""
            botUsername = ""
            adminTelegramIds = ""
        }
    }
    return ($data | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
}

function Ensure-Manifest {
    $manifest = Load-Json $ManifestPath
    if (-not $manifest) {
        throw "Manifest not found: $ManifestPath. Run: .\tools\vpn-orchestrator.ps1 init"
    }
    return $manifest
}

function Ensure-Secrets {
    $secrets = Load-Json $SecretsPath
    if (-not $secrets) {
        $secrets = New-EmptySecrets
        Save-Json $secrets $SecretsPath
    }
    return $secrets
}

function Get-SecretExit {
    param([object]$Secrets, [string]$Name)
    $props = $Secrets.wireguard.exits.PSObject.Properties
    $found = $props | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($found) {
        return $found.Value
    }
    $value = [ordered]@{ privateKey = ""; publicKey = ""; presharedKey = "" }
    $Secrets.wireguard.exits | Add-Member -NotePropertyName $Name -NotePropertyValue $value
    return $value
}

function Escape-Sh {
    param([string]$Value)
    return ($Value -replace "'", "'\''")
}

function Require-Secret {
    param([string]$Value, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return "__MISSING_$($Name)__"
    }
    return $Value
}

function Initialize-Network {
    $ingressName = Read-Value "Ingress name" "msk-ingress" -Required
    $ingressHost = Read-Value "Ingress SSH host/IP" "193.233.91.195" -Required
    $ingressSshUser = Read-Value "Ingress SSH user" "root" -Required
    $domain = Read-Value "Public domain" "space.indiangolf.ru" -Required
    $publicIp = Read-Value "Ingress public IP" $ingressHost -Required
    $publicInterface = Read-Value "Ingress public interface" "net0" -Required
    $clientSourceIp = Read-Value "wg-easy container/client source IP" "10.42.42.42" -Required

    $manifest = [ordered]@{
        productVersion = 1
        ingress = [ordered]@{
            name = $ingressName
            host = $ingressHost
            sshUser = $ingressSshUser
            domain = $domain
            publicIp = $publicIp
            publicInterface = $publicInterface
            clientSourceIp = $clientSourceIp
            wgPort = 51820
            hysteriaUser = "hysteria"
        }
        routing = [ordered]@{
            tableId = 100
            reserveTableId = 101
            mark = "0x77"
            reserveMark = "0x78"
            directDomains = @("2ip.ru")
            reserveDomains = @()
        }
        exits = @()
    }

    $secrets = New-EmptySecrets
    $secrets.wireguard.ingress.privateKey = Read-Value "Ingress WireGuard private key (empty = fill later)" ""
    $secrets.wireguard.ingress.publicKey = Read-Value "Ingress WireGuard public key" "" -Required
    $secrets.telegram.botToken = Read-Value "Telegram bot token (empty = skip)" ""
    $secrets.telegram.botUsername = Read-Value "Telegram bot username (empty = skip)" ""
    $secrets.telegram.adminTelegramIds = Read-Value "Admin Telegram IDs, comma/space separated (empty = skip)" ""

    Save-Json $manifest $ManifestPath
    Save-Json $secrets $SecretsPath
    Write-Host "Created $ManifestPath and $SecretsPath"
    Write-Host "Secrets path is ignored by git. Keep backups outside the repository."
}

function Add-Exit {
    $manifest = Ensure-Manifest
    $secrets = Ensure-Secrets

    $name = Read-Value "Exit display name" "" -Required
    $mode = Read-Value "Mode: auto/reserve" "auto" -Required
    if ($mode -notin @("auto", "reserve")) {
        throw "Mode must be auto or reserve."
    }
    $host = Read-Value "Exit SSH host/IP" "" -Required
    $sshUser = Read-Value "Exit SSH user" "root" -Required
    $publicIp = Read-Value "Exit public IP" $host -Required
    $publicInterface = Read-Value "Exit public interface" "eth0" -Required
    $iface = Read-Value "WireGuard interface name" ("wg-exit-" + ($name.ToLower() -replace '[^a-z0-9]+', '')) -Required
    $ingressAddress = Read-Value "Ingress tunnel IP without prefix" "" -Required
    $exitAddress = Read-Value "Exit tunnel IP without prefix" "" -Required
    $prefixLength = Read-IntValue "Tunnel prefix length" 30
    $listenPort = Read-IntValue "Exit WireGuard UDP listen port" 51830
    $weight = if ($mode -eq "reserve") { 0 } else { Read-IntValue "Route weight" 10 }

    $exit = [ordered]@{
        name = $name
        mode = $mode
        host = $host
        sshUser = $sshUser
        publicIp = $publicIp
        publicInterface = $publicInterface
        iface = $iface
        ingressAddress = $ingressAddress
        exitAddress = $exitAddress
        prefixLength = $prefixLength
        listenPort = $listenPort
        weight = $weight
    }

    $list = @($manifest.exits | Where-Object { $_.name -ne $name -and $_.iface -ne $iface })
    $manifest.exits = @($list + $exit)

    $secretExit = Get-SecretExit $secrets $name
    $secretExit.privateKey = Read-Value "Exit WireGuard private key (empty = fill later)" ""
    $secretExit.publicKey = Read-Value "Exit WireGuard public key" "" -Required
    $secretExit.presharedKey = Read-Value "WireGuard preshared key (empty = skip)" ""

    Save-Json $manifest $ManifestPath
    Save-Json $secrets $SecretsPath
    Write-Host "Added/updated exit $name"
}

function Render-Files {
    $manifest = Ensure-Manifest
    $secrets = Ensure-Secrets
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    $ingressPrivate = Require-Secret $secrets.wireguard.ingress.privateKey "INGRESS_PRIVATE_KEY"
    $ingressPublic = Require-Secret $secrets.wireguard.ingress.publicKey "INGRESS_PUBLIC_KEY"

    $healthAutoLines = New-Object System.Collections.Generic.List[string]
    $reserveLine = ""
    $snatLines = New-Object System.Collections.Generic.List[string]
    $ingressWgBlocks = New-Object System.Collections.Generic.List[string]

    foreach ($exit in @($manifest.exits)) {
        $secretExit = Get-SecretExit $secrets $exit.name
        $exitPrivate = Require-Secret $secretExit.privateKey ("EXIT_" + $exit.name + "_PRIVATE_KEY")
        $exitPublic = Require-Secret $secretExit.publicKey ("EXIT_" + $exit.name + "_PUBLIC_KEY")
        $psk = $secretExit.presharedKey

        $pskPeer = if ($psk) { "PresharedKey = $psk`n" } else { "" }
        $exitScript = @"
#!/usr/bin/env bash
set -euo pipefail

install -d -m 700 /etc/wireguard/cascade-keys
install -d -m 755 /root/cascade-backups
tar -czf "/root/cascade-backups/before-$($exit.iface)-`$(date -u +%Y%m%dT%H%M%SZ).tgz" \
  /etc/wireguard /etc/systemd/system /etc/sysctl.d 2>/dev/null || true

cat >/etc/wireguard/$($exit.iface).conf <<'WGEOF'
[Interface]
Address = $($exit.exitAddress)/$($exit.prefixLength)
ListenPort = $($exit.listenPort)
PrivateKey = $exitPrivate

[Peer]
PublicKey = $ingressPublic
$($pskPeer)AllowedIPs = $($exit.ingressAddress)/32
WGEOF

chmod 600 /etc/wireguard/$($exit.iface).conf
sysctl -w net.ipv4.ip_forward=1
printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/99-cascade-forward.conf
iptables -C FORWARD -i $($exit.iface) -j ACCEPT 2>/dev/null || iptables -A FORWARD -i $($exit.iface) -j ACCEPT
iptables -C FORWARD -o $($exit.iface) -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -o $($exit.iface) -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -s $($exit.ingressAddress)/32 -o $($exit.publicInterface) -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s $($exit.ingressAddress)/32 -o $($exit.publicInterface) -j MASQUERADE
systemctl enable wg-quick@$($exit.iface).service
systemctl restart wg-quick@$($exit.iface).service
"@
        Write-TextFile -Path (Join-Path $OutputDir "exit-$($exit.iface).sh") -Value $exitScript

        $ingressPsk = if ($psk) { "PresharedKey = $psk`n" } else { "" }
        $ingressWgBlocks.Add(@"
cat >/etc/wireguard/$($exit.iface).conf <<'WGEOF'
[Interface]
Address = $($exit.ingressAddress)/$($exit.prefixLength)
PrivateKey = $ingressPrivate

[Peer]
PublicKey = $exitPublic
$($ingressPsk)Endpoint = $($exit.publicIp):$($exit.listenPort)
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
WGEOF
chmod 600 /etc/wireguard/$($exit.iface).conf
systemctl enable wg-quick@$($exit.iface).service
systemctl restart wg-quick@$($exit.iface).service
"@)

        $stateName = $exit.iface -replace '^wg-exit-', ''
        if ($exit.mode -eq "reserve") {
            $reserveLine = "$stateName $($exit.iface) $($exit.exitAddress)"
        } else {
            $healthAutoLines.Add("$stateName $($exit.iface) $($exit.exitAddress) $($exit.weight)")
        }
        $snatLines.Add("    meta skuid `$HYSTERIA_UID oifname `"$($exit.iface)`" snat ip to $($exit.ingressAddress)")
    }

    $ingressScript = @"
#!/usr/bin/env bash
set -euo pipefail

install -d -m 700 /etc/wireguard/cascade-keys
install -d -m 755 /root/cascade-backups
tar -czf "/root/cascade-backups/before-cascade-ingress-`$(date -u +%Y%m%dT%H%M%SZ).tgz" \
  /etc/wireguard /etc/systemd/system /etc/cascade 2>/dev/null || true

$($ingressWgBlocks -join "`n")
"@
    Write-TextFile -Path (Join-Path $OutputDir "ingress-wireguard.sh") -Value $ingressScript

    $healthScript = @"
#!/usr/bin/env bash
set -euo pipefail

TABLE_ID=$($manifest.routing.tableId)
RESERVE_TABLE_ID=$($manifest.routing.reserveTableId)
MARK=$($manifest.routing.mark)
RESERVE_MARK=$($manifest.routing.reserveMark)
STATE_DIR=/run/cascade-health
FAIL_DOWN=3
OK_UP=2
PING_TIMEOUT=2

EXITS='$($healthAutoLines -join "`n")'
RESERVE_EXIT='$reserveLine'

mkdir -p "`$STATE_DIR"

state_file() { printf '%s/%s.state\n' "`$STATE_DIR" "`$1"; }

read_state() {
  local name="`$1" file
  file="`$(state_file "`$name")"
  if [[ -f "`$file" ]]; then
    source "`$file"
  else
    status=unknown
    ok_count=0
    fail_count=0
  fi
}

write_state() {
  local name="`$1"
  cat > "`$(state_file "`$name")" <<EOF
status=`$status
ok_count=`$ok_count
fail_count=`$fail_count
updated_at=`$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
}

probe_once() {
  local ifname="`$1" ip="`$2"
  ip link show "`$ifname" >/dev/null 2>&1 && ping -I "`$ifname" -c 1 -W "`$PING_TIMEOUT" "`$ip" >/dev/null 2>&1
}

update_probe_state() {
  local name="`$1" ifname="`$2" ip="`$3"
  read_state "`$name"
  if probe_once "`$ifname" "`$ip"; then
    ok_count=`$((ok_count + 1))
    fail_count=0
    if [[ "`$status" != "up" && "`$ok_count" -ge "`$OK_UP" ]]; then status=up; elif [[ "`$status" == "unknown" ]]; then status=up; fi
  else
    fail_count=`$((fail_count + 1))
    ok_count=0
    if [[ "`$status" == "up" && "`$fail_count" -ge "`$FAIL_DOWN" ]]; then status=down; elif [[ "`$status" == "unknown" ]]; then status=down; fi
  fi
  write_state "`$name"
  [[ "`$status" == "up" ]]
}

build_route() {
  local route=(ip route replace default table "`$TABLE_ID")
  local reserve_route=(ip route replace default table "`$RESERVE_TABLE_ID")
  local alive=0 reserve_alive=0 _rname riface rip

  while read -r name ifname ip weight; do
    [[ -z "`${name:-}" ]] && continue
    if update_probe_state "`$name" "`$ifname" "`$ip"; then
      route+=(nexthop dev "`$ifname" weight "`$weight")
      alive=`$((alive + 1))
    fi
  done <<< "`$EXITS"

  if [[ -n "`$RESERVE_EXIT" ]]; then
    read -r _rname riface rip <<< "`$RESERVE_EXIT"
    if update_probe_state "`$_rname" "`$riface" "`$rip"; then reserve_alive=1; fi
  fi

  if [[ "`$alive" -eq 0 ]]; then
    if [[ "`$reserve_alive" -eq 1 ]]; then ip route replace default dev "`$riface" table "`$TABLE_ID"; else ip route replace blackhole default table "`$TABLE_ID"; fi
  else
    "`${route[@]}"
  fi

  if [[ "`$reserve_alive" -eq 1 ]]; then
    "`${reserve_route[@]}" dev "`$riface"
  elif [[ "`$alive" -gt 0 ]]; then
    "`${route[@]/`$TABLE_ID/`$RESERVE_TABLE_ID}"
  else
    ip route replace blackhole default table "`$RESERVE_TABLE_ID"
  fi

  while ip rule del pref 90 fwmark "`$RESERVE_MARK" table "`$RESERVE_TABLE_ID" 2>/dev/null; do :; done
  while ip rule del pref 100 fwmark "`$MARK" table "`$TABLE_ID" 2>/dev/null; do :; done
  ip rule add pref 90 fwmark "`$RESERVE_MARK" table "`$RESERVE_TABLE_ID"
  ip rule add pref 100 fwmark "`$MARK" table "`$TABLE_ID"
  ip route flush cache
}

build_route
"@
    Write-TextFile -Path (Join-Path $OutputDir "cascade-health.generated.sh") -Value $healthScript

    $runtimeManifest = $manifest | ConvertTo-Json -Depth 20
    Write-TextFile -Path (Join-Path $OutputDir "network.runtime.json") -Value $runtimeManifest

    Write-Host "Generated scripts in $OutputDir"
    Write-Host "Review generated files before deploy. Missing secrets are rendered as __MISSING_* placeholders."
}

function Deploy-Script {
    $manifest = Ensure-Manifest
    if (-not (Test-Path $OutputDir)) {
        throw "Output dir not found. Run render first."
    }
    $target = Read-Value "Target: ingress or exit name" "ingress" -Required
    if ($target -eq "ingress") {
        $hostName = $manifest.ingress.host
        $sshUser = $manifest.ingress.sshUser
        $file = Join-Path $OutputDir "ingress-wireguard.sh"
    } else {
        $exit = @($manifest.exits | Where-Object { $_.name -eq $target -or $_.iface -eq $target }) | Select-Object -First 1
        if (-not $exit) {
            throw "Unknown target: $target"
        }
        $hostName = $exit.host
        $sshUser = $exit.sshUser
        $file = Join-Path $OutputDir "exit-$($exit.iface).sh"
    }
    if (-not (Test-Path $file)) {
        throw "Generated file not found: $file"
    }
    if (Select-String -Path $file -Pattern "__MISSING_" -Quiet) {
        throw "Generated file contains missing secret placeholders. Fill $SecretsPath and render again."
    }
    $confirm = Read-Value "Upload and run $file on $sshUser@$hostName? Type APPLY to continue" ""
    if ($confirm -ne "APPLY") {
        Write-Host "Deploy cancelled."
        return
    }
    & scp $file "$sshUser@$hostName`:/tmp/cascade-apply.sh"
    & ssh "$sshUser@$hostName" "bash /tmp/cascade-apply.sh"
}

function Show-Menu {
    while ($true) {
        Write-Host ""
        Write-Host "VPN Orchestrator"
        Write-Host "1. Init network"
        Write-Host "2. Add exit"
        Write-Host "3. Render scripts"
        Write-Host "4. Deploy generated script"
        Write-Host "5. Quit"
        $choice = Read-Host "Choose"
        switch ($choice) {
            "1" { Initialize-Network }
            "2" { Add-Exit }
            "3" { Render-Files }
            "4" { Deploy-Script }
            "5" { return }
            default { Write-Host "Unknown option." -ForegroundColor Yellow }
        }
    }
}

switch ($Command) {
    "init" { Initialize-Network }
    "add-exit" { Add-Exit }
    "render" { Render-Files }
    "deploy" { Deploy-Script }
    default { Show-Menu }
}
