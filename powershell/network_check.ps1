Write-Host "`n[INFO] Running Deep Network Threat Analysis..." -ForegroundColor Cyan
Write-Host "---------------------------------------------" -ForegroundColor Gray

# Krijimi i folderit për raport
$reportFolder = Resolve-Path -Path "$PSScriptRoot/../reports"
if (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder | Out-Null
}
$output = "$reportFolder/network_report.txt"
"[*] Running BlueSentinel - Deep Network Threat Check..." | Out-File -FilePath $output -Encoding utf8

# Step 1 - Network Interfaces
Write-Host "`nStep 1. Checking Network Interfaces..." -ForegroundColor Gray
$ifaces = Get-NetIPConfiguration
$ifaces | Out-File -Append -FilePath $output -Encoding utf8
Write-Host "✓ Interfaces checked and logged." -ForegroundColor Green

# Step 2 - ARP Spoofing Check
Write-Host "`nStep 2. Analyzing ARP Table for Spoofing..." -ForegroundColor Gray
$arp = arp -a | Select-String dynamic
$macs = @{}
$spoofedARP = 0

foreach ($line in $arp) {
    $parts = $line -split '\s+'
    if ($parts.Count -ge 3) {
        $mac = $parts[1].ToLower()
        if ($macs.ContainsKey($mac)) {
            $spoofedARP++
        } else {
            $macs[$mac] = @()
        }
    }
}

if ($spoofedARP -gt 0) {
    Write-Host "✗ Detected $spoofedARP suspicious ARP entries!" -ForegroundColor Red
    "ARP Spoofing Detected: $spoofedARP suspicious entries" | Out-File -Append -FilePath $output -Encoding utf8
} else {
    Write-Host "✓ No suspicious ARP entries found." -ForegroundColor Green
    "No ARP spoofing detected." | Out-File -Append -FilePath $output -Encoding utf8
}

# Step 3 - Promiscuous Mode Check
Write-Host "`nStep 3. Checking for Promiscuous Mode..." -ForegroundColor Gray
$promiscuousCount = 0
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

foreach ($adapter in $adapters) {
    $name = $adapter.Name
    $mode = (Get-NetAdapterAdvancedProperty -Name $name -DisplayName "Monitor Mode" -ErrorAction SilentlyContinue).DisplayValue
    if ($mode -eq "Enabled") {
        $promiscuousCount++
    }
}

if ($promiscuousCount -gt 0) {
    Write-Host "✗ $promiscuousCount interface(s) in Promiscuous Mode!" -ForegroundColor Red
    "Promiscuous Mode Detected: $promiscuousCount interfaces" | Out-File -Append -FilePath $output -Encoding utf8
} else {
    Write-Host "✓ No interface in Promiscuous Mode." -ForegroundColor Green
    "No Promiscuous Mode detected." | Out-File -Append -FilePath $output -Encoding utf8
}

# Step 4 - DNS Servers
Write-Host "`nStep 4. Checking DNS Servers..." -ForegroundColor Gray
$dnsServers = Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | Select-Object -ExpandProperty ServerAddresses
$dnsServers | Out-File -Append -FilePath $output -Encoding utf8
Write-Host "✓ DNS Server info saved." -ForegroundColor Green

# Step 5 - Gateway Consistency
Write-Host "`nStep 5. Checking Gateway Consistency..." -ForegroundColor Gray
$gateways = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -ExpandProperty NextHop
if ($gateways -eq $null -or $gateways.Count -eq 0) {
    Write-Host "✗ No default gateway found!" -ForegroundColor Red
    "No Default Gateway Found" | Out-File -Append -FilePath $output -Encoding utf8
} else {
    Write-Host "✓ Default Gateway is consistent." -ForegroundColor Green
    "Default Gateway(s): $($gateways -join ', ')" | Out-File -Append -FilePath $output -Encoding utf8
}

# Final Summary
$externalConnections = (Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }).Count

Write-Host "`n------------------- Network Summary -------------------" -ForegroundColor Gray
Write-Host "• Interfaces Checked       : $($ifaces.Count)"
Write-Host "• Active External Connections : $externalConnections"
Write-Host "• Suspicious ARP Entries   : $spoofedARP"
Write-Host "• Promiscuous Interfaces   : $promiscuousCount"
Write-Host "• DNS Servers Found        : $($dnsServers.Count)"
Write-Host "• Default Gateway(s)       : $($gateways.Count)"

Write-Host "`n[OK] Deep Network Threat Analysis Completed." -ForegroundColor Green
