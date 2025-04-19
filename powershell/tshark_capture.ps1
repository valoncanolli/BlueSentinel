Write-Host "`n[INFO] Starting Deep Traffic Analysis using TShark..." -ForegroundColor Cyan

# Kontrollo nëse tshark është në PATH
$tsharkPath = Get-Command tshark -ErrorAction SilentlyContinue

# Vendosja e output-it në të njëjtin raport si pjesët tjera
$reportFolder = Resolve-Path "$PSScriptRoot/../reports"
$output = "$reportFolder/network_report.txt"

if (-not $tsharkPath) {
    Write-Host "[WARN] TShark is not installed or not in PATH. Skipping capture." -ForegroundColor Yellow
    Add-Content -Path $output -Value "`n[WARN] TShark not found. Traffic analysis skipped."
    return
}

# Interface ID për të kapur trafikun
$interfaceID = 1  # Mund të bëhet dinamik më vonë
$tempFile = Join-Path $env:TEMP "tshark_capture_summary.txt"

Write-Host "[INFO] Capturing 60 seconds of network traffic..." -ForegroundColor Gray
tshark -i $interfaceID -a duration:60 -q -z conv,tcp -z conv,udp > $tempFile 2>$null

# Ruaj rezultatet në raport
Add-Content -Path $output -Value "`n--- TShark TCP/UDP Summary (60s capture) ---`n"
Get-Content $tempFile | Out-File -Append -FilePath $output -Encoding utf8

# Analizë për IP të dyshimta (paketa të vogla dhe të shpeshta)
Write-Host "[INFO] Analyzing traffic patterns for suspicious behavior..." -ForegroundColor Gray
$suspiciousLines = Select-String -Path $tempFile -Pattern " < " | Where-Object { $_.Line -match "\d+\.\d+\.\d+\.\d+" }
$suspiciousCount = ($suspiciousLines | Select-String -Pattern "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" -AllMatches).Matches.Count

if ($suspiciousCount -gt 0) {
    Write-Host "[ALERT] Detected potential beaconing or C2 traffic from $suspiciousCount IP entries." -ForegroundColor Red
    Add-Content -Path $output -Value "`n[ALERT] Potential beaconing traffic detected: $suspiciousCount suspicious flows"
} else {
    Write-Host "[OK] No suspicious beaconing traffic detected." -ForegroundColor Green
    Add-Content -Path $output -Value "`n[OK] No beaconing detected in tshark analysis."
}

Remove-Item $tempFile -ErrorAction SilentlyContinue