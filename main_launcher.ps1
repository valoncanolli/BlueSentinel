Write-Host "[*] Starting BlueSentinel Scan..." -ForegroundColor Cyan

# PowerShell scripts
Write-Host "[1/6] Running system info check..." -ForegroundColor Yellow
powershell.exe -ExecutionPolicy Bypass -File "./powershell/sysinfo_check.ps1"

Write-Host "[2/6] Running network check..." -ForegroundColor Yellow
powershell.exe -ExecutionPolicy Bypass -File "./powershell/network_check.ps1"

Write-Host "[3/6] Running Deep Traffic Analysis with TShark..." -ForegroundColor Yellow
powershell.exe -ExecutionPolicy Bypass -File "./powershell/tshark_capture.ps1"

Write-Host "[4/6] Running autorun check..." -ForegroundColor Yellow
powershell.exe -ExecutionPolicy Bypass -File "./powershell/autorun_check.ps1"

# Python scripts
Write-Host "[5/6] Running Advanced Threat File Scanner..." -ForegroundColor Yellow
python ./python/Advanced_Threat_File_Scanner.py

Write-Host "[6/6] Running VirusTotal lookup..." -ForegroundColor Yellow
python ./python/virustotal_lookup.py

Write-Host "[7/7] Generating final HTML report..." -ForegroundColor Yellow
python ./python/html_report_generator.py

# Vendosja e emrit të raportit
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = "./reports/BlueSentinel_Report_$timestamp.html"

# Output profesional & i lexueshëm
Write-Host ""
Write-Host "==============================================" -ForegroundColor DarkGray
Write-Host "[OK] BlueSentinel Scan Completed" -ForegroundColor Green
Write-Host "[OK] Report saved to: $reportPath" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor DarkGray
