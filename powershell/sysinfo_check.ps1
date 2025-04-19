Write-Host "[INFO] Running System Info Collection..." -ForegroundColor Cyan

$reportFolder = Resolve-Path -Path "$PSScriptRoot/../reports"
if (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder | Out-Null
}

$output = "$reportFolder/sysinfo_report.txt"
"[*] Running BlueSentinel - System Info Check..." | Out-File -FilePath $output -Encoding utf8

Get-ComputerInfo | Out-File -Append -FilePath $output -Encoding utf8

Write-Host "[OK] System Info Collected and Saved." -ForegroundColor Green
