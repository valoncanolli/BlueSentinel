Write-Host "[INFO] Running Deep Autorun & Persistence Check..." -ForegroundColor Cyan

# Folderi për raport
$reportFolder = Join-Path $PSScriptRoot "..\reports"
if (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder | Out-Null
}

# Emri i raportit
$output = Join-Path $reportFolder "autorun_report.txt"
"[*] Running BlueSentinel - Deep Autorun & Persistence Check..." | Out-File -FilePath $output -Encoding utf8

# -----------------------------------
# 1. Startup folder check
# -----------------------------------
"`n--- Startup Folder ---`n" | Out-File -Append -FilePath $output -Encoding utf8
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($path in $startupPaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Filter *.lnk | Select-Object Name, FullName | Format-List | Out-File -Append -FilePath $output -Encoding utf8
    }
}

# -----------------------------------
# 2. Registry Run Keys
# -----------------------------------
"`n--- Registry: Run Keys ---`n" | Out-File -Append -FilePath $output -Encoding utf8
$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        Get-ItemProperty -Path $regPath | ForEach-Object {
            $_.PSObject.Properties | ForEach-Object {
                "`n$($_.Name) : $($_.Value)" | Out-File -Append -FilePath $output -Encoding utf8
            }
        }
    }
}

# -----------------------------------
# 3. Scheduled Tasks (persistent)
# -----------------------------------
"`n--- Scheduled Tasks ---`n" | Out-File -Append -FilePath $output -Encoding utf8
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object TaskName, TaskPath | Format-List | Out-File -Append -FilePath $output -Encoding utf8

# -----------------------------------
# 4. WMI Persistence
# -----------------------------------
"`n--- WMI Persistence ---`n" | Out-File -Append -FilePath $output -Encoding utf8
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Format-List Name, Query, CreatorSID | Out-File -Append -FilePath $output -Encoding utf8

# -----------------------------------
# 5. PowerShell Profile Scripts
# -----------------------------------
"`n--- PowerShell Profile Scripts ---`n" | Out-File -Append -FilePath $output -Encoding utf8
$profiles = @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost)
foreach ($profile in $profiles) {
    if (Test-Path $profile) {
        "Profile Found: $profile" | Out-File -Append -FilePath $output -Encoding utf8
    }
}

Write-Host "[OK] Autorun Check Completed." -ForegroundColor Green
