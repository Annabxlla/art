$browsers = @()
$registryPath = "HKLM:\SOFTWARE\Clients\StartMenuInternet"
$logDir = "C:/temp/pccheck/logs"

# Ensure the 'logs' directory exists (silent creation)
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}
# Get the list of browser keys from the registry
$browserKeys = Get-ChildItem -Path $registryPath | Where-Object { $_.PSChildName -match "^[A-Za-z0-9]" }
foreach ($key in $browserKeys) {
    $browserName = $key.PSChildName
    $browserDisplayName = (Get-ItemProperty -Path $key.PSPath -Name "LocalizedString" -ErrorAction SilentlyContinue).LocalizedString
    if (-not $browserDisplayName) {
        $browserDisplayName = $browserName
    }
    $browsers += [PSCustomObject]@{
        Browser = $browserDisplayName
        Key     = $browserName
    }
}
# Log header for the section
"## Installed Browsers`n" | Out-File -Append -FilePath "$logDir/InstalledBrowsers.md"
if ($browsers.Count -gt 0) {
    Write-Host "[+] Installed Browsers:`n" -ForegroundColor Green
    # Log installed browsers
    $browsers | ForEach-Object {
        Write-Host "$($_.Browser)"
        "- $($_.Browser)" | Out-File -Append -FilePath "$logDir/InstalledBrowsers.md"
    }
} else {
    Write-Host "[-] No installed browsers detected." -ForegroundColor Red
    # Log no browsers detected
    "No installed browsers detected." | Out-File -Append -FilePath "$logDir/InstalledBrowsers.md"
}

