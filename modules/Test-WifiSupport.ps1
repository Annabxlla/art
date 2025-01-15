try {
    # Ensure the 'logs' directory exists (silent creation)
    $logDir = "C:/temp/pccheck/logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }
    
    $wifiAdapters = @(Get-NetAdapter -Name * -Physical -IncludeHidden | Where-Object { $_.InterfaceDescription -match "Wi-Fi" })
    Start-Sleep -Seconds 1
    
    # Log header for the section
    "## Wi-Fi Support`n" | Out-File -Append -FilePath "$logDir/WifiSupport.md"
    if ($wifiAdapters.Count -gt 0) {
        Write-Host "[-] Wi-Fi Support Detected." -ForegroundColor Green
        # Log Wi-Fi support detected
        "Wi-Fi Support Detected." | Out-File -Append -FilePath "$logDir/WifiSupport.md"
        $wifiAdapters | ForEach-Object {
            Write-Host "    Adapter: $($_.InterfaceDescription) - Status: $($_.Status)"
            # Log adapter information
            "    Adapter: $($_.InterfaceDescription) - Status: $($_.Status)" | Out-File -Append -FilePath "$logDir/WifiSupport.md"
        }
    } else {
        Write-Host "[-] No Wi-Fi adapters detected." -ForegroundColor Red
        # Log no Wi-Fi adapters detected
        "No Wi-Fi adapters detected." | Out-File -Append -FilePath "$logDir/WifiSupport.md"
    }
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    # Log the error message
    "An error occurred: $_" | Out-File -Append -FilePath "$logDir/WifiSupport.md"
}

