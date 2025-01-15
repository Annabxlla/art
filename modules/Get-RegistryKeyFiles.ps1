    Write-Host "[-] Fetching UserSettings Entries..." -ForegroundColor DarkMagenta
    $logDir = "C:/temp/pccheck/logs"
    $logFile = "$logDir/RegistryEntries.md"
    $global:logEntries = ""  # Initialize the log entries string for all sections
    $loggedPaths = @{}
    
    # Ensure the 'logs' directory exists (silent creation)
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }

    # Start the overall log file
    "## Registry Check Results`n" | Out-File -FilePath $logFile

    # Fetch BAMStateUserSettings
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $global:logEntries += "### BAMStateUserSettings`n`n"
    $userSettings = Get-ChildItem -Path $registryPath | Where-Object { $_.Name -like "*1001" }
    
    if ($userSettings) {
        foreach ($setting in $userSettings) {
            $items = Get-ItemProperty -Path $setting.PSPath | Select-Object -Property *
            foreach ($item in $items.PSObject.Properties) {
                if (($item.Name -match "exe" -or $item.Name -match ".rar") -and -not $loggedPaths.ContainsKey($item.Name) -and $item.Name -notmatch "FileSyncConfig.exe|OutlookForWindows" -and $item.Name -notmatch "ASUS|Overwolf|WindowsApps") {
                    $global:logEntries += "- $($item.Name)`n"
                    $loggedPaths[$item.Name] = $true
                }
            }
        }
    } else {
        $global:logEntries += "No relevant user settings found.`n"
    }

    # Append BAMStateUserSettings section to the log file
    $global:logEntries | Out-File -Append -FilePath $logFile

    # Fetch Compatibility Assistant Entries
    Write-Host "[-] Fetching Compatibility Assistant Entries..." -ForegroundColor DarkMagenta
    $global:logEntries = "### Compatibility Assistant`n`n"
    $compatRegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" 
    $compatEntries = Get-ItemProperty -Path $compatRegistryPath
    $compatEntries.PSObject.Properties | ForEach-Object {
        if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows" -and $_.Name -notmatch "ASUS|Overwolf|WindowsApps") {
            $global:logEntries += "- $($_.Name)`n"
            $loggedPaths[$_.Name] = $true
        }
    }

    # Append Compatibility Assistant section to the log file
    $global:logEntries | Out-File -Append -FilePath $logFile

    # Fetch AppsSwitched Entries
    Write-Host "[-] Fetching AppsSwitched Entries..." -ForegroundColor DarkMagenta
    $global:logEntries = "### AppsSwitched`n`n"
    $newRegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
    if (Test-Path $newRegistryPath) {
        $newEntries = Get-ItemProperty -Path $newRegistryPath
        $newEntries.PSObject.Properties | ForEach-Object {
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows" -and $_.Name -notmatch "ASUS|Overwolf|WindowsApps") {
                $global:logEntries += "- $($_.Name) | $($_.Value)`n"
                $loggedPaths[$_.Name] = $true
            }
        }
    }

    # Append AppsSwitched section to the log file
    $global:logEntries | Out-File -Append -FilePath $logFile

    # Fetch MuiCache Entries
    Write-Host "[-] Fetching MuiCache Entries..." -ForegroundColor DarkMagenta
    $global:logEntries = "### MuiCache`n`n"
    $muiCachePath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    if (Test-Path $muiCachePath) {
        $muiCacheEntries = Get-ChildItem -Path $muiCachePath
        $muiCacheEntries.PSObject.Properties | ForEach-Object {
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows" -and $_.Name -notmatch "ASUS|Overwolf|WindowsApps") {
                $global:logEntries += "- $($_.Name) | $($_.Value)`n"
                $loggedPaths[$_.Name] = $true
            }
        }
    }

    # Append MuiCache section to the log file
    $global:logEntries | Out-File -Append -FilePath $logFile

