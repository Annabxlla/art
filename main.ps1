# Function to display header information
function Write-Header {
    Clear-Host
    $asciiArtUrl = "https://raw.githubusercontent.com/Annabxlla/art/refs/heads/master/art.ps1"
    $asciiArtScript = Invoke-RestMethod -Uri $asciiArtUrl
    Invoke-Expression $asciiArtScript
    
    $encodedTitle = "VXBkYXRlZCBieSBAYW5uYWJ4bGxhIG9uIERpc2NvcmQg4pml"
    $titleText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedTitle))
    $Host.UI.RawUI.WindowTitle = $titleText
}

# Function to test Secure Boot status
function Test-SecureBoot {
    try {
        if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            $secureBootState = Confirm-SecureBootUEFI
            if ($secureBootState) {
                Write-Host "`n[-] Secure Boot is ON." -ForegroundColor Green
            } else {
                Write-Host "`n[-] Secure Boot is OFF." -ForegroundColor Red
            }
        } else {
            Write-Host "`n[-] Secure Boot not available on this system." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "`n[-] Unable to retrieve Secure Boot status: $_" -ForegroundColor Red
    }
}

# Function to fetch OneDrive path from registry or environment variables
function Get-OneDrivePath {
    try {
        $oneDrivePath = (Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive" -Name "UserFolder").UserFolder
        if (-not $oneDrivePath) {
            Write-Warning "OneDrive path not found in registry. Attempting alternative detection..."
            $envOneDrive = [System.IO.Path]::Combine($env:UserProfile, "OneDrive")
            if (Test-Path $envOneDrive) {
                $oneDrivePath = $envOneDrive
                Write-Host "[-] OneDrive path detected using environment variable: $oneDrivePath" -ForegroundColor Green
            } else {
                Write-Error "Unable to find OneDrive path automatically."
            }
        }
        return $oneDrivePath
    } catch {
        Write-Error "Unable to find OneDrive path: $_"
        return $null
    }
}

# Function to get Ubisoft launcher path from default directories
function Get-UbisoftLauncherPath {
    $defaultPaths = @(
        "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher",
        "C:\Program Files\Ubisoft\Ubisoft Game Launcher"
    )

    foreach ($path in $defaultPaths) {
        if (Test-Path $path) {
            return $path
        }
    }

    Write-Output "Ubisoft Game Launcher not found in default paths."
    return $null
}

# Function to format output for display in log
function Format-Output {
    param($name, $value)
    $output = "{0} : {1}" -f $name, $value -replace 'System.Byte\[\]', ''
    if ($output -notmatch "Steam|Origin|EAPlay|FileSyncConfig.exe|OutlookForWindows") {
        return $output
    }
}

# Function to get Ubisoft profile paths
function Get-UbisoftProfilePaths {
    $documentsPath = [System.Environment]::GetFolderPath('MyDocuments')
    $ubisoftPath = Get-UbisoftLauncherPath
    $potentialPaths = @(
        "$documentsPath\My Games\Rainbow Six - Siege",
        "$ubisoftPath\savegames")
    $allUserNames = @()

    foreach ($path in $potentialPaths) {
        if (Test-Path -Path $path) {
            $dirNames = Get-ChildItem -Path $path -Directory | ForEach-Object { $_.Name }
            $allUserNames += $dirNames
        }
    }

    # Filter to only include UUIDs
    $uuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $uniqueUserNames = $allUserNames | Select-Object -Unique | Where-Object { $_ -match $uuidPattern }

    if ($uniqueUserNames.Count -eq 0) {
        Write-Host "`nSkipping Stats.cc Search" -ForegroundColor Yellow
    } else {
        Write-Host "`nR6 Usernames Detected. Summon Stats.cc? | (Y/N)"
        $userResponse = Read-Host

        if ($userResponse -eq "Y") {
            foreach ($name in $uniqueUserNames) {
                $url = "https://stats.cc/siege/$name"
                Write-Host " [-] Opening stats for $name on Stats.cc ..." -ForegroundColor DarkMagenta
                Start-Process $url
                Start-Sleep -Seconds 0.5
            }
        } else {
            Write-Host "Stats.cc Search Skipped" -ForegroundColor Yellow
        }
    }
}

# Function to find suspicious files
function Find-SusFiles {
    Write-Host " [-] Finding suspicious files names..." -ForegroundColor DarkMagenta
    $susFiles = @()

    foreach ($file in $global:logEntries) {
        if ($file -match "loader\.exe" -and $file -notmatch "downloader\.exe") {
            $susFiles += $file
        }
    }

    $klarFiles = @()
    $klarFiles += Get-ChildItem -Path $env:UserProfile -File -Recurse | Where-Object { $_.Name -match "(?i)^[a-zA-Z0-9]{10}\.exe" }
    if ($klarFiles.Count -gt 0) {
        $global:logEntries += "`n-----------------`nPossible Klar Files:`n"
        $global:logEntries += $klarFiles | Sort-Object
        $global:KeyFiles += "`n-----------------`nnPossible Klar Files:`n"
        $global:KeyFiles += $klarFiles | Sort-Object
    }

    $tempPath = [System.IO.Path]::Combine($env:UserProfile, "AppData\Local\Temp")
    $tempFiles = Get-ChildItem -Path $tempPath -File -Recurse | Where-Object { $_.Name -match "^.{1,6}\.exe" }
    foreach ($file in $tempFiles) {
        $susFiles += $file.FullName
    }

    if ($susFiles.Count -gt 0) {
        $global:logEntries += "`n-----------------`nSus Files(Files with loader in their name):`n"
        $global:logEntries += $susFiles | Sort-Object
        $global:KeyFiles += "`n-----------------`nSus Files(Files with loader in their name):`n"
        $global:KeyFiles += $susFiles | Sort-Object
    }
}

# Function to get Zip and Rar files
function Get-ZipRarFiles {
    Write-Host " [-] Finding .zip and .rar files. Please wait..." -ForegroundColor DarkMagenta
    $global:KeyFiles += "`n-----------------`nZip/Rar Files:`n"
    $zipRarFiles = @()
    $searchPaths = @($env:UserProfile, "$env:UserProfile\Downloads")
    $uniquePaths = @{}

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse -Include *.zip, *.rar -File
            foreach ($file in $files) {
                if (-not $uniquePaths.ContainsKey($file.FullName) -and $file.FullName -notmatch "minecraft" -and $file.FullName -notmatch "node_modules" -and $file.FullName -notmatch "go") {
                    $uniquePaths[$file.FullName] = $true
                    $zipRarFiles += $file
                    $global:KeyFiles += $file.FullName
                }
            }
        }
    }

    if ($zipRarFiles.Count -gt 0) {
        $global:logEntries += "`n-----------------"
        $global:logEntries += "`nFound .zip and .rar files:"
        $zipRarFiles | ForEach-Object { $global:logEntries += "`n" + $_.FullName }
    }
}

# Function to get registry key files
function Get-RegistryKeyFiles {
    Write-Host " `n [-] Fetching" -ForegroundColor DarkMagenta -NoNewline; Write-Host " UserSettings" -ForegroundColor White -NoNewline; Write-Host " Entries " -ForegroundColor DarkMagenta
    $global:KeyFiles += "`n-----------------`nBAMStateUserSettings:`n"
    $global:KeyFiles += "THESE NEED TO BE MANUALLY CHECKED AND REMOVED AS NT AUTHORITY\SYSTEM." 
    $loggedPaths = @{}

    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $userSettings = Get-ChildItem -Path $registryPath | Where-Object { $_.Name -like "*1001" }

    if ($userSettings) {
        foreach ($setting in $userSettings) {
            $global:logEntries += "`n$($setting.PSPath)"
            $items = Get-ItemProperty -Path $setting.PSPath | Select-Object -Property *
            foreach ($item in $items.PSObject.Properties) {
                if (($item.Name -match "exe" -or $item.Name -match ".rar") -and -not $loggedPaths.ContainsKey($item.Name) -and $item.Name -notmatch "FileSyncConfig.exe|OutlookForWindows" -and $item.Name -notmatch "ASUS|Overwolf|WindowsApps") {
                    $global:logEntries += "`n" + (Format-Output $item.Name $item.Value)
                    $loggedPaths[$item.Name] = $true
                    $global:KeyFiles += "`n" + $item.Name
                }
            }
        }
    } else {
        Write-Host " [-] No relevant user settings found." -ForegroundColor Red
    }

    Write-Host " [-] Fetching" -ForegroundColor DarkMagenta -NoNewline; Write-Host " Compatibility Assistant" -ForegroundColor White -NoNewline; Write-Host " Entries" -ForegroundColor DarkMagenta
    $compatRegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    $compatEntries = Get-ItemProperty -Path $compatRegistryPath
    $compatEntries.PSObject.Properties | ForEach-Object {
        if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
            $global:logEntries += "`n" + (Format-Output $_.Name $_.Value)
            $loggedPaths[$_.Name] = $true
        }
    }

    Write-Host " [-] Fetching" -ForegroundColor DarkMagenta -NoNewline; Write-Host " AppsSwitched" -ForegroundColor White -NoNewline; Write-Host " Entries" -ForegroundColor DarkMagenta
    $newRegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
    if (Test-Path $newRegistryPath) {
        $newEntries = Get-ItemProperty -Path $newRegistryPath
        $newEntries.PSObject.Properties | ForEach-Object {
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                $global:logEntries += "`n" + (Format-Output $_.Name $_.Value)
                $loggedPaths[$_.Name] = $true
            }
        }
    }

    Write-Host " [-] Fetching" -ForegroundColor DarkMagenta -NoNewline; Write-Host " MuiCache" -ForegroundColor White -NoNewline; Write-Host " Entries" -ForegroundColor DarkMagenta
    $muiCachePath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    if (Test-Path $muiCachePath) {
        $muiCacheEntries = Get-ChildItem -Path $muiCachePath
        $muiCacheEntries.PSObject.Properties | ForEach-Object {
            if (($_.Name -match "exe" -or $_.Name -match ".rar") -and -not $loggedPaths.ContainsKey($_.Name) -and $_.Name -notmatch "FileSyncConfig.exe|OutlookForWindows") {
                $global:logEntries += "`n" + (Format-Output $_.Name $_.Value)
                $loggedPaths[$_.Name] = $true
            }
        }
    }
    $global:logEntries = $global:logEntries | Sort-Object | Get-Unique | Where-Object { $_ -notmatch "\{.*\}" } | ForEach-Object { $_ -replace ":", "" }
}

# Function to check Wi-Fi support
function Test-WifiSupport {
    # Get all physical network adapters, including hidden ones
    $wifiAdapters = Get-NetAdapter -Name * -Physical -IncludeHidden | Where-Object { $_.InterfaceDescription -match "Wi-Fi" }

    if ($wifiAdapters.Count -gt 0) {
        Write-Host "[-] Wi-Fi Support Detected." -ForegroundColor Green
        $wifiAdapters | ForEach-Object { Write-Host "    Adapter: $($_.InterfaceDescription) - Status: $($_.Status)" }
        return $wifiAdapters
    } else {
        Write-Host "[-] No Wi-Fi adapters detected." -ForegroundColor Red
        return $null
    }
}

# Function to get installed browsers and their versions
function Get-InstalledBrowsers {
    $browsers = @()
    $registryPath = "HKLM:\SOFTWARE\Clients\StartMenuInternet"

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

    if ($browsers.Count -gt 0) {
        Write-Host "`n[+] Installed Browsers:`n"
        $browsers | ForEach-Object { Write-Host "$($_.Browser)" }
    } else {
        Write-Host "`n[-] No installed browsers detected." -ForegroundColor Red
    }
}

# Function to get installed applications
function Get-InstalledApplications {
    # list only common applications that are likely to be present:
    $susApps = @(
        "Arbor",
        "Vivado"
        )
    $installedApps = Get-WmiObject -Class Win32_Product
    if ($installedApps.CounWt -gt 0) {
        Write-Host "`n[+] Installed Applications:`n"
        $installedApps | Where-Object { $_.Name -match $susApps -and $_.Name -notmatch "Update for" } | ForEach-Object { Write-Host $_.Name }
        $global:logEntries += "`n-----------------`nInstalled Applications:`n"
        $installedApps | Where-Object { $_.Name -notmatch "Update" -and $_.Name -notmatch "Windows" -and $_.Name -notmatch "Microsoft" } | ForEach-Object { $global:logEntries += $_.Name }
    } else {
        Write-Host "`n[-] No installed applications detected." -ForegroundColor Red
    }
}

function Write-PrefetchFiles {
    Write-Host " [-] Fetching Last Ran Dates..." -ForegroundColor DarkMagenta
    $prefetchPath = "C:\Windows\Prefetch"
    $pfFilesHeader = "n=======================n.pf files:n"

    if (Test-Path $prefetchPath) {
        $pfFiles = Get-ChildItem -Path $prefetchPath -Filter *.pf -File
        if ($pfFiles.Count -gt 0) {
            $global:logEntries += $pfFilesHeader
            $pfFiles | ForEach-Object {
                $logEntry = "{0} | {1}" -f $_.Name, $_.LastWriteTime
                $global:logEntries += "n" + $logEntry
            }
        } else {
            Write-Host "No .pf files found in the Prefetch folder." -ForegroundColor Green
        }
    } else {
        Write-Host "Prefetch folder not found." -ForegroundColor Red
    }
}

# Main execution flow
function Main {
    $global:logEntries = @()
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $logFilePath = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"

    Write-Header
    Test-SecureBoot
    Test-WifiSupport | Out-Null
    Get-InstalledBrowsers
    Get-InstalledApplications
    Get-ZipRarFiles
    Get-RegistryKeyFiles
    Write-PrefetchFiles # fix this
    Find-SusFiles


    $global:logEntries | Out-File $logFilePath -Encoding utf8
    Write-Host " Log file created: $logFilePath"
    Get-Content $logFilePath | Set-Clipboard
    Write-Host " Log file copied to clipboard."
    Get-UbisoftProfilePaths

}

#Make sure its running in admin mode.
if(!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Start-Process powershell –verb runAs -ArgumentList "-NoExit -Command iex(iwr('https://raw.githubusercontent.com/Annabxlla/art/refs/heads/master/main.ps1'))"
    Exit
}

Main
