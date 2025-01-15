    # List of suspicious applications
    $susApps = @(
        "Arbor",
        "Vivado"
    )

    $logDir = "C:/temp/pccheck/logs"

    # Ensure the 'logs' directory exists (silent creation)
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }

    $installedApps = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" |
        Get-ItemProperty |
        Where-Object { $null -ne $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

    # Log header for the section
    "## Installed Applications" | Out-File -Append -FilePath "$logDir/InstalledApplications.md"
    "`n### Found $($installedApps.Count) installed applications`n" | Out-File -Append -FilePath "$logDir/InstalledApplications.md"

    $susFound = $false

    # Log all installed applications into markdown format
    foreach ($app in $installedApps) {
        $appInfo = "$($app.DisplayName)"
        if ($app.DisplayVersion) {
            $appInfo += " | $($app.DisplayVersion)"
        }
        
        # Log all applications in markdown format
        "- $appInfo" | Out-File -Append -FilePath "$logDir/InstalledApplications.md"

        # If the application is suspicious, highlight it in the console
        if ($susApps -contains $app.DisplayName) {
            $susFound = $true
            Write-Host "    [-] $appInfo" -ForegroundColor Red
        }
    }

    # If no suspicious apps were found, log a message
    if (-not $susFound) {
        Write-Host "[-] No suspicious applications detected." -ForegroundColor Yellow
    }
