try {
    # Ensure the 'logs' directory exists (silent creation)
    $logDir = "C:/temp/pccheck/logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }
    
    # Get the list of recent files
    $recentDir = "$env:APPDATA/Microsoft/Windows/Recent"
    if (Test-Path $recentDir) {
        $recentFiles = Get-ChildItem -Path $recentDir | Select-Object -ExpandProperty Name
        if ($recentFiles) {
            Write-Host "`n[-] Recent files found." -ForegroundColor Green
            # Log to Markdown file
            "## Recent Files`n" | Out-File -Append -FilePath "$logDir/RecentFiles.md"
            $recentFiles | ForEach-Object { $_ | Out-File -Append -FilePath "$logDir/RecentFiles.md" }
        } else {
            Write-Host "`n[-] No recent files found." -ForegroundColor Red
            # Log to Markdown file
            "## Recent Files`n" | Out-File -Append -FilePath "$logDir/RecentFiles.md"
            "No recent files found." | Out-File -Append -FilePath "$logDir/RecentFiles.md"
        }
    } else {
        Write-Host "`n[-] Recent directory not found." -ForegroundColor Red
        # Log to Markdown file
        "## Recent Files`n" | Out-File -Append -FilePath "$logDir/RecentFiles.md"
        "Recent directory not found." | Out-File -Append -FilePath "$logDir/RecentFiles.md"
    }
} catch {
    Write-Host "`n[-] Unable to retrieve recent files: $_" -ForegroundColor Red
    # Log to Markdown file
    "## Recent Files`n" | Out-File -Append -FilePath "$logDir/RecentFiles.md"
    "Unable to retrieve recent files: $_" | Out-File -Append -FilePath "$logDir/RecentFiles.md"
}