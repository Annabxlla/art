    # Direct paths for logs and combined file
    $logDir = "C:/temp/pccheck/logs"
    $combinedFile = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), "PcCheckLogs.md")

    # Ensure the 'logs' directory exists (silent creation)
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }

    # Combine all .md files into the combined Markdown file
    "# PC Checker | By @annabxlla" | Out-File -Append -FilePath $combinedFile
    $logFiles = Get-ChildItem -Path $logDir -Filter "*.md" -File
    $logFiles | ForEach-Object {
        $content = Get-Content -Path $_.FullName
        $content | Out-File -Append -FilePath $combinedFile
        # Add an extra new line after each log file's content
        "" | Out-File -Append -FilePath $combinedFile
    }
