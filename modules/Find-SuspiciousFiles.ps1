    # Direct paths for the combined file and pattern
    $combinedFile = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), "PcCheckLogs.md")
    $susPattern = "(?i)^[a-zA-Z0-9]{10}\.exe|^gc(\s\(\d+\))*\.exe$|^SKREECHWARE(\s\(\d+\))*\.exe$|loader\.exe"

    # Check if the combined file exists
    if (-not (Test-Path $combinedFile)) {
        Write-Host "[!] Combined log file does not exist." -ForegroundColor Red
        return
    }

    # Find suspicious files based on specific patterns
    $susFiles = @()
    $susFiles += Get-ChildItem -Path $env:UserProfile -File -Recurse | Where-Object { 
        $_.Name -match "(?i)^[a-zA-Z0-9]{10}\.exe"  -and 
        $_.Name -notmatch "jrunscript.exe"          -and 
        $_.Name -notmatch "jwebserver.exe"          -and
        $_.Name -notmatch "policytool.exe"          -and
        $_.Name -notmatch "servertool.exe"          -or
        $_.Name -match "(?i)^gc(\s\(\d+\))*\.exe$"   -or
        $_.Name -match "(?i)^SKREECHWARE(\s\(\d+\))*\.exe$" -or 
        (
            $_.Name -contains "loader\.exe" -and -not $_.Name -contains "downloader"
        )
    }

    # Filter for suspicious files in the combined file
    $filteredLines = Select-String -Path $combinedFile -Pattern $susPattern

    # Append suspicious files entries to the combined Markdown file
    if ($filteredLines.Count -gt 0 -or $susFiles.Count -gt 0) {
        Write-Host "[+] Found suspicious files. Appending to the combined log..." -ForegroundColor Red
        $susHeader = "## Suspicious Files Found`n`n"

        # Combine filtered lines from the combined log and suspicious file paths
        $susData = $filteredLines | ForEach-Object { $_.Line }
        $susData += $susFiles | ForEach-Object { $_.FullName }

        # Append the header and data to the combined Markdown file
        $susHeader + $susData | Out-File -Append -FilePath $combinedFile
    } else {
        Write-Host "[-] No suspicious files found." -ForegroundColor Green
    }

