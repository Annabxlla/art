    Write-Host "[-] Finding .zip and .rar files. Please wait..." -ForegroundColor DarkMagenta
    $zipRarFiles = @()
    $searchPaths = @($env:UserProfile, "$env:UserProfile\Downloads")
    $uniquePaths = @{}
    $logDir = "C:/temp/pccheck/logs"

    # Ensure the 'logs' directory exists (silent creation)
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }

    # Set the markdown header for Zip and Rar files
    $zipRarHeader = "## Zip and Rar Files`n"

    $jobs = @()

    foreach ($path in $searchPaths) {
        $jobs += Start-Job -ScriptBlock {
            param ($path, $uniquePaths)

            $zipRarFiles = @()

            if (Test-Path $path) {
                # Only search up to a depth of 2 (or adjust as needed) for performance
                $files = Get-ChildItem -Path $path -Recurse -File -Include *.zip, *.rar -Depth 2
                foreach ($file in $files) {
                    if (-not $uniquePaths.ContainsKey($file.FullName) -and $file.FullName -notmatch "minecraft" -and $file.FullName -notmatch "node_modules" -and $file.FullName -notmatch "go") {
                        $uniquePaths[$file.FullName] = $true
                        $zipRarFiles += $file
                    }
                }
            }
            return $zipRarFiles
        } -ArgumentList $path, $uniquePaths
    }

    # Wait for all jobs to complete and collect their results
    $jobs | ForEach-Object {
        # Wait for the job to complete
        $job = $_
        while ($job.State -eq 'Running') {
            Start-Sleep -Seconds 1
        }

        $result = Receive-Job -Job $job
        $zipRarFiles += $result

        # Remove the job after it's finished
        Remove-Job -Job $job
    }

    # If zip/rar files were found, log them to markdown
    if ($zipRarFiles.Count -gt 0) {
        Write-Host "[-] Found $($zipRarFiles.Count) .zip and .rar files." -ForegroundColor Green
        # Write the header to the markdown file
        $zipRarHeader | Out-File -Append -FilePath "$logDir/ZipRarFiles.md"

        # Log each zip/rar file into markdown format
        foreach ($file in $zipRarFiles) {
            $logEntry = "- $($file.FullName)"
            $logEntry | Out-File -Append -FilePath "$logDir/ZipRarFiles.md"
        }
    } else {
        Write-Host "No .zip or .rar files found." -ForegroundColor Red
        # Log message for no files found
        "No .zip or .rar files found." | Out-File -Append -FilePath "$logDir/ZipRarFiles.md"
    }

