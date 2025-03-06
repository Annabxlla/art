# Define the directory to search for .automaticDestinations-ms files
$searchDir = "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"

# Ensure the 'logs' directory exists (silent creation)
$logDir = "C:/temp/pccheck/logs"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

# Get all .automaticDestinations-ms files recursively in the directory
$jumplistFiles = Get-ChildItem -Path $searchDir -Recurse -Filter "*.automaticDestinations-ms"

if ($jumplistFiles.Count -eq 0) {
    Write-Host "No .automaticDestinations-ms files found." -ForegroundColor Yellow
    # Log to Markdown file
    "## Jumplist Files Check`n" | Out-File -Append -FilePath "$logDir/Jumplist.md"
    "No .automaticDestinations-ms files found." | Out-File -Append -FilePath "$logDir/Jumplist.md"
    exit
}

# Start logging the output to the Markdown file
"## Valid File Paths`n" | Out-File -Append -FilePath "$logDir/Jumplist.md"

$allPaths = @()

foreach ($jumplist in $jumplistFiles) {
    try {
        # Read file as bytes (ensuring full file read)
        $bytes = [System.IO.File]::ReadAllBytes($jumplist.FullName)

        # Convert bytes to a Unicode string
        $stringData = [System.Text.Encoding]::Unicode.GetString($bytes)

        # Remove non-printable characters to clean output
        $cleanString = $stringData -replace "[^\x20-\x7E\u0080-\uFFFF]", ""

        # Extract valid file paths using a stricter regex
        $regex = "([a-zA-Z]:\\(?:[^<>:""/\\|?*]+\\)*[^<>:""/\\|?*]+\.(?:txt|docx|pdf|exe|lnk|jpg|png|mp4|xlsx|pptx|zip|dll|ini|bat|ps1|py|json))"
        $regmatches = [regex]::Matches($cleanString, $regex)

        # Filter out corrupted paths and add them to the list
        $validPaths = $regmatches | ForEach-Object { $_.Value }

        # Add valid paths to the allPaths array
        $allPaths += $validPaths
    }
    catch {
        Write-Host "Error reading file: $($jumplist.FullName) - $_" -ForegroundColor Red
        # Log the error to the Markdown file
        "## Error Processing Jumplist`n" | Out-File -Append -FilePath "$logDir/Jumplist.md"
        "Error processing file: $($jumplist.FullName) - $_" | Out-File -Append -FilePath "$logDir/Jumplist.md"
    }
}

# Remove duplicates and filter out any lines longer than 100 characters
$uniquePaths = $allPaths | Sort-Object -Unique | Where-Object { $_.Length -le 100 }

# Write the valid paths to the Markdown file
$uniquePaths | ForEach-Object {
    $_ | Out-File -Append -FilePath "$logDir/Jumplist.md"
}

Write-Host "Jumplist files processed successfully." -ForegroundColor Green
