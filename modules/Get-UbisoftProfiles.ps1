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

# Function to get Ubisoft profile
function Get-UbisoftProfiles {
    $documentsPath = [System.Environment]::GetFolderPath('MyDocuments')
    $ubisoftPath = Get-UbisoftLauncherPath
    $potentialPaths = @(
        "$documentsPath\My Games\Rainbow Six - Siege",
        "$ubisoftPath\savegames",
        "$ubisoftPath\cache\ownership",
        "$ubisoftPath\cache\activations",
        "$ubisoftPath\cache\club",
        "$ubisoftPath\cache\conversations",
        "$ubisoftPath\cache\game_stats",
        "$ubisoftPath\cache\ptdata",
        "$ubisoftPath\cache\settings"
    )
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
        Write-Host "`n`nNo Ubi accounts found!`n`n" -ForegroundColor DarkRed -BackgroundColor Yellow
    } else {
        $usernameCount = $uniqueUserNames.Count
        Write-Host "`n$usernameCount R6 Accounts Detected. Summon Stats.cc? | (Y/n)"
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

Get-UbisoftProfiles