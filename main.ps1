function Invoke-Modules {
    $modules = @(
        'Write-Header.ps1',
        'Test-SecureBoot.ps1',
        'Test-WifiSupport.ps1',
        'Get-InstalledBrowsers.ps1',
        'Get-InstalledApplications.ps1',
        'Get-PrefetchFiles.ps1',
        'Get-ZipRarFiles.ps1',
        'Get-RegistryKeyFiles.ps1',
        'Join-Logs.ps1',
        'Find-SuspiciousFiles.ps1',
        'Get-UbisoftProfiles.ps1'
    )

    # Check if the -dev argument is provided
    if ($vars -contains "-dev") {
        # Load modules from local ./modules/ directory
        foreach ($module in $modules) {
            $modulePath = "./modules/$module"
            if (Test-Path $modulePath) {
                . $modulePath
            } else {
                Write-Host "[!] Module '$module' not found in './modules/'" -ForegroundColor Red
            }
        }
    } else {
         Load modules from URL
        foreach ($module in $modules) {
            $url = "https://raw.githubusercontent.com/Annabxlla/art/refs/heads/master/modules/$module"
            #Write-Host "Downloading and executing $module from $url..." -ForegroundColor Green
            Invoke-Expression (Invoke-WebRequest $url -UseBasicP)
        }
    }
}

# Main function to run the script logic
function Main {
    param (
        [string[]]$vars
    )

    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

    $logDir = "./logs"
    if (Test-Path $logDir) {
        Remove-Item -Path "$logDir/*" -Force
    }

    # Load the modules
    Invoke-Modules -vars $vars

    # Now execute the rest of the script
    $combinedFile = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), "PcCheckLogs.md")
    Get-Content $combinedFile | Set-Clipboard

    Write-Host "`nPress any key to exit..."
    [void][System.Console]::ReadKey($true)
    Exit
}

# Make sure the script is running in admin mode.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    $scriptPath = $MyInvocation.MyCommand.Path
    $global:args = $args
    if ($args -contains "-dev") {
        Start-Process powershell -verb runAs -ArgumentList "-NoExit -Command $scriptPath"
    } else {
        Start-Process powershell -verb runAs -ArgumentList "-NoExit -Command Invoke-Expression (Invoke-WebRequest 'https://raw.githubusercontent.com/Annabxlla/art/refs/heads/master/main.ps1')"
    }
    Exit
} else {
    Main -vars $args
}

