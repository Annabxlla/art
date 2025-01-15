try {
    # Ensure the 'logs' directory exists (silent creation)
    $logDir = "C:/temp/pccheck/logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }
    
    # Check Secure Boot status
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        $secureBootState = Confirm-SecureBootUEFI
        if ($secureBootState) {
            Write-Host "`n[-] Secure Boot is ON." -ForegroundColor Green
            # Log to Markdown file
            "## Secure Boot Status`n" | Out-File -Append -FilePath "$logDir/SecureBoot.md"
            "Secure Boot is ON." | Out-File -Append -FilePath "$logDir/SecureBoot.md"
        } else {
            Write-Host "`n[-] Secure Boot is OFF." -ForegroundColor Red
            # Log to Markdown file
            "## Secure Boot Status`n" | Out-File -Append -FilePath "$logDir/SecureBoot.md"
            "Secure Boot is OFF." | Out-File -Append -FilePath "$logDir/SecureBoot.md"
        }
    } else {
        Write-Host "`n[-] Secure Boot not available on this system." -ForegroundColor Yellow
        # Log to Markdown file
        "## Secure Boot Status`n" | Out-File -Append -FilePath "$logDir/SecureBoot.md"
        "Secure Boot not available on this system." | Out-File -Append -FilePath "$logDir/SecureBoot.md"
    }
} catch {
    Write-Host "`n[-] Unable to retrieve Secure Boot status: $_" -ForegroundColor Red
    # Log to Markdown file
    "## Secure Boot Status`n" | Out-File -Append -FilePath "$logDir/SecureBoot.md"
    "Unable to retrieve Secure Boot status: $_" | Out-File -Append -FilePath "$logDir/SecureBoot.md"
}

