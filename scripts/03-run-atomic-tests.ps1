# =============================================================================
# ATOMIC RED TEAM TEST RUNNER
# Run on the Windows Server 2022 endpoint, in PowerShell AS ADMINISTRATOR.
# Installs Invoke-AtomicRedTeam and runs the test set mapped to this lab's
# detection rules.
#
# WARNING: This executes real attack simulation commands (LSASS dump,
# registry persistence, etc.) for ENGINEERING TESTING in your isolated lab.
# Do not run this against production systems.
# =============================================================================

param(
    [switch]$InstallOnly,
    [string[]]$TechniqueIds = @("T1003.001", "T1547.001", "T1218.014")
)

$ErrorActionPreference = "Stop"

function Write-Ok($msg)   { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Yellow }

Write-Host "================================" -ForegroundColor Yellow
Write-Host " ATOMIC RED TEAM TEST RUNNER" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Yellow

# ---- INSTALL INVOKE-ATOMICREDTEAM ----
Write-Info "Installing Invoke-AtomicRedTeam framework..."
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

Import-Module "$env:USERPROFILE\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Write-Ok "Invoke-AtomicRedTeam installed"

if ($InstallOnly) {
    Write-Ok "Install-only mode complete. Exiting before running tests."
    exit 0
}

# ---- RESULTS LOG ----
$resultsDir = "C:\AtomicRedTeam-Results"
New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
$resultsFile = "$resultsDir\test-run-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

"ATOMIC RED TEAM TEST RUN - $(Get-Date)" | Out-File $resultsFile
"================================================" | Out-File $resultsFile -Append

# ---- RUN TESTS ----
foreach ($technique in $TechniqueIds) {
    Write-Info "Running atomic test for $technique ..."
    "`n--- $technique ---" | Out-File $resultsFile -Append
    "Started: $(Get-Date)" | Out-File $resultsFile -Append

    try {
        Invoke-AtomicTest $technique -Confirm:$false | Tee-Object -FilePath $resultsFile -Append
        Write-Ok "$technique executed"
    } catch {
        Write-Host "[!] $technique failed: $_" -ForegroundColor Red
        "ERROR: $_" | Out-File $resultsFile -Append
    }

    "Finished: $(Get-Date)" | Out-File $resultsFile -Append
    Start-Sleep -Seconds 5
}

Write-Host "================================" -ForegroundColor Green
Write-Host " TEST RUN COMPLETE" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host "Results logged to: $resultsFile"
Write-Host ""
Write-Host "Next: check your Wazuh dashboard for alerts matching these techniques."
Write-Host "Expected rule IDs: 100100, 100101 (T1003.001), 100120 (T1547.001), 100130 (T1218.014)"
