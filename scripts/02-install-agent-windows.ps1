# =============================================================================
# WAZUH DETECTION LAB — STEP 3: WINDOWS AGENT + SYSMON INSTALLATION
# Run this ON the Windows Server 2022 endpoint, in PowerShell AS ADMINISTRATOR.
# Usage: .\02-install-agent-windows.ps1 -ManagerIp "10.0.1.10" -AgentName "WIN-TARGET-01"
# =============================================================================

param(
    [string]$ManagerIp = "10.0.1.10",
    [string]$AgentName = "WIN-TARGET-01"
)

$ErrorActionPreference = "Stop"

function Write-Ok($msg)   { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Yellow }

Write-Host "================================" -ForegroundColor Yellow
Write-Host " WAZUH AGENT + SYSMON - WINDOWS" -ForegroundColor Yellow
Write-Host " Manager IP: $ManagerIp" -ForegroundColor Yellow
Write-Host " Agent Name: $AgentName" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Yellow

# ---- SYSMON ----
Write-Info "Downloading Sysmon..."
$sysmonPath = "C:\Tools\Sysmon"
New-Item -ItemType Directory -Path $sysmonPath -Force | Out-Null
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$sysmonPath\sysmon.zip"
Expand-Archive -Path "$sysmonPath\sysmon.zip" -DestinationPath $sysmonPath -Force

Write-Info "Downloading SwiftOnSecurity Sysmon config (reduces noise)..."
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$sysmonPath\sysmonconfig.xml"

Write-Info "Installing Sysmon..."
Push-Location $sysmonPath
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
Pop-Location

Start-Sleep -Seconds 3
$sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue
if ($sysmonEvents) {
    Write-Ok "Sysmon is running and generating events"
} else {
    Write-Host "[!] Sysmon installed but no events yet (this is OK, they'll start flowing)" -ForegroundColor Yellow
}

# ---- WAZUH AGENT ----
Write-Info "Downloading Wazuh agent MSI..."
$wazuhMsi = "C:\Tools\wazuh-agent.msi"
New-Item -ItemType Directory -Path "C:\Tools" -Force | Out-Null
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi" -OutFile $wazuhMsi

Write-Info "Installing Wazuh agent..."
$msiArgs = "/i `"$wazuhMsi`" /q WAZUH_MANAGER=`"$ManagerIp`" WAZUH_AGENT_NAME=`"$AgentName`" WAZUH_AGENT_GROUP=`"windows`""
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait

Write-Info "Starting Wazuh agent service..."
Start-Service -Name WazuhSvc
Start-Sleep -Seconds 5

$svc = Get-Service -Name WazuhSvc
if ($svc.Status -eq "Running") {
    Write-Ok "Wazuh agent service is running"
} else {
    Write-Host "[!] Wazuh agent service status: $($svc.Status)" -ForegroundColor Red
}

Write-Host "================================" -ForegroundColor Green
Write-Host " WINDOWS AGENT + SYSMON INSTALLED" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host ""
Write-Host "Agent log location: C:\Program Files (x86)\ossec-agent\ossec.log"
Write-Host ""
Write-Host "Verify from the manager with:"
Write-Host "  sudo /var/ossec/bin/manage_agents -l"
