#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys the Endpoint Forensics collection solution to a Windows machine.

.DESCRIPTION
    This script installs the collection script, autorunsc64.exe, and configures
    a scheduled task to run the collection periodically. Run this script as 
    Administrator to deploy to the local machine.

.PARAMETER InstallPath
    The base installation directory. Defaults to C:\ProgramData\EndpointForensics

.PARAMETER CollectionIntervalHours
    How often to run the collection. Defaults to 6 hours.

.PARAMETER AutorunscUrl
    URL to download autorunsc64.exe if not bundled. Defaults to Sysinternals Live.

.PARAMETER Uninstall
    Remove the installation and scheduled task.

.EXAMPLE
    .\Deploy-EndpointForensics.ps1
    
    Installs with default settings.

.EXAMPLE
    .\Deploy-EndpointForensics.ps1 -CollectionIntervalHours 4
    
    Installs with 4-hour collection interval.

.EXAMPLE
    .\Deploy-EndpointForensics.ps1 -Uninstall
    
    Removes the installation.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InstallPath = "C:\ProgramData\EndpointForensics",
    
    [Parameter()]
    [int]$CollectionIntervalHours = 6,
    
    [Parameter()]
    [string]$AutorunscUrl = "https://live.sysinternals.com/autorunsc64.exe",
    
    [Parameter()]
    [switch]$Uninstall
)

$TaskName = "Endpoint Forensics Collector"
$CollectionScript = "Collect-EndpointForensics.ps1"

function Write-Status {
    param([string]$Message, [string]$Status = "INFO")
    $color = switch ($Status) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    Write-Host "[$Status] " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Uninstall-EndpointForensics {
    Write-Status "Uninstalling Endpoint Forensics..." "INFO"
    
    # Remove scheduled task
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Status "Removed scheduled task" "OK"
    }
    
    # Remove installation directory
    if (Test-Path $InstallPath) {
        Remove-Item $InstallPath -Recurse -Force
        Write-Status "Removed installation directory" "OK"
    }
    
    Write-Status "Uninstallation complete" "OK"
}

function Install-EndpointForensics {
    Write-Status "Installing Endpoint Forensics to $InstallPath" "INFO"
    
    # Create directories
    $directories = @(
        $InstallPath,
        (Join-Path $InstallPath "outbox"),
        (Join-Path $InstallPath "archive"),
        (Join-Path $InstallPath "logs")
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Status "Created directory: $dir" "OK"
        }
    }
    
    # Copy collection script
    $scriptSource = Join-Path $PSScriptRoot $CollectionScript
    $scriptDest = Join-Path $InstallPath $CollectionScript
    
    if (Test-Path $scriptSource) {
        Copy-Item $scriptSource $scriptDest -Force
        Write-Status "Copied collection script" "OK"
    }
    else {
        Write-Status "Collection script not found at $scriptSource" "ERROR"
        Write-Status "Please ensure $CollectionScript is in the same directory as this deployment script" "ERROR"
        exit 1
    }
    
    # Get autorunsc64.exe
    $autorunscDest = Join-Path $InstallPath "autorunsc64.exe"
    $autorunscSource = Join-Path $PSScriptRoot "autorunsc64.exe"
    
    if (Test-Path $autorunscSource) {
        Copy-Item $autorunscSource $autorunscDest -Force
        Write-Status "Copied autorunsc64.exe from bundle" "OK"
    }
    elseif (Test-Path $autorunscDest) {
        Write-Status "autorunsc64.exe already exists" "OK"
    }
    else {
        Write-Status "Downloading autorunsc64.exe from Sysinternals..." "INFO"
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $AutorunscUrl -OutFile $autorunscDest -UseBasicParsing
            Write-Status "Downloaded autorunsc64.exe" "OK"
        }
        catch {
            Write-Status "Failed to download autorunsc64.exe: $_" "WARN"
            Write-Status "Autorunsc collection will be skipped" "WARN"
        }
    }
    
    # Set permissions (SYSTEM and Administrators only)
    try {
        $acl = Get-Acl $InstallPath
        $acl.SetAccessRuleProtection($true, $false)
        
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $adminsRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        
        $acl.SetAccessRule($systemRule)
        $acl.SetAccessRule($adminsRule)
        Set-Acl $InstallPath $acl
        
        Write-Status "Set directory permissions" "OK"
    }
    catch {
        Write-Status "Could not set permissions: $_" "WARN"
    }
    
    # Remove existing scheduled task if present
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Status "Removed existing scheduled task" "OK"
    }
    
    # Create scheduled task
    $scriptPath = Join-Path $InstallPath $CollectionScript
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    
    # Run at a random minute to spread load
    $randomMinute = Get-Random -Minimum 0 -Maximum 59
    $trigger = New-ScheduledTaskTrigger -Once -At "3:$($randomMinute.ToString('00'))AM" -RepetitionInterval (New-TimeSpan -Hours $CollectionIntervalHours) -RepetitionDuration ([TimeSpan]::MaxValue)
    
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
    
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Collects endpoint forensic data for Azure Log Analytics ingestion" -Force | Out-Null
    
    Write-Status "Created scheduled task (runs every $CollectionIntervalHours hours)" "OK"
    
    # Run initial collection
    Write-Status "Running initial collection..." "INFO"
    Start-ScheduledTask -TaskName $TaskName
    
    # Wait for completion
    $timeout = 300  # 5 minutes
    $elapsed = 0
    while ((Get-ScheduledTask -TaskName $TaskName).State -eq 'Running' -and $elapsed -lt $timeout) {
        Start-Sleep -Seconds 5
        $elapsed += 5
        Write-Host "." -NoNewline
    }
    Write-Host ""
    
    if ((Get-ScheduledTask -TaskName $TaskName).State -eq 'Running') {
        Write-Status "Initial collection still running (will complete in background)" "INFO"
    }
    else {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
        if ($taskInfo.LastTaskResult -eq 0) {
            Write-Status "Initial collection completed successfully" "OK"
        }
        else {
            Write-Status "Initial collection completed with result code: $($taskInfo.LastTaskResult)" "WARN"
        }
    }
    
    # Check outbox
    $outboxPath = Join-Path $InstallPath "outbox"
    $files = Get-ChildItem $outboxPath -Filter "*.ndjson" -ErrorAction SilentlyContinue
    if ($files.Count -gt 0) {
        Write-Status "Generated $($files.Count) NDJSON files in outbox" "OK"
    }
    else {
        Write-Status "No NDJSON files found in outbox (may still be generating)" "WARN"
    }
    
    Write-Host ""
    Write-Status "Installation complete!" "OK"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Ensure Azure Monitor Agent is installed on this machine"
    Write-Host "  2. Create/associate a Data Collection Rule that watches:"
    Write-Host "     $outboxPath\*.ndjson"
    Write-Host "  3. Verify data appears in your Log Analytics workspace"
    Write-Host ""
}

# Main
if ($Uninstall) {
    Uninstall-EndpointForensics
}
else {
    Install-EndpointForensics
}
