#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Collects endpoint forensic data and writes NDJSON files for Azure Monitor Agent ingestion.

.DESCRIPTION
    This script runs locally on Windows endpoints to collect system configuration, 
    network state, process information, persistence mechanisms, and security-relevant 
    data. Output is written as NDJSON (Newline Delimited JSON) files that Azure Monitor 
    Agent (AMA) can ingest via Data Collection Rules.

.NOTES
    Version:        2.0.0
    Author:         Endpoint Forensics Team
    Creation Date:  2024-12-02
    Purpose:        Replace WinRM-based collection with local AMA-based ingestion
    
    REQUIREMENTS:
    - PowerShell 5.1 or later
    - Run as Administrator (or SYSTEM via scheduled task)
    - Azure Monitor Agent installed and configured
    - autorunsc64.exe in same directory as this script
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$BasePath = "C:\ProgramData\EndpointForensics",
    
    [Parameter()]
    [int]$ArchiveRetentionDays = 7,
    
    [Parameter()]
    [switch]$SkipAutorunsc
)

#region Configuration
$Script:Version = "2.0.0"
$Script:StartTime = Get-Date
$Script:OutboxPath = Join-Path $BasePath "outbox"
$Script:ArchivePath = Join-Path $BasePath "archive"
$Script:LogPath = Join-Path $BasePath "logs"
$Script:AutorunscPath = Join-Path $PSScriptRoot "autorunsc64.exe"

# Standard fields added to every record
$Script:SnapshotId = [Guid]::NewGuid().ToString()
$Script:HostUUID = $null
$Script:ComputerName = $env:COMPUTERNAME
$Script:TimeGenerated = $Script:StartTime.ToUniversalTime().ToString("o")

# Collection errors tracked here
$Script:CollectionErrors = [System.Collections.ArrayList]::new()
#endregion

#region Helper Functions
function Initialize-Directories {
    @($Script:OutboxPath, $Script:ArchivePath, $Script:LogPath) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }
    }
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    $logFile = Join-Path $Script:LogPath "collection_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    if ($Level -eq "ERROR") {
        Write-Warning $Message
    } else {
        Write-Verbose $Message
    }
}

function Add-StandardFields {
    param([PSCustomObject]$Record)
    
    $Record | Add-Member -NotePropertyName "TimeGenerated" -NotePropertyValue $Script:TimeGenerated -Force
    $Record | Add-Member -NotePropertyName "Computer" -NotePropertyValue $Script:ComputerName -Force
    $Record | Add-Member -NotePropertyName "HostUUID" -NotePropertyValue $Script:HostUUID -Force
    $Record | Add-Member -NotePropertyName "SnapshotId" -NotePropertyValue $Script:SnapshotId -Force
    
    return $Record
}

function Write-NdjsonFile {
    param(
        [string]$FileName,
        [array]$Records
    )
    
    if ($null -eq $Records -or $Records.Count -eq 0) {
        Write-Log "No records to write for $FileName"
        return
    }
    
    $filePath = Join-Path $Script:OutboxPath "$FileName.ndjson"
    
    try {
        $Records | ForEach-Object {
            $enrichedRecord = Add-StandardFields -Record $_
            $enrichedRecord | ConvertTo-Json -Compress -Depth 10
        } | Out-File -FilePath $filePath -Encoding utf8 -Force
        
        Write-Log "Wrote $($Records.Count) records to $FileName.ndjson"
    }
    catch {
        Write-Log "Failed to write $FileName.ndjson: $_" -Level "ERROR"
        $null = $Script:CollectionErrors.Add([PSCustomObject]@{
            Category = $FileName
            Error = $_.Exception.Message
        })
    }
}

function Invoke-SafeCollection {
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock
    )
    
    Write-Log "Collecting $Name..."
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $result = & $ScriptBlock
        $stopwatch.Stop()
        Write-Log "Completed $Name in $($stopwatch.ElapsedMilliseconds)ms"
        return $result
    }
    catch {
        $stopwatch.Stop()
        Write-Log "Failed to collect $Name: $_" -Level "ERROR"
        $null = $Script:CollectionErrors.Add([PSCustomObject]@{
            Category = $Name
            Error = $_.Exception.Message
            Duration = $stopwatch.ElapsedMilliseconds
        })
        return $null
    }
}

function Move-ProcessedFiles {
    # Archive previous collection files
    $existingFiles = Get-ChildItem $Script:OutboxPath -Filter "*.ndjson" -ErrorAction SilentlyContinue
    if ($existingFiles.Count -gt 0) {
        $archiveFolder = Join-Path $Script:ArchivePath (Get-Date -Format "yyyy-MM-dd_HHmmss")
        New-Item -ItemType Directory -Path $archiveFolder -Force | Out-Null
        $existingFiles | Move-Item -Destination $archiveFolder -Force
        Write-Log "Archived $($existingFiles.Count) files to $archiveFolder"
    }
}

function Remove-OldArchives {
    $cutoff = (Get-Date).AddDays(-$ArchiveRetentionDays)
    Get-ChildItem $Script:ArchivePath -Directory -ErrorAction SilentlyContinue | 
        Where-Object { $_.CreationTime -lt $cutoff } | 
        ForEach-Object {
            Remove-Item $_.FullName -Recurse -Force
            Write-Log "Removed old archive: $($_.Name)"
        }
}
#endregion

#region Collection Functions

function Get-SystemUUID {
    try {
        $uuid = (Get-WmiObject -Class Win32_ComputerSystemProduct -ErrorAction Stop).UUID
        return $uuid
    }
    catch {
        # Fallback to machine GUID
        try {
            $machineGuid = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid -ErrorAction Stop).MachineGuid
            return $machineGuid
        }
        catch {
            return [Guid]::NewGuid().ToString()
        }
    }
}

function Get-ComputerInfoData {
    $info = Get-ComputerInfo -ErrorAction Stop
    
    [PSCustomObject]@{
        CsName = $info.CsName
        CsDNSHostName = $info.CsDNSHostName
        CsDomain = $info.CsDomain
        CsManufacturer = $info.CsManufacturer
        CsModel = $info.CsModel
        CsPartOfDomain = $info.CsPartOfDomain
        CsPCSystemType = $info.CsPCSystemType.ToString()
        OsName = $info.OsName
        OsType = $info.OsType.ToString()
        OsVersion = $info.OsVersion
        OsBuildNumber = $info.OsBuildNumber
        OsArchitecture = $info.OsArchitecture
        OsSystemDrive = $info.OsSystemDrive
        OsLastBootUpTime = $info.OsLastBootUpTime
        OsInstallDate = $info.OsInstallDate
        BiosVersion = $info.BiosBIOSVersion -join "; "
        BiosSerialNumber = $info.BiosSeralNumber
        CsProcessors = $info.CsProcessors.Name -join "; "
        CsNumberOfProcessors = $info.CsNumberOfProcessors
        CsNumberOfLogicalProcessors = $info.CsNumberOfLogicalProcessors
        CsTotalPhysicalMemory = $info.CsTotalPhysicalMemory
        TimeZone = $info.TimeZone
    }
}

function Get-DiskVolumeData {
    Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -or $_.FileSystemLabel } | ForEach-Object {
        [PSCustomObject]@{
            UniqueId = $_.UniqueId
            DriveLetter = $_.DriveLetter
            DriveType = $_.DriveType.ToString()
            Size = $_.Size
            SizeRemaining = $_.SizeRemaining
            FileSystemLabel = $_.FileSystemLabel
            FileSystem = $_.FileSystem
            HealthStatus = $_.HealthStatus.ToString()
        }
    }
}

function Get-NetworkAdapterData {
    $adapters = Get-NetAdapter -IncludeHidden -ErrorAction Stop
    $dnsSettings = Get-DnsClient -ErrorAction SilentlyContinue
    
    $adapters | ForEach-Object {
        $adapter = $_
        $dns = $dnsSettings | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex }
        
        [PSCustomObject]@{
            InterfaceIndex = $adapter.InterfaceIndex
            Name = $adapter.Name
            InterfaceDescription = $adapter.InterfaceDescription
            MacAddress = $adapter.MacAddress
            Status = $adapter.Status.ToString()
            LinkSpeed = $adapter.LinkSpeed
            MediaType = $adapter.MediaType
            PhysicalMediaType = $adapter.PhysicalMediaType
            DriverVersion = $adapter.DriverVersion
            DriverDate = $adapter.DriverDate
            Virtual = $adapter.Virtual
            Hidden = $adapter.Hidden
            ConnectionSpecificSuffix = $dns.ConnectionSpecificSuffix
            RegisterThisConnectionsAddress = $dns.RegisterThisConnectionsAddress
        }
    }
}

function Get-IPAddressData {
    Get-NetIPAddress -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            InterfaceIndex = $_.InterfaceIndex
            InterfaceAlias = $_.InterfaceAlias
            IPAddress = $_.IPAddress
            PrefixLength = $_.PrefixLength
            AddressFamily = $_.AddressFamily.ToString()
            Type = $_.Type.ToString()
            PrefixOrigin = $_.PrefixOrigin.ToString()
            SuffixOrigin = $_.SuffixOrigin.ToString()
            AddressState = $_.AddressState.ToString()
            SkipAsSource = $_.SkipAsSource
            ValidLifetime = $_.ValidLifetime.TotalSeconds
        }
    }
}

function Get-DnsServerData {
    Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object {
        $ifIndex = $_.InterfaceIndex
        $_.ServerAddresses | ForEach-Object {
            [PSCustomObject]@{
                InterfaceIndex = $ifIndex
                ServerAddress = $_
                AddressFamily = "IPv4"
            }
        }
    }
    
    Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | ForEach-Object {
        $ifIndex = $_.InterfaceIndex
        $_.ServerAddresses | ForEach-Object {
            [PSCustomObject]@{
                InterfaceIndex = $ifIndex
                ServerAddress = $_
                AddressFamily = "IPv6"
            }
        }
    }
}

function Get-ArpCacheData {
    Get-NetNeighbor -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            InterfaceIndex = $_.InterfaceIndex
            InterfaceAlias = $_.InterfaceAlias
            IPAddress = $_.IPAddress
            LinkLayerAddress = $_.LinkLayerAddress
            State = $_.State.ToString()
            AddressFamily = $_.AddressFamily.ToString()
        }
    }
}

function Get-RouteData {
    Get-NetRoute -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            InterfaceIndex = $_.InterfaceIndex
            InterfaceAlias = $_.InterfaceAlias
            DestinationPrefix = $_.DestinationPrefix
            NextHop = $_.NextHop
            RouteMetric = $_.RouteMetric
            InterfaceMetric = $_.InterfaceMetric
            Protocol = $_.Protocol.ToString()
            AddressFamily = $_.AddressFamily.ToString()
            State = $_.State.ToString()
        }
    }
}

function Get-TcpConnectionData {
    Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            State = $_.State.ToString()
            OwningProcess = $_.OwningProcess
            CreationTime = $_.CreationTime
            OffloadState = $_.OffloadState.ToString()
        }
    }
}

function Get-UdpListenerData {
    Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            OwningProcess = $_.OwningProcess
            CreationTime = $_.CreationTime
        }
    }
}

function Get-ProcessData {
    $wmiProcesses = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | 
        Select-Object ProcessId, ParentProcessId, CommandLine, ExecutablePath, CreationDate
    
    Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object {
        $proc = $_
        $wmiProc = $wmiProcesses | Where-Object { $_.ProcessId -eq $proc.Id }
        
        [PSCustomObject]@{
            ProcessId = $proc.Id
            ProcessName = $proc.Name
            ParentProcessId = $wmiProc.ParentProcessId
            UserName = $proc.UserName
            CommandLine = $wmiProc.CommandLine
            ExecutablePath = $proc.Path
            StartTime = $proc.StartTime
            WorkingSet = $proc.WorkingSet64
            CPU = $proc.CPU
            HandleCount = $proc.HandleCount
            ThreadCount = $proc.Threads.Count
            Company = $proc.Company
            ProductVersion = $proc.ProductVersion
            FileVersion = $proc.FileVersion
            Description = $proc.Description
        }
    }
}

function Get-LocalUserData {
    Get-LocalUser -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            FullName = $_.FullName
            Description = $_.Description
            Enabled = $_.Enabled
            LastLogon = $_.LastLogon
            PasswordLastSet = $_.PasswordLastSet
            PasswordExpires = $_.PasswordExpires
            UserMayChangePassword = $_.UserMayChangePassword
            PasswordRequired = $_.PasswordRequired
            AccountExpires = $_.AccountExpires
            PrincipalSource = $_.PrincipalSource.ToString()
            SID = $_.SID.Value
        }
    }
}

function Get-LocalGroupData {
    Get-LocalGroup -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Description = $_.Description
            PrincipalSource = $_.PrincipalSource.ToString()
            SID = $_.SID.Value
        }
    }
}

function Get-GroupMemberData {
    $groups = Get-LocalGroup -ErrorAction Stop
    $results = [System.Collections.ArrayList]::new()
    
    foreach ($group in $groups) {
        try {
            $members = Get-LocalGroupMember -Group $group -ErrorAction Stop
            foreach ($member in $members) {
                $null = $results.Add([PSCustomObject]@{
                    GroupName = $group.Name
                    GroupSID = $group.SID.Value
                    MemberName = $member.Name
                    MemberSID = $member.SID.Value
                    ObjectClass = $member.ObjectClass
                    PrincipalSource = $member.PrincipalSource.ToString()
                })
            }
        }
        catch {
            # Some groups may not be enumerable
            Write-Log "Could not enumerate members of group $($group.Name): $_" -Level "WARN"
        }
    }
    
    return $results.ToArray()
}

function Get-ShareData {
    Get-SmbShare -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Path = $_.Path
            Description = $_.Description
            ScopeName = $_.ScopeName
            CurrentUsers = $_.CurrentUsers
            ShareType = $_.ShareType.ToString()
            Special = $_.Special
            CachingMode = $_.CachingMode.ToString()
        }
    }
}

function Get-InstalledSoftwareData {
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $registryPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName } | ForEach-Object {
        [PSCustomObject]@{
            DisplayName = $_.DisplayName
            DisplayVersion = $_.DisplayVersion
            Publisher = $_.Publisher
            InstallDate = $_.InstallDate
            InstallLocation = $_.InstallLocation
            UninstallString = $_.UninstallString
            QuietUninstallString = $_.QuietUninstallString
            EstimatedSize = $_.EstimatedSize
            RegistryPath = $_.PSPath
        }
    } | Sort-Object DisplayName -Unique
}

function Get-AutorunscData {
    if (-not (Test-Path $Script:AutorunscPath)) {
        Write-Log "autorunsc64.exe not found at $Script:AutorunscPath" -Level "WARN"
        return $null
    }
    
    $args = '-accepteula', '-a', '*', '-ct', '-s', '-h', '-nobanner', '*'
    
    try {
        $output = & $Script:AutorunscPath $args 2>&1
        $autorunData = $output | ConvertFrom-Csv -Delimiter "`t" -ErrorAction Stop | 
            Where-Object { $_.MD5 -and $_.MD5 -ne '' }
        
        $autorunData | ForEach-Object {
            [PSCustomObject]@{
                EntryLocation = $_.'Entry Location'
                Entry = $_.Entry
                Enabled = $_.Enabled
                Category = $_.Category
                Profile = $_.Profile
                Description = $_.Description
                Signer = $_.Signer
                Company = $_.Company
                ImagePath = $_.'Image Path'
                Version = $_.Version
                LaunchString = $_.'Launch String'
                MD5 = $_.MD5
                SHA1 = $_.'SHA-1'
                PESHA1 = $_.'PE-SHA1'
                PESHA256 = $_.'PESHA-256'
                SHA256 = $_.'SHA-256'
                IMP = $_.IMP
            }
        }
    }
    catch {
        Write-Log "Failed to run autorunsc: $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region Main Execution

try {
    Write-Log "=== Starting Endpoint Forensics Collection v$($Script:Version) ==="
    
    # Initialize
    Initialize-Directories
    $Script:HostUUID = Get-SystemUUID
    Write-Log "Host UUID: $Script:HostUUID"
    
    # Archive previous collection files (important: do this before writing new ones)
    Move-ProcessedFiles
    
    # Collect all data categories
    $collections = @(
        @{ Name = "ComputerInfo"; Function = { Get-ComputerInfoData } },
        @{ Name = "DiskVolumes"; Function = { Get-DiskVolumeData } },
        @{ Name = "NetworkAdapters"; Function = { Get-NetworkAdapterData } },
        @{ Name = "IPAddresses"; Function = { Get-IPAddressData } },
        @{ Name = "DnsServers"; Function = { Get-DnsServerData } },
        @{ Name = "ArpCache"; Function = { Get-ArpCacheData } },
        @{ Name = "Routes"; Function = { Get-RouteData } },
        @{ Name = "TcpConnections"; Function = { Get-TcpConnectionData } },
        @{ Name = "UdpListeners"; Function = { Get-UdpListenerData } },
        @{ Name = "Processes"; Function = { Get-ProcessData } },
        @{ Name = "Users"; Function = { Get-LocalUserData } },
        @{ Name = "Groups"; Function = { Get-LocalGroupData } },
        @{ Name = "GroupMembers"; Function = { Get-GroupMemberData } },
        @{ Name = "Shares"; Function = { Get-ShareData } },
        @{ Name = "InstalledSoftware"; Function = { Get-InstalledSoftwareData } }
    )
    
    # Add Autorunsc if not skipped (includes services and scheduled tasks)
    if (-not $SkipAutorunsc) {
        $collections += @{ Name = "Autorunsc"; Function = { Get-AutorunscData } }
    }
    
    # Execute all collections
    foreach ($collection in $collections) {
        $data = Invoke-SafeCollection -Name $collection.Name -ScriptBlock $collection.Function
        if ($null -ne $data) {
            # Ensure data is always an array
            if ($data -isnot [array]) {
                $data = @($data)
            }
            Write-NdjsonFile -FileName $collection.Name -Records $data
        }
    }
    
    # Write errors if any
    if ($Script:CollectionErrors.Count -gt 0) {
        Write-NdjsonFile -FileName "CollectionErrors" -Records $Script:CollectionErrors.ToArray()
    }
    
    # Cleanup old archives
    Remove-OldArchives
    
    $totalDuration = ((Get-Date) - $Script:StartTime).TotalSeconds
    Write-Log "=== Collection completed in $([math]::Round($totalDuration, 2)) seconds with $($Script:CollectionErrors.Count) errors ==="
}
catch {
    Write-Log "Fatal error during collection: $_" -Level "ERROR"
    throw
}

#endregion
