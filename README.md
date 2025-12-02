# Endpoint Forensics Collection for Azure Log Analytics

A distributed endpoint forensics solution that collects system configuration, network state, process information, and persistence mechanisms from Windows endpoints and ingests them into Azure Log Analytics via Azure Monitor Agent (AMA).

## 🎯 Overview

A distributed architecture where each endpoint:
1. Runs a local PowerShell script on a schedule
2. Generates NDJSON files with forensic data
3. Azure Monitor Agent picks up the files and sends to Log Analytics

## 📁 Repository Structure

```
endpoint-forensics/
├── Collect-EndpointForensics.ps1    # Main collection script (runs on endpoints)
├── Deploy-EndpointForensics.ps1     # Deployment script (installs solution)
├── ARCHITECTURE.md                   # Detailed architecture documentation
├── infrastructure/
│   ├── custom-tables.json           # ARM template for Log Analytics tables
│   └── data-collection-rule.json    # ARM template for DCR
└── queries/
    └── hunting-queries.kql          # KQL queries for threat hunting
```

## 🚀 Quick Start

### Prerequisites

1. **Azure Resources**
   - Log Analytics workspace
   - Data Collection Endpoint (optional, DCR can provide its own)
   
2. **On Each Endpoint**
   - Windows 10/11 or Windows Server 2016+
   - PowerShell 5.1+
   - Azure Monitor Agent installed
   - Local admin access (for deployment)

### Step 1: Create Azure Infrastructure

```powershell
# Create custom tables in your Log Analytics workspace
az deployment group create \
  --resource-group <your-rg> \
  --template-file infrastructure/custom-tables.json \
  --parameters workspaceName=<your-workspace>

# Create the Data Collection Rule
az deployment group create \
  --resource-group <your-rg> \
  --template-file infrastructure/data-collection-rule.json \
  --parameters workspaceResourceId=<full-workspace-resource-id>
```

### Step 2: Deploy to Endpoints

Copy the following files to each endpoint and run the deployment script:
- `Collect-EndpointForensics.ps1`
- `Deploy-EndpointForensics.ps1`
- `autorunsc64.exe` (download from [Sysinternals](https://live.sysinternals.com/autorunsc64.exe))

```powershell
# Run as Administrator
.\Deploy-EndpointForensics.ps1 -CollectionIntervalHours 6
```

### Step 3: Associate DCR with Endpoints

In Azure Portal:
1. Go to **Monitor** → **Data Collection Rules**
2. Select your DCR
3. Click **Resources** → **Add**
4. Select the VMs/servers to monitor

### Step 4: Verify Data Flow

```kusto
// Check if data is arriving (use AMA's built-in Heartbeat table for agent health)
Heartbeat
| where TimeGenerated > ago(1h)
| where Category == "Azure Monitor Agent"
| project TimeGenerated, Computer, OSType, Version

// Check if autorunsc data is arriving
EndpointForensics_Autorunsc_CL
| where TimeGenerated > ago(1h)
| summarize count() by Computer
```

## 📊 Data Collected

| Category | Description | Use Case |
|----------|-------------|----------|
| **ComputerInfo** | System identity, OS, hardware | Asset inventory |
| **Processes** | Running processes with command lines | Malware detection |
| **TcpConnections** | Active TCP connections | C2 detection |
| **UdpListeners** | UDP endpoints | Covert channels |
| **Autorunsc** | Persistence mechanisms (services, tasks, drivers, etc.) | Persistence hunting |
| **Users** | Local user accounts | Rogue accounts |
| **Groups** | Local groups | Privilege escalation |
| **GroupMembers** | Group memberships | Privilege abuse |
| **InstalledSoftware** | Installed applications | Vulnerability mgmt |
| **NetworkAdapters** | Network interfaces | Network mapping |
| **DnsServers** | DNS configuration | DNS tampering |
| **ArpCache** | ARP table | ARP spoofing |
| **Routes** | Routing table | Network pivoting |
| **Shares** | SMB shares | Data exposure |
| **DiskVolumes** | Disk/volume information | Storage analysis |
| **IPAddresses** | IP address configuration | Network analysis |

> **Note**: Services and Scheduled Tasks are included in Autorunsc output. Security Events and Heartbeat are collected natively by AMA - configure `windowsEventLogs` in your DCR for security events.

## 🔍 Hunting Queries

See `queries/hunting-queries.kql` for ready-to-use KQL queries including:

- **Persistence Hunting**: New/unsigned autorun entries
- **Network Hunting**: Connections to rare IPs/ports
- **Process Hunting**: Suspicious parent-child relationships
- **Privilege Hunting**: New admin group members
- **Baseline Deviation**: Detect changes from known-good state

Example - Find unsigned persistence:
```kusto
EndpointForensics_Autorunsc_CL
| where TimeGenerated > ago(1d)
| where Signer == "" or Signer contains "Not verified"
| project Computer, Category, Entry, ImagePath, MD5
```

## 💰 Cost Estimation

| Endpoints | Collection Interval | Monthly Data | Est. Cost |
|-----------|---------------------|--------------|-----------|
| 100 | 6 hours | ~2.3 GB | $6-8 |
| 1,000 | 6 hours | ~23 GB | $60-75 |
| 10,000 | 6 hours | ~230 GB | $600-750 |

*Costs based on pay-as-you-go pricing. Use Commitment Tiers for larger volumes.*

## 🔒 Security Considerations

1. **Script Signing**: Sign the collection script with a code-signing certificate
2. **File Permissions**: Only SYSTEM and Administrators can access installation folder
3. **AMA Authentication**: Uses managed identity, no credentials on disk
4. **Data in Transit**: HTTPS/TLS 1.2+ to Azure

## 🛠️ Customization

### Change Collection Interval
```powershell
.\Deploy-EndpointForensics.ps1 -CollectionIntervalHours 4
```

### Skip Autorunsc (if not needed)
```powershell
# In Collect-EndpointForensics.ps1, use:
.\Collect-EndpointForensics.ps1 -SkipAutorunsc
```

### Add Custom Collection
Edit `Collect-EndpointForensics.ps1` and add to the `$collections` array:
```powershell
@{ Name = "MyCustomData"; Function = { Get-MyCustomData } }
```

## 📋 Troubleshooting

### No data in Log Analytics
1. Check AMA is installed: `Get-Service AzureMonitorAgent`
2. Check DCR is associated: Azure Portal → DCR → Resources
3. Check files exist: `Get-ChildItem C:\ProgramData\EndpointForensics\outbox`

### Collection script errors
Check the log file:
```powershell
Get-Content C:\ProgramData\EndpointForensics\logs\collection_*.log | Select-Object -Last 50
```

### Scheduled task not running
```powershell
Get-ScheduledTask -TaskName "Endpoint Forensics Collector" | Get-ScheduledTaskInfo
```

## 📚 Additional Resources

- [Azure Monitor Agent Overview](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-overview)
- [Custom JSON Logs with AMA](https://learn.microsoft.com/azure/azure-monitor/vm/data-collection-log-json)
- [Data Collection Rules](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-rule-overview)
- [Sysinternals Autoruns](https://docs.microsoft.com/sysinternals/downloads/autoruns)

## 📄 License

This project is provided as-is for internal security operations use.
