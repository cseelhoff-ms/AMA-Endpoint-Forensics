# Endpoint Forensics Collection Architecture

## Overview

A distributed, agent-based approach using Azure Monitor Agent (AMA) and Data Collection Rules (DCR) to ingest endpoint forensic data into Azure Log Analytics.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              WINDOWS ENDPOINT                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                     Scheduled Task (SYSTEM, every 4-24h)                    ││
│  │  ┌───────────────────────────────────────────────────────────────────────┐  ││
│  │  │                    Collect-EndpointForensics.ps1                      │  ││
│  │  │  • Runs autorunsc64.exe (Sysinternals)                                │  ││
│  │  │  • Collects: Processes, TCP/UDP, Users, Groups, Shares, etc.          │  ││
│  │  │  • Generates NDJSON files per data category                           │  ││
│  │  └───────────────────────────────────────────────────────────────────────┘  ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
│                                      │                                           │
│                                      ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │              C:\ProgramData\EndpointForensics\outbox\                       ││
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           ││
│  │  │Autorunsc.json│ │Processes.json│ │TcpConn.json │ │ Users.json  │  ...     ││
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘           ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
│                                      │                                           │
│                                      ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                      Azure Monitor Agent (AMA)                              ││
│  │  • Watches outbox folder for *.ndjson files                                 ││
│  │  • Configured via Data Collection Rule (DCR)                                ││
│  │  • Handles offline buffering and retry                                      ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼ (HTTPS/TLS 1.2+)
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                    AZURE                                         │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                   Data Collection Rule (DCR)                                ││
│  │  • Custom JSON Logs data source                                             ││
│  │  • Transformation: maps fields, adds TimeGenerated                          ││
│  │  • Routes to appropriate custom tables                                       ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
│                                      │                                           │
│                                      ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                     Log Analytics Workspace                                 ││
│  │  ┌─────────────────────────────────────────────────────────────────────┐   ││
│  │  │ Custom Tables:                                                       │   ││
│  │  │  • EndpointForensics_Autorunsc_CL                                   │   ││
│  │  │  • EndpointForensics_Processes_CL                                   │   ││
│  │  │  • EndpointForensics_TcpConnections_CL                              │   ││
│  │  │  • EndpointForensics_Users_CL                                       │   ││
│  │  │  • EndpointForensics_NetworkAdapters_CL                             │   ││
│  │  │  • ... (one per data category)                                      │   ││
│  │  └─────────────────────────────────────────────────────────────────────┘   ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
│                                      │                                           │
│                                      ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                     Analytics & Hunting                                     ││
│  │  • Azure Sentinel (SIEM)                                                    ││
│  │  • KQL Workbooks for persistence hunting                                    ││
│  │  • Scheduled Analytics Rules for anomaly detection                          ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Key Improvements Over Draft

Your draft was solid, but here are the gaps I identified and addressed:

### 1. **Separate NDJSON Files Per Table (CRITICAL)**

Your draft wrote everything to a single JSON file with a `_Table` field. This approach has issues:
- AMA Custom JSON Logs expects a consistent schema per file pattern
- Mixing schemas in one file requires complex transformations
- **Solution**: Write separate NDJSON files per data category (e.g., `Autorunsc.ndjson`, `Processes.ndjson`)

### 2. **Missing Installed Software Collection**

Your original scripts didn't collect installed software. This is critical for:
- Vulnerability management
- Detecting unauthorized software
- License compliance

### 3. **Error Handling and Logging**

Your draft had minimal error handling. Added:
- Per-collection error capture
- Error logging to separate file
- Graceful degradation if one collection fails

### 4. **File Rotation Strategy Issues**

AMA can miss files if they're deleted too quickly. Improved rotation logic:
- Move processed files to archive folder
- Keep archives for configurable retention period
- Use file age, not just date

### 5. **Missing DCR Schema Definitions**

Your draft mentioned tables would auto-create. While true, explicit schema:
- Ensures correct data types
- Prevents schema drift
- Enables proper indexing

### 6. **Missing Deployment Automation**

Added complete deployment scripts for:
- Intune/SCCM deployment package
- Azure infrastructure (Bicep/ARM)
- DCR configuration

### Note: What's NOT Collected (Handled Elsewhere)

- **Services & Scheduled Tasks**: Already collected by `autorunsc -a *` (includes `-a s` for services and `-a t` for tasks)
- **Security Events**: Configure AMA's native `windowsEventLogs` data source in your DCR
- **Heartbeat**: AMA provides its own heartbeat to the built-in `Heartbeat` table

---

## Data Categories Collected

| Category | Description | Primary Use Case |
|----------|-------------|------------------|
| **ComputerInfo** | System identity, OS version, domain membership | Asset inventory |
| **DiskVolumes** | Volume IDs, sizes, labels | Storage analysis |
| **NetworkAdapters** | MACs, status, interface details | Network mapping |
| **IPAddresses** | All IP addresses per interface | Network analysis |
| **DnsServers** | Configured DNS servers | DNS poisoning detection |
| **DnsSearchSuffixes** | DNS suffix search list | Lateral movement analysis |
| **ArpCache** | ARP table entries | ARP spoofing detection |
| **Routes** | Routing table | Network pivot detection |
| **TcpConnections** | Active TCP connections | C2 detection, data exfil |
| **UdpListeners** | UDP endpoints | Covert channel detection |
| **Processes** | Running processes with command lines | Malware detection |
| **Users** | Local user accounts | Rogue account detection |
| **Groups** | Local groups | Privilege escalation detection |
| **GroupMembers** | Group memberships | Privilege abuse detection |
| **Shares** | SMB shares | Data exposure analysis |
| **Autorunsc** | Persistence mechanisms (includes services, tasks, drivers, etc.) | Persistence hunting |
| **InstalledSoftware** | Installed applications | Vulnerability mgmt |

> **Note**: Services and Scheduled Tasks are captured within the Autorunsc output. Security Events and Heartbeat are handled by AMA natively.

---

## File Structure

### On Each Endpoint

```
C:\ProgramData\EndpointForensics\
├── Collect-EndpointForensics.ps1    # Main collection script
├── autorunsc64.exe                   # Sysinternals Autoruns
├── config.json                       # Collection configuration
├── outbox\                           # AMA watches this folder
│   ├── ComputerInfo.ndjson
│   ├── Processes.ndjson
│   ├── TcpConnections.ndjson
│   ├── Autorunsc.ndjson
│   └── ... (one file per category)
├── archive\                          # Processed files (7-day retention)
│   └── 2024-12-01_143022\
│       ├── ComputerInfo.ndjson
│       └── ...
└── logs\                             # Script execution logs
    └── collection.log
```

### NDJSON File Format

Each file contains newline-delimited JSON. Every record includes standard fields:

```json
{"TimeGenerated":"2024-12-02T14:30:22.000Z","Computer":"WORKSTATION01","HostUUID":"12345678-1234-1234-1234-123456789ABC","SnapshotId":"abc123","ProcessName":"notepad.exe","ProcessId":1234,"CommandLine":"notepad.exe C:\\temp\\file.txt",...}
{"TimeGenerated":"2024-12-02T14:30:22.000Z","Computer":"WORKSTATION01","HostUUID":"12345678-1234-1234-1234-123456789ABC","SnapshotId":"abc123","ProcessName":"explorer.exe","ProcessId":5678,"CommandLine":"C:\\Windows\\explorer.exe",...}
```

---

## Azure Infrastructure Requirements

### 1. Log Analytics Workspace

- SKU: Pay-as-you-go or Commitment Tier (based on volume)
- Retention: 90 days minimum (adjust based on compliance)
- Region: Same as your endpoints for optimal latency

### 2. Data Collection Endpoint (DCE)

- Required for AMA to know where to send data
- One per region where endpoints exist

### 3. Data Collection Rule (DCR)

- One DCR per data category (recommended) OR
- Single DCR with multiple data sources
- Includes:
  - Data source: Custom JSON Logs
  - File patterns: `C:\ProgramData\EndpointForensics\outbox\*.ndjson`
  - Transformations: Field mapping, TimeGenerated extraction
  - Destinations: Log Analytics workspace + custom table

### 4. Custom Tables

Create these tables BEFORE configuring DCR:

| Table Name | Primary Fields |
|------------|----------------|
| `EndpointForensics_Heartbeat_CL` | TimeGenerated, Computer, HostUUID, ScriptVersion, CollectionDuration |
| `EndpointForensics_ComputerInfo_CL` | TimeGenerated, Computer, HostUUID, CsDomain, OsVersion, ... |
| `EndpointForensics_Processes_CL` | TimeGenerated, Computer, HostUUID, ProcessName, ProcessId, CommandLine, ... |
| `EndpointForensics_Autorunsc_CL` | TimeGenerated, Computer, HostUUID, EntryLocation, Entry, Signer, MD5, SHA256, ... |
| ... | ... |

---

## Deployment Strategy

### Option A: Intune (Modern Management)

1. Package script + autorunsc64.exe as Win32 app
2. Deploy to device groups
3. Use Proactive Remediations for health monitoring

### Option B: SCCM/MECM (Traditional)

1. Create Application with deployment type
2. Deploy to collections
3. Use compliance baselines for monitoring

### Option C: Group Policy

1. Copy files via GPO file preferences
2. Create scheduled task via GPO
3. Less visibility into deployment status

### Option D: Manual/Script

1. Use deployment script for standalone machines
2. Suitable for testing or small environments

---

## Security Considerations

### Script Signing

- Sign `Collect-EndpointForensics.ps1` with code-signing certificate
- Configure execution policy to require signed scripts
- Prevents tampering with collection logic

### File Permissions

```
C:\ProgramData\EndpointForensics\
    Owner: SYSTEM
    Permissions:
        SYSTEM: Full Control
        Administrators: Full Control
        Users: Read (for troubleshooting only)
```

### AMA Managed Identity

- AMA uses system-assigned managed identity
- DCR association grants permissions automatically
- No credentials stored on endpoints

### Network Security

- AMA uses HTTPS/TLS 1.2+
- Can work through proxies
- Supports Private Link for private connectivity

---

## Cost Estimation

### Log Analytics Ingestion Costs

Approximate data volume per endpoint per collection:

| Data Category | Avg Size | Daily (4h interval) |
|---------------|----------|---------------------|
| ComputerInfo | 1 KB | 6 KB |
| Processes | 50 KB | 300 KB |
| TcpConnections | 20 KB | 120 KB |
| Autorunsc | 30 KB | 180 KB |
| All Other | 25 KB | 150 KB |
| **Total** | **~126 KB** | **~756 KB** |

**Monthly per endpoint**: ~23 MB
**1,000 endpoints**: ~23 GB/month ≈ $60-75/month at pay-as-you-go

### Cost Optimization

1. Use Commitment Tiers for >100 GB/day
2. Reduce collection frequency for stable environments
3. Filter out noisy/low-value data in transformations
4. Set appropriate retention periods per table

---

## Implementation Checklist

### Phase 1: Azure Infrastructure
- [ ] Create/identify Log Analytics workspace
- [ ] Create Data Collection Endpoint
- [ ] Create custom tables (see schema files)
- [ ] Create Data Collection Rule(s)
- [ ] Test DCR with manual file upload

### Phase 2: Script Development
- [ ] Finalize collection script
- [ ] Test on representative endpoints
- [ ] Sign script with code-signing certificate
- [ ] Package with autorunsc64.exe

### Phase 3: Pilot Deployment
- [ ] Deploy AMA to pilot group
- [ ] Associate DCR with pilot machines
- [ ] Deploy collection package
- [ ] Validate data in Log Analytics
- [ ] Tune collection frequency

### Phase 4: Production Rollout
- [ ] Deploy AMA to all endpoints
- [ ] Associate DCR
- [ ] Deploy collection package
- [ ] Monitor ingestion metrics
- [ ] Create alerting for collection failures

### Phase 5: Analytics
- [ ] Create KQL queries for common hunts
- [ ] Build workbooks for visualization
- [ ] Configure Sentinel analytics rules
- [ ] Document investigation playbooks

---

## Next Steps

1. Review the collection script in `Collect-EndpointForensics.ps1`
2. Review Azure infrastructure in `infrastructure/` folder
3. Review custom table schemas in `schemas/` folder
4. Test in lab environment before production deployment
