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
