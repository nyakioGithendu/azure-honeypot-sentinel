# azure-honeypot-sentinel
Deployed an internet-exposed Azure honeypot and built a Sentinel/KQL detection pipeline to identify brute-force login attempts (Event ID 4625, MITRE T1110).

Overview

This project simulates a real-world SOC detection workflow: deploying an internet-exposed Windows VM as a honeypot in Azure, generating brute-force login activity against it, and building a centralized logging and detection pipeline using Azure Log Analytics and Microsoft Sentinel. The goal was to practice the full lifecycle a SOC analyst works with daily — from raw endpoint logs to a queryable SIEM — using KQL as the query language.
Skills demonstrated: Azure infrastructure deployment, Windows Security Event log analysis, SIEM architecture (Log Analytics Workspace + Sentinel), Azure Monitor Agent (AMA) log forwarding, Data Collection Rules (DCR), and KQL-based threat detection.


### 1. Honeypot Deployment
- Provisioned a **Windows 10 Enterprise** VM in Azure.
  - **Size:** Standard D2s v3 (2 vCPUs, 8 GiB memory)
  - **Location:** Australia East (Zone 1)
- Modified the VM's Network Security Group (NSG) to allow **all inbound traffic**, deliberately exposing the machine to the internet.
- Disabled the Windows Firewall (`wf.msc`) across all profiles (Domain, Private, Public), removing local filtering to simulate a poorly hardened, internet-facing asset.


### 2. Baseline Log Verification
- Generated 3 failed login attempts using the account "employee" to simulate brute-force / credential-guessing activity.
- Verified the failed logons locally in **Event Viewer → Security Logs**, confirming **Event ID 4625** (An account failed to log on) for each attempt.
- Reviewed event detail fields including Account Name, Logon Type, and Failure Reason to understand what data Windows captures natively before any centralization occurs.
