# Azure Honeypot & SIEM Detection Pipeline (Sentinel + KQL)

## Overview
This project simulates a real-world SOC detection workflow: deploying an internet-exposed Windows VM as a honeypot in Azure, generating brute-force login activity against it, and building a centralized logging, enrichment, and visualization pipeline using Azure Log Analytics and Microsoft Sentinel. The goal was to practice the full lifecycle a SOC analyst works with daily — from raw endpoint logs to a queryable, enriched SIEM with visual reporting — using KQL as the query language.

**Skills demonstrated:** Azure infrastructure deployment, Windows Security Event log analysis, SIEM architecture (Log Analytics Workspace + Sentinel), Azure Monitor Agent (AMA) log forwarding, Data Collection Rules (DCR), KQL-based threat detection, log enrichment via Sentinel Watchlists, geo-IP correlation, Sentinel Workbook/attack map visualization, and open-source threat intelligence (OSINT) correlation using VirusTotal and AbuseIPDB.

---

## Attack Map

![Attack Map](screenshots/19-attack-map.png)

*Visualization of failed logon attempts against the honeypot, plotted by source IP geolocation using a Sentinel Workbook.*

---

## Architecture

![Architecture Diagram](architecture/architecture-diagram.png)

```
Internet (open inbound NSG rule)
        │
        ▼
Windows 10 Enterprise VM — Standard D2s v3 (2 vCPUs, 8 GiB) — Australia East
(Windows Firewall disabled — intentionally exposed)
        │  Azure Monitor Agent (AMA)
        ▼
Data Collection Rule (DCR)
        │
        ▼
Log Analytics Workspace (LAW)
        │
        ▼
Microsoft Sentinel (SIEM)
        │
        ├──► Sentinel Watchlist (geoip) — enriches IP → geographic location
        │
        └──► Sentinel Workbook — visualizes enriched data as an attack map
        │
        ▼
KQL Queries / Detection, Enrichment & Visualization
```

---

## What I Built

### 1. Honeypot Deployment
- Provisioned a **Windows 10 Enterprise** VM in Azure.
  - **Size:** Standard D2s v3 (2 vCPUs, 8 GiB memory)
  - **Location:** Australia East (Zone 1)
- Modified the VM's Network Security Group (NSG) to allow **all inbound traffic**, deliberately exposing the machine to the internet.
- Disabled the Windows Firewall (`wf.msc`) across all profiles (Domain, Private, Public), removing local filtering to simulate a poorly hardened, internet-facing asset.

### 2. Baseline Log Verification
- Generated 3 manually-triggered failed login attempts using the account "employee" to simulate brute-force / credential-guessing activity.
- Verified the failed logons locally in **Event Viewer → Security Logs**, confirming **Event ID 4625** (An account failed to log on) for each attempt.
- Reviewed event detail fields including Account Name, Logon Type, and Failure Reason to understand what data Windows captures natively before any centralization occurs.

### 3. Centralized Log Collection
- Created a **Log Analytics Workspace (LAW)** as the central log repository.
- Deployed a **Microsoft Sentinel** instance and connected it to the LAW.
- Configured the **"Windows Security Events via AMA"** data connector.
- Created the associated **Data Collection Rule (DCR)** and observed the Azure Monitor Agent extension install on the VM.

### 4. Detection & Querying (KQL)
- Queried the LAW/Sentinel for failed logon events, now centralized rather than viewed locally.
- Wrote KQL queries to isolate and analyze Event ID 4625 activity, and to pivot on specific source IP addresses once real attack traffic began arriving (see `/kql-queries`).

### 5. Log Enrichment — Geo-IP Lookup
- Raw `SecurityEvent` logs contain only an `IpAddress` field, with no inherent geographic context.
- Imported a public Geo-IP CSV dataset (~54,000 rows) as a **Sentinel Watchlist** (`geoip`), keyed on the `network` field, to map IP ranges to geographic location data.
- Used the `ipv4_lookup()` KQL plugin to join the watchlist against failed logon events, enriching each entry with location data derived purely from the IP address.
- **Note on data discrepancy:** The Sentinel Watchlist geo-IP lookup placed the confirmed attacking IP (80.94.95.83) in Maarn, Netherlands, while VirusTotal and AbuseIPDB both associate this IP with Timișoara, Romania. This is a known limitation of static IP-geolocation datasets — IP block registration location often does not match the actual physical or ISP-reported location, particularly for hosting/proxy infrastructure. This highlights why SOC workflows should treat automated geo-IP enrichment as a starting point for triage rather than definitive attribution, and why cross-referencing multiple threat intelligence sources is standard practice rather than relying on a single dataset.

### 6. Attack Map Visualization
- Built a **Sentinel Workbook** to visualize failed logon attempts geographically, using the enriched geo-IP data from the `geoip` watchlist.
- Replaced the default workbook elements with a custom **Query** element, configured via the advanced (JSON) editor to plot attacker source locations on an interactive world map.
- The resulting map provides an at-a-glance view of where brute-force attempts against the honeypot are originating from, turning raw log data into an immediately interpretable visual for triage and reporting — a common deliverable expected of SOC analysts when briefing non-technical stakeholders.

---

## Sample KQL Queries

**All failed logon attempts:**
```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, IpAddress, LogonType, FailureReason
| order by TimeGenerated desc
```

**Activity from a specific source IP:**
```kql
SecurityEvent
| where IpAddress == "80.94.95.83"
| project TimeGenerated, EventID, Account, Computer, IpAddress, LogonType, Activity
| order by TimeGenerated desc
```

**Geo-IP enriched query (Watchlist lookup):**
```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "80.94.95.83"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```

See `/kql-queries` for the full set of query files.

---

## Findings

- Confirmed 3 manually-generated failed login attempts against the "employee" account, matching Event ID 4625, successfully forwarded from the VM to the Log Analytics Workspace shortly after the AMA/DCR pipeline was configured.
- Within hours of deployment, the honeypot began receiving genuine external brute-force traffic. Source IP **80.94.95.83** was observed conducting repeated RDP login attempts using multiple different usernames, captured via the same `SecurityEvent` / Event ID 4625 pipeline.
- Threat intelligence lookups confirmed this IP as a known, actively-maintained malicious actor:
  - **VirusTotal** (source: Guardpot) — associated with 807 malicious events across two attack vectors: TCP port scanning/network reconnaissance (798 events) and RDP connection attempts (9 events), active between November 2025 and July 2026. Location reported as Timișoara, Romania.
  - **AbuseIPDB** — reported 5,444 times by 302 distinct sources, with activity dating back to January 2023 and a most recent report within the hour of this writeup. Location reported as Timișoara, Romania.
  - **Sentinel Watchlist geo-IP enrichment** — placed the same IP in Maarn, Netherlands, illustrating a real-world discrepancy between static geo-IP datasets and live threat intelligence sources (see Log Enrichment section above).
- This confirms the earlier hypothesis that an internet-facing, unfiltered VM will be discovered by opportunistic scanning infrastructure rapidly and repeatedly. This particular IP was not an isolated one-off but a long-running, actively maintained scanning/brute-force source with a multi-year track record targeting exposed RDP hosts — consistent with **opportunistic, automated attack activity** rather than a targeted attack against this VM specifically.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force | T1110 | Repeated failed logon attempts using multiple usernames, observed both from manually-generated tests and from a real external actor (80.94.95.83), consistent with credential-guessing activity against an internet-exposed host. |
| Active Scanning | T1595 | Source IP 80.94.95.83 was independently confirmed via VirusTotal/Guardpot to have conducted TCP port scanning and network reconnaissance activity, consistent with pre-attack target discovery. |

---

## Lessons Learned / Next Steps

- Understanding the full log pipeline (endpoint → AMA → DCR → LAW → Sentinel) is critical — knowing *where* a log lives and *how* it got there is as important as knowing how to query it.
- KQL syntax overlaps conceptually with SQL and SPL (Splunk); the underlying logic of filtering, projecting, and aggregating transfers well across SIEM platforms.
- The failed logon attempts captured here are consistent with **opportunistic, automated scanning** rather than a targeted attack. Cloud IP ranges are publicly published, and services like Shodan and Censys continuously scan and index the entire internet for open ports and exposed services — meaning a misconfigured, internet-facing VM can be discovered and probed within hours of deployment, without ever being individually targeted. The open NSG rule combined with the disabled Windows Firewall is precisely what made this VM "visible" to that kind of scanning.
- Correlating a live observed IP against threat intelligence sources (VirusTotal, AbuseIPDB) turned a raw log entry into actionable context — this is a core SOC analyst skill: an alert is far more useful once you know whether the source has a track record.
- Log enrichment surfaced a real discrepancy between static geo-IP datasets and live threat intelligence — a reminder that automated enrichment should support analyst judgment, not replace it.
- **Next steps to extend this project:**
  - Build a Sentinel **Analytics Rule** to auto-generate an incident when failed logons exceed a threshold (e.g. 5 in 5 minutes).
  - Create a **Sentinel Playbook** (Logic App) to auto-block the offending source IP via NSG update, potentially using AbuseIPDB's API for automated reputation checks.
  - Add a **Workbook panel** trending failed logon volume and top offending source IPs over time, alongside the existing attack map.

---

## Cleanup Note
All Azure resources (VM, NSG, LAW, Sentinel workspace) were deprovisioned after project completion to avoid ongoing compute/ingestion costs.

---

## Sources
- VirusTotal / Guardpot threat summary for 80.94.95.83
- AbuseIPDB report history for 80.94.95.83

---

## Repo Structure
```
├── README.md
├── architecture/
│   └── architecture-diagram.png
├── screenshots/
│   ├── 01-nsg-inbound-rule.png
│   ├── 02-vm-overview.png
│   ├── 03-failed-logins-4625.png
│   ├── 04-failed-login-detail.png
│   ├── 05-law-created.png
│   ├── 06-sentinel-connected.png
│   ├── 07-ama-connector-config.png
│   ├── 08-dcr-creation.png
│   ├── 09-ama-extension-installed.png
│   ├── 10-kql-query-results.png
│   ├── 11-kql-ip-pivot-results.png
│   ├── 12-virustotal-threat-report.png
│   ├── 13-abuseipdb-report.png
│   ├── 14-watchlist-creation.png
│   ├── 15-watchlist-imported.png
│   ├── 16-geoip-enriched-results.png
│   ├── 17-security-events.png
│   ├── 18-geo-source-ip-analysis.png
│   └── 19-attack-map.png
├── kql-queries/
│   ├── failed-logon-4625.kql
│   ├── failed-logon-by-ip.kql
│   └── geo-source-ip-analysis.kql
└── docs/
    └── setup-steps.md
```
