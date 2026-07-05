# Setup Steps

This document walks through how the honeypot and detection pipeline were built, step by step. For findings and analysis, see the main [README](../README.md).

---

## Part 1 — Azure Subscription
1. Created an Azure subscription (free trial credit).
2. Logged into the Azure Portal at https://portal.azure.com.

---

## Part 2 — Create the Honeypot (Azure Virtual Machine)
1. In the Azure Portal, searched for **Virtual machines** → **Create**.
2. Configured the VM:
   - **OS:** Windows 10 Enterprise
   - **Size:** Standard D2s v3 (2 vCPUs, 8 GiB memory)
   - **Location:** Australia East (Zone 1)
3. Recorded the VM's admin username and password securely (not committed to this repo).
4. Opened the VM's **Network Security Group (NSG)** and added an inbound rule allowing **all traffic**, intentionally exposing the VM to the internet.
5. Logged into the VM via RDP and disabled the Windows Firewall:
   - `Start` → `wf.msc` → **Properties** → set Domain, Private, and Public profiles to **Off**.

---

## Part 3 — Logging In and Inspecting Logs
1. Deliberately failed 3 login attempts using a non-existent account ("employee") to simulate brute-force activity.
2. Logged into the VM and opened **Event Viewer** → **Windows Logs** → **Security**.
3. Located the 3 failed logon events, confirming **Event ID 4625** for each.
4. Reviewed event details (Account Name, Logon Type, Failure Reason) to understand what data is captured locally before centralizing logs.

---

## Part 4 — Log Forwarding and KQL
1. Created a **Log Analytics Workspace (LAW)** to act as the central log repository.
2. Created a **Microsoft Sentinel** instance and connected it to the LAW.
3. Under Sentinel **Data Connectors**, configured **"Windows Security Events via AMA"**.
4. Created the associated **Data Collection Rule (DCR)**, scoped to the honeypot VM.
5. Confirmed the **Azure Monitor Agent (AMA)** extension installed automatically on the VM (visible under the VM's **Extensions** blade).
6. Queried the LAW directly using KQL:
   ```kql
   SecurityEvent
   | where EventID == 4625
   ```
7. Left the VM running to allow real, opportunistic internet traffic to reach it. Within hours, genuine external brute-force attempts began appearing in the logs from source IP `80.94.95.83`.
8. Cross-referenced this IP against **VirusTotal** and **AbuseIPDB**, confirming a long-standing history of scanning and brute-force activity.

---

## Part 5 — Log Enrichment and Finding Location Data
1. Observed that raw `SecurityEvent` logs contain only an `IpAddress` field, with no built-in geographic context.
2. Downloaded the public `geoip-summarized.csv` dataset (~54,000 rows).
3. In Sentinel, created a **Watchlist**:
   - **Name/Alias:** geoip
   - **Source type:** Local File
   - **Number of lines before row:** 0
   - **Search key:** network
4. Allowed the watchlist to fully import (~54,000 rows).
5. Ran an enrichment query using the `ipv4_lookup()` plugin to join the watchlist against failed logon events:
   ```kql
   let GeoIPDB_FULL = _GetWatchlist("geoip");
   let WindowsEvents = SecurityEvent
       | where IpAddress == "80.94.95.83"
       | where EventID == 4625
       | order by TimeGenerated desc
       | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
   WindowsEvents
   ```
6. Noted a discrepancy: the watchlist enrichment placed the attacking IP in Maarn, Netherlands, while VirusTotal and AbuseIPDB both reported Timișoara, Romania — highlighting the limitations of static geo-IP datasets versus live threat intelligence sources.

---

## Part 6 — Attack Map Creation
1. In Sentinel, created a new **Workbook**.
2. Deleted the default prepopulated elements.
3. Added a new **Query** element.
4. Opened the **Advanced Editor** tab and pasted the provided `map.json` configuration.
5. Reviewed the underlying query, the map's visualization settings, and the resulting rendered map.
6. Observed the final attack map, plotting failed logon attempts by enriched geographic location — providing an at-a-glance visual of where brute-force activity against the honeypot originated from.

---

## Cleanup
Once documentation and screenshots were complete, all Azure resources (VM, NSG, LAW, Sentinel workspace) were deallocated and then deleted via the resource group to stop all further billing.
