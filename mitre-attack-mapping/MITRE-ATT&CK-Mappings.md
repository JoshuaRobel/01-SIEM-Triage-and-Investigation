# MITRE ATT&CK Technique Mappings & Detection Strategies

## Reconnaissance (TA0043)

### T1590 - Gather Victim Organization Information
**Observable:** DNS WHOIS queries for target domains, LinkedIn reconnaissance
**Detection Source:** Proxy logs, DNS logs
**Detection Method:** 
- Monitor bulk WHOIS queries from single source
- Alert on multiple LinkedIn profile views from same IP
**Case Studies:** SIEM-001 (initial phase), NET-2026-001

---

## Initial Access (TA0001)

### T1189 - Drive-by Compromise
**Observable:** Malicious redirects in HTTP response, EXE downloads from compromised websites
**Detection Source:** Proxy logs, IDS/IPS, Sysmon Event 1
**Detection Query:**
```spl
index=proxy action=block OR action=drop uri="*.exe" OR uri="*.dll"
| stats count by src_ip, dest_domain, uri
| where count > 5
```

### T1193 - Spearphishing Attachment
**Observable:** Office macro execution, suspicious attachment file extensions
**Detection Source:** Sysmon Event 1 (WINWORD.EXE parent), EDR logs
**Case Study:** PHISH-001, PHISH-002

---

## Execution (TA0002)

### T1059.001 - Command Line Interface (PowerShell)
**Observable:** Encoded PowerShell commands, download cradles, reflective DLL injection
**Event IDs:** Sysmon 1 (Process Creation), Windows Event 4688
**Detection Query:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where match(CommandLine, "(?i)-enc") OR match(CommandLine, "(?i)IEX")
| stats count by Computer, User, CommandLine
```
**Artifacts:** Command line args, parent process, child processes

### T1053.005 - Scheduled Task Execution
**Observable:** schtasks.exe execution, registry key creation in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache
**Event IDs:** Sysmon 1, Windows Event 4688, 4698
**False Positives:** Legitimate system tasks, backup software

### T1047 - Windows Management Instrumentation (WMI)
**Observable:** wmic.exe process creation, WMI event consumers, __EventFilter objects
**Event IDs:** Sysmon 1, 22 (DNS query)
**Real Case:** Lateral movement in SIEM-003 using WmiPrvSE.exe

---

## Persistence (TA0003)

### T1547.001 - Registry Run Keys / Startup Folder
**Observable:** Registry modifications in HKLM\Software\Microsoft\Windows\CurrentVersion\Run
**Event IDs:** Sysmon Event 12, 13, 14 (Registry events)
**Detection Query:**
```spl
index=sysmon EventCode=13
| where TargetObject="*CurrentVersion\\Run*"
| where Details contains ".exe" OR Details contains ".bat"
| stats count by Computer, User, TargetObject, Details
```

### T1547.014 - Kernel Modules and Drivers
**Observable:** Driver installation, .sys file creation in System32\drivers
**Event IDs:** Sysmon 6 (Driver load), 11 (File created)
**Detection:** Rootkit signatures, code signing validation

### T1053.005 - Scheduled Task
**Observable:** Malicious scheduled tasks executing at system startup or on intervals
**Real Example:** CASE-004 used Task Scheduler for ransomware persistence
**Remediation:** Remove task, check System32\Tasks directory

---

## Privilege Escalation (TA0004)

### T1548 - Abuse Elevation Control Mechanism
**Observable:** 
- UAC bypass techniques (fodhelper.exe, eventvwr.exe abuse)
- Failed token impersonation attempts
- Access to Protected Processes

**Event IDs:** 
- Windows Event 4672 (Special Privileges Assigned)
- Sysmon Event 1 (suspicious parent-child process relationships)

**Detection Query:**
```spl
index=sysmon EventCode=1 
| where ParentImage="*fodhelper.exe" OR ParentImage="*eventvwr.exe"
| stats count by Computer, User, Image, CommandLine
| where count > 0
```

### T1134.003 - Process Injection (Token Impersonation)
**Observable:** 
- CreateRemoteThread into LSASS.exe
- Access to LSASS with unusual access masks
- Mimikatz/gsecdump execution

**Event IDs:** 
- Sysmon 8 (CreateRemoteThread)
- Sysmon 10 (ProcessAccess)
- Windows Event 4672

**Real Investigation:** CASE-005 detected via Sysmon Event 10

---

## Defence Evasion (TA0005)

### T1027 - Obfuscated Files or Information
**Observable:** 
- Encoded PowerShell scripts
- Base64-encoded executables
- Executable files with misleading extensions (.txt containing .exe)
- Packed/obfuscated binaries

**Detection Methods:**
```spl
index=sysmon EventCode=1 
| where CommandLine contains "base64" OR CommandLine contains "IEX"
| table Computer, User, CommandLine, ParentImage
```

### T1140 - Deobfuscate/Decode Files or Information
**Observable:** 
- certutil.exe -decode usage
- powershell -encodedcommand with small data
- XXd, base64 utilities execution

**Event IDs:** Sysmon 1, Windows Event 4688

### T1036 - Masquerading
**Observable:** 
- svchost.exe running from unexpected directory
- lsass.exe child processes (legitimate lsass has no children)
- System32 files with mismatched timestamps

**Real Cases:** 
- CASE-004: Ransomware masquerading as Windows Update
- NET-2026-001: Malware renamed to explorer.exe

---

## Credential Access (TA0006)

### T1110 - Brute Force
**Observable:** 
- Multiple failed logon attempts (Event 4625)
- Distributed brute force (varies source IPs)
- Service account brute force attempts

**Detection Query:**
```spl
index=wineventlog EventCode=4625
| stats count(eval(EventCode=4625)) as failed by src_ip, user
| where failed > 10
| eval risk_score=failed*failed
| sort - risk_score
```

**Real Case:** SIEM-001 - 2,847 failed logons over 6 hours targeting domain admin account

### T1003.001 - LSASS Memory Dumping
**Observable:** 
- lsass.exe access from unusual processes
- Sysmon Event 10 with specific access masks
- Tool signatures: Mimikatz, Procdump

**Event IDs:** 
- Sysmon 10 (ProcessAccess)
- Windows Event 4656, 4663

**Malware Examples:**
- Mimikatz: Access code 0x1fffff (full access)
- Procdump: MiniDumpWriteDump API call
- Task Manager: Standard process view

**Filter Rules:**
```
alert if:
  TargetImage="C:\\Windows\\System32\\lsass.exe"
  AND SourceImage NOT IN (taskmgr.exe, svchost.exe, csrss.exe, wininit.exe)
  AND GrantedAccess IN (0x1fffff, 0x1010, 0x0040)
```

### T1557.002 - LLMNR/NBT-NS Poisoning
**Observable:** 
- LLMNR or NBT-NS requests for non-existent hosts
- Responder.py execution (Python process with network connections)
- Inbound LLMNR/NBT-NS responses from unusual source

**Detection:** Monitor for high volume LLMNR traffic, restrict LLMNR at network edge

---

## Discovery (TA0007)

### T1087 - Account Discovery
**Observable:** 
- Get-ADUser, net user command execution
- LDAP search queries
- Repeated authentication failures (probing for valid accounts)

**Event IDs:** Windows Event 4625 (failed logons), Sysmon 1

### T1526 - Cloud Service Enumeration
**Observable:** aws ec2-describe-instances, az vm list commands
**Detection:** Monitor for cloud CLI tool execution, check command history

### T1135 - Network Share Discovery
**Observable:** 
- net view, net use commands
- Sysmon Event 3 (network connections to IPC$ shares)
- Registry queries for SMB shares

**Real Case:** CASE-003 (insider threat) enumerated shares before data theft

---

## Lateral Movement (TA0008)

### T1021.002 - SMB / Windows Admin Shares
**Observable:** 
- Administrative shares (\\target\ADMIN$, \\target\C$)
- PsExec.exe or similar remote execution
- Sysmon Event 3 (SMB connections), Sysmon Event 1 (svchost parent)

**Detection Query:**
```spl
index=proxy OR index=firewall
| where dest_port=445 AND src_port != 445
| stats count by src_ip, dest_ip, user
| where count > 100
```

**Real Investigation:** SIEM-003 traced lateral movement via ADMIN$ shares

### T1021.001 - Remote Services (RDP)
**Observable:** 
- RDP logons (Event 4624 with LogonType=10)
- RDP port 3389 connections
- xfreerdp or mstsc.exe process execution

**Detection:** Monitor for after-hours RDP, RDP from unusual locations

### T1550.002 - Pass the Hash
**Observable:** 
- NTLM authentication without Kerberos
- Sysmon Event 3 (network connections) from unusual processes
- LSASS memory access preceding NTLM auth

**Real Case:** SIEM-003 used Pass-the-Hash for lateral movement

---

## Collection (TA0009)

### T1005 - Data from Local System
**Observable:** 
- File staging in temp directories
- Large file copy operations
- archive.exe, 7z, WinRAR execution

**Detection:** Monitor C:\Windows\Temp, %APPDATA%\Temp for large files

### T1056.004 - Keylogging / Keyboard Capture
**Observable:** 
- User32.dll SetWindowsHookEx API calls
- GetAsyncKeyState API usage
- Keylogger tool signatures

**Real Case:** CASE-005 used Keylogger for credential harvesting

### T1025 - Data from Removable Media
**Observable:** 
- USB device connection events
- File copy from device
- AutoRun infections

---

## Command & Control (TA0011)

### T1071.001 - Application Layer Protocol (HTTP/HTTPS)
**Observable:** 
- Regular HTTPS connections to suspicious domains
- Beaconing patterns (consistent intervals, file size)
- C2 domains with TLS certificate spoofing
- JA3 fingerprints matching known C2

**Zeek Detection:**
```zeek
event http_request(c: connection, method: string, uri: string, version: string, user_agent: string, request_body_len: count, response_body_len: count, status_code: count, status_msg: string, tags: set[string], username: string, password: string, capture_password: bool, content_type: string)
{
  if ( /\/api\/check-in/ in uri || /\/post/ in uri ) {
    print "Potential C2 beacon detected", c$id$orig_h, uri;
  }
}
```

**Real Case:** NET-2026-003 identified Cobalt Strike C2 via JA3 fingerprint

### T1008 - Alternative Protocols / Fallback C2
**Observable:** 
- DNS TXT record queries
- ICMP tunneling
- HTTP tunneling through proxy
- Fallback to hard-coded C2 IP

**Detection:** Monitor for unusual protocol use, protocol anomalies

### T1571 - Non-Standard Port
**Observable:** 
- C2 beaconing on unusual ports (e.g., HTTPS on 8443, 9443)
- Port hopping (changing C2 port per connection)
- Service detection mismatch (HTTP on 443)

**Real Example:** CASE-004 beaconed on TCP 8080 with HTTPS traffic

---

## Exfiltration (TA0010)

### T1041 - Exfiltration Over C2 Channel
**Observable:** 
- Large data transfers over C2 connection
- High entropy outbound traffic
- Outbound connections to C2 without incoming traffic

**Detection Query:**
```spl
index=firewall action=allow dest_ip=203.0.113.89 dest_port=443
| stats sum(bytes_out) as total_out by src_ip, dest_ip, hour
| where total_out > 104857600
| eval gb=round(total_out/1073741824, 2)
```

**Real Case:** SIEM-001 exfiltrated 2.3GB over 4 hours via C2

### T1020 - Exfiltration Over Unencrypted C2
**Observable:** Plaintext data in network traffic, base64-encoded data in HTTP requests

### T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol
**Observable:** 
- FTP data transfers
- Cleartext SMTP for data exfil
- SMB shares to external systems

---

## Impact (TA0040)

### T1486 - Data Encrypted for Impact (Ransomware)
**Observable:** 
- Process accessing many files in succession
- File extensions changing (bulk rename)
- Large write operations
- Self-destructing activity logs

**Real Case:** CASE-002 (Hive ransomware) deleted VSS copies, encrypted 3,847 files

**Detection:**
```spl
index=sysmon EventCode=11 
| stats count by Computer, Image, TargetFilename
| eval dir=dirname(TargetFilename)
| stats count by Computer, dir, Image
| where count > 1000
```

### T1561 - Disk Wipe
**Observable:** Cipher.exe execution, cipher /w usage, DiskWipe malware signatures

### T1490 - Inhibit System Recovery
**Observable:** 
- Volume Shadow Copy deletion (vssadmin delete shadows)
- Recovery partition deletion
- Windows Recovery deletion

**Real Case:** CASE-002 executed: `vssadmin delete shadows /all /quiet`

---

## Summary by Investigation

| Case ID | Primary Techniques | Detection Method |
|---------|-------------------|------------------|
| SIEM-001 | T1110, T1078, T1041 | Splunk correlation, Event 4625 spikes |
| SIEM-002 | T1059.001, T1027, T1005 | Sysmon Event 1 encoding detection |
| SIEM-003 | T1078, T1098, T1021.002 | Pass-the-Hash detection via NTLM |
| NET-2026-001 | T1189, T1071.001 | Wireshark HTTP analysis, JA3 fingerprint |
| NET-2026-003 | T1071.001, T1008 | Zeek conn.log interval analysis |
| CASE-002 | T1486, T1490, T1561 | File creation rate, vssadmin execution |
| CASE-005 | T1003.001, T1056.004 | Sysmon 10 (LSASS access) |
| PHISH-001 | T1566.001, T1204.002 | Email header analysis, sandbox detonation |

---

## Detection Gap Analysis

### Not Actively Monitored (HIGH RISK)
- T1127 - Trusted Developer Utilities (Living off the Land)
- T1218.009 - Regsvcs/Regasm execution
- T1218.013 - ProgramFiles Redirection

### Low-Signal Detections (High False Positive Rate)
- T1087 - Account Discovery (many legitimate tools use it)
- T1135 - Network Share Discovery

### Requires Investigation
- T1136 - Create Account (legitimate admins create accounts daily)
- T1546 - Event Triggered Execution

---

*This mapping connects real investigations to adversary techniques, enabling both detection engineering and threat hunting. Update with new cases quarterly.*
