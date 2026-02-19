# Case Study: Brute Force Attack & Multi-Layer Defense Failure

**Case ID:** SIEM-001  
**Date:** 2025-11-15  
**Severity:** High  
**Status:** Escalated to Incident Response

---

## Executive Summary

An attacker conducted a distributed brute force attack against a domain admin account, successfully compromising credentials and establishing persistence. The attack succeeded due to gaps in authentication controls, network segmentation, and log monitoring.

**Key Findings:**
- 2,847 failed logon attempts over 6 hours
- 17 source IPs (distributed attack)
- Successful compromise after 2,100 failed attempts
- 4.3GB data exfiltrated over C2 channel
- Attack persisted for 12 days before detection

---

## Attack Progression (Cyber Kill Chain)

### 1. Reconnaissance (Day -3)
**Observable:** LDAP enumeration queries  
**Detection:** Firewall logs showing unusual LDAP traffic  
**Details:** Attacker discovered domain admin account "svc_admin" exists

### 2. Weaponization (Day -2)
**Observable:** Credential stuffing wordlist purchase on dark web  
**Detection:** N/A (external)  

### 3. Delivery (Day -1)
**Observable:** Distributed brute force attack from 17 compromised servers  
**Detection Method:**
- Failed logon spikes (Event 4625)
- Multiple source IPs
- Consistent target (svc_admin account)

**Event Log Analysis:**
```
Event ID: 4625
Logon Type: 3 (Network)
Failure Reason: Invalid credentials
Account: svc_admin
Time Range: 14:32 - 20:17 UTC
Source IPs: 203.0.113.x, 198.51.100.x, 192.0.2.x
Rate: ~8 failed logons/minute
```

**Why Detection Failed:**
- No alert configured for Event 4625 spike
- SIEM configured but no correlation rules
- Windows Event Log forwarding had 2-hour delay

### 4. Exploitation (Day 0)
**Observable:** Successful logon (Event 4624) after 2,147 failed attempts  
**Time:** 20:18 UTC  
**Logon Type:** 3 (Network)  
**Source:** 203.0.113.42 (compromised server in Bulgaria)

**Credential Details:**
- Username: svc_admin
- Password: "Welcomecom!2025" (weak despite policy)
- MFA Status: DISABLED for service accounts
- Last password change: 487 days prior

### 5. Installation (Days 0-1)
**Observable:**
- Powershell.exe execution with encoded commands
- Download of Cobalt Strike beacon
- Service creation: "Windows Update Service" (WUS)

**Sysmon Event 1 (Process Creation):**
```
Parent Process: svchost.exe
Image: C:\Windows\System32\powershell.exe
CommandLine: powershell.exe -NoP -sta -NonI -W Hidden -Enc JABzAD...
User: svc_admin
Time: 20:24 UTC

Child Process: C:\Windows\Temp\updates.exe
(MD5: a1b2c3d4e5f6g7h8i9j0)
```

**Why Installation Succeeded:**
- Service account had local admin rights
- No application whitelisting
- PowerShell execution logging not enabled
- Endpoint Detection & Response (EDR) agent was disabled for service accounts

### 6. Command & Control (Days 1-12)
**Observable:** C2 beaconing to 185.220.101.45:443

**Zeek Analysis (conn.log):**
```
ts = 2025-11-16 20:45:32
uid = C5aBrI4q3j9k2l1m
id.orig_h = 10.0.50.15 (compromised server)
id.resp_h = 185.220.101.45 (C2 server)
id.resp_p = 443
proto = tcp
duration = 45.231
orig_bytes = 1200
resp_bytes = 45000
conn_state = SF (established)
```

**Beacon Pattern Analysis:**
- Check-in interval: Every 60 seconds ± 5 seconds (tight jitter)
- Data transfer: 1-2 MB per beacon
- TLS fingerprint (JA3): 47d3cd...a2b1f (Cobalt Strike signature)
- User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" (spoofed)

**Why Detection Failed:**
- No outbound connection monitoring at firewall
- Proxy logs not forwarded to SIEM
- IDS/IPS in passive mode (no blocking)
- No threat intelligence feed for C2 domains

### 7. Exfiltration (Days 2-12)
**Observable:** Large outbound data transfers

**Firewall Analysis:**
- Destination: 185.220.101.45:443
- Volume: 2.3 GB over 10 days
- Timing: Consistent 50 MB/hour exfiltration
- Protocol: HTTPS (encrypted payload)

**Likely Data Stolen:**
- Domain admin credentials
- Active Directory dump
- SharePoint documents (HR, Finance, Legal)
- Email archives (2 executives)
- Database backups

**Why Detection Failed:**
- No DLP (Data Loss Prevention) system
- No baseline for normal data flow per account
- Encrypted HTTPS traffic couldn't be inspected
- No user behavior analytics

### 8. Actions on Objective (Days 5-12)
**Observable:**
- Additional domain admin account created: "svc_backup"
- Golden Ticket generation (Kerberos domain admin ticket)
- Domain member computers added to attacker-controlled OU
- GPO modifications for backdoor persistence

**Persistence Mechanisms:**
1. Service account "Windows Update Service" (WUS) - runs beacon every reboot
2. Scheduled task "Windows Maintenance" - triggers beacon hourly
3. Registry Run key - C:\Windows\Temp\svc.exe
4. Domain admin account (svc_backup) - for credential-based access

---

## Detection Timeline vs Reality Timeline

| Event | Actual Time | Detection Time | Gap |
|-------|------------|----------------|-----|
| Brute force starts | Day -1, 14:32 | Day 0, 09:45 (manual review) | 19 hours |
| Successful compromise | Day 0, 20:18 | Not detected | Never |
| Malware execution | Day 0, 20:24 | Day 1, 14:20 (EDR alert - IGNORED) | 18 hours |
| C2 beaconing | Day 1, 20:45 | Not detected | Never |
| Persistence created | Day 5, 03:12 | Not detected | Never |
| **Incident FOUND** | **Day 12** | **Day 12, 16:30 (manual audit)** | **Reported 12 days late** |

---

## Root Cause Analysis

### 1. Authentication Controls Failed
- **No MFA:** Service accounts exempt from multi-factor authentication
- **Weak Password Policy:** No complexity checks for "Welcome" prefix, no history validation
- **No Account Lockout:** Lockout threshold set to 0 (disabled)
- **No Anomaly Detection:** No baseline for service account access patterns

### 2. Detection Capabilities Insufficient
- **Event Log Forwarding Slow:** 2-hour delay for Windows events to SIEM
- **No Alerting Configured:** Event 4625 spike had no threshold alert
- **Log Retention Short:** Only 30 days of Firewall logs (attack detected on day 12)
- **EDR Agent Disabled:** Service accounts excluded from EDR monitoring
- **No Network Monitoring:** Outbound connections not captured

### 3. Defense Depth Insufficient
- **No Network Segmentation:** Server could reach external C2 directly
- **No Application Whitelisting:** Any executable could run on server
- **No PowerShell Logging:** No visibility into encoded command execution
- **No DLP System:** No detection of bulk data access/transfer
- **No EDR:** Endpoint visibility completely absent

### 4. Operational Gaps
- **No Incident Response Plan:** Manual audit only detected after 12 days
- **No Threat Intelligence:** C2 domain not recognized as malicious
- **No Regular Patching:** Server was 87 days overdue for security patches
- **No Privilege Audit:** Service account had full domain admin rights (excessive)

---

## Recommended Controls (Defense in Depth)

### Authentication Layer
**Priority 1 (CRITICAL):**
```
[ ] Implement MFA for ALL accounts, including service accounts
    - Windows Hello for Business
    - Smart cards for domain admins
    - Passwordless sign-in options
    
[ ] Strong password policy:
    - Minimum 14 characters
    - Complexity requirements (upper, lower, number, special)
    - Password history: last 24 passwords
    - No common patterns (Welcome, Admin, Company name)
    
[ ] Account lockout:
    - Threshold: 5 failed logons
    - Duration: 30 minutes
    - Reset counter: 30 minutes after last failure
```

### Detection Layer
**Priority 1 (CRITICAL):**
```
[ ] Event 4625 spike alert:
    - Condition: >10 failed logons in 15 minutes for same account
    - Severity: HIGH
    - Action: Immediate lock, disable account
    
[ ] Event 4624 after-hours alert:
    - Condition: Domain admin logon outside 06:00-22:00 Mon-Fri
    - Exception: On-call rotation list
    
[ ] PowerShell execution alert:
    - Condition: Encoded commands (-enc, -encodedcommand)
    - Source: Service accounts running PowerShell
    - Action: Block or require approval
```

**Priority 2 (HIGH):**
```
[ ] Windows Event Log forwarding:
    - Target: SIEM
    - Events: 4624, 4625, 4648, 4720, 4728, 4732
    - Latency: <5 seconds
    
[ ] Process execution monitoring:
    - Tool: Sysmon
    - Log parent-child process relationships
    - Alert on suspicious patterns: Office → PowerShell
    
[ ] Network egress monitoring:
    - Outbound traffic to external IPs
    - Port 443 baseline per server
    - Alert on 10x normal volume
```

### Defense Depth Layer
**Priority 1:**
```
[ ] Network segmentation:
    - Admin/service accounts in isolated VLAN
    - Firewall rules: Only allow necessary outbound
    - Deny all outbound C2 ports (443 to untrusted ASNs)
    
[ ] Application whitelisting:
    - Whitelist critical applications only
    - Prevent execution from Temp directories
    - Sign all enterprise applications
    
[ ] Endpoint Detection & Response (EDR):
    - Mandatory for ALL systems including servers
    - Service accounts included
    - Real-time response capability
    
[ ] Data Loss Prevention (DLP):
    - Monitor and block large file transfers
    - Inspect HTTPS traffic (MITM or endpoint agent)
    - Alert on unusual access patterns
```

### Operational Layer
**Priority 1:**
```
[ ] Incident Response Plan:
    - Procedures for account compromise
    - Escalation triggers
    - Communication templates
    - Response time SLA: <2 hours for confirmed breach
    
[ ] Regular privilege audits:
    - Quarterly review of domain admin membership
    - Remove excessive permissions from service accounts
    - Principle of least privilege enforcement
    
[ ] Patch management:
    - Apply security patches within 30 days
    - Critical patches within 7 days
    - Track and remediate overdue systems
```

---

## Implementation Roadmap

| Timeline | Control | Owner | Status |
|----------|---------|-------|--------|
| Immediate (Week 1) | Account lockout threshold | IT Ops | In Progress |
| Immediate (Week 1) | Event 4625 spike alert | SOC | In Progress |
| Short-term (Month 1) | MFA for privileged accounts | Identity Team | Planned |
| Short-term (Month 1) | Event log forwarding latency fix | IT Ops | Planned |
| Medium-term (Month 2-3) | EDR deployment to servers | Security | Planned |
| Medium-term (Month 2-3) | PowerShell logging & alerting | SOC | Planned |
| Long-term (Month 4-6) | Network segmentation implementation | Architecture | Proposed |

---

## Lessons Learned

1. **Service account security is critical:** Service accounts often have excessive privileges and weak authentication. Treat them as privileged.

2. **Detection must be fast:** A 19-hour gap between attack and detection is unacceptable. Automated alerting on Event 4625 spikes is essential.

3. **Defense in depth is non-negotiable:** Single-layer detection (SIEM alone) failed. Multiple layers (auth, network, endpoint, behavioral) needed.

4. **Encryption is a double-edged sword:** HTTPS C2 traffic evaded detection because we couldn't inspect encrypted traffic. DLP or EDR needed to detect exfiltration.

5. **Disabled controls are invisible attacks:** EDR agents disabled for service accounts meant we had zero visibility into malware execution.

---

*Prepared by: Incident Response Team*  
*Review Date: 2025-12-15*  
*Distribution: Security Leadership, Infrastructure Team, Risk Management*
