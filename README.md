# Cyber Defence Frameworks

Security operations methodologies and strategic defence frameworks applied to real-world scenarios.

## Contents

### MITRE ATT&CK Mapping
Technique-to-observable mappings derived from investigations across the portfolio. 25+ techniques documented with detection strategies and observable indicators.

**Key Mappings:**
| Technique | ID | Observable | Detection Source |
|-----------|-----|------------|------------------|
| Brute Force | T1110 | 10+ failed logins in 5 min | Windows Event 4625 |
| Valid Accounts | T1078 | Service account interactive logon | Windows Event 4624 |
| PowerShell | T1059.001 | Encoded commands, download cradles | Sysmon Event 1 |
| LSASS Memory | T1003.001 | Access to lsass.exe | Sysmon Event 10 |
| C2 Beaconing | T1071.001 | Regular HTTPS intervals | Zeek conn.log |

### Cyber Kill Chain Analysis
Attack phase identification and detection opportunities mapped to the Lockheed Martin Cyber Kill Chain.

**Applied in:**
- SIEM-001: Full kill chain from reconnaissance to exfiltration
- NET-2026-003: Weaponisation through C2 establishment
- PHISH-002: Delivery and exploitation phases

### Incident Response Lifecycle
NIST SP 800-61 based incident response process documentation.

**Phases Implemented:**
1. Preparation — Tooling and playbook readiness
2. Detection & Analysis — Alert triage and validation
3. Containment — Short-term and long-term isolation
4. Eradication — Threat removal and system cleaning
5. Recovery — Service restoration and monitoring
6. Post-Incident — Lessons learned and improvements

### Defence in Depth
Multi-layer security architecture reviews and gap analysis from investigations.

**Layers Analysed:**
- Perimeter (firewall, IDS/IPS)
- Network (segmentation, east-west monitoring)
- Endpoint (EDR, host-based firewall)
- Application (authentication, authorisation)
- Data (encryption, DLP)

## Case Studies

Real-world framework application examples:
- **Case Study 1:** Brute force detection gaps and layered defence failures
- **Case Study 2:** C2 beaconing detection through multiple control layers
- **Case Study 3:** BEC prevention through email + human + process controls

---

*Frameworks provide structure; investigations provide context. Both are necessary for effective security operations.*
