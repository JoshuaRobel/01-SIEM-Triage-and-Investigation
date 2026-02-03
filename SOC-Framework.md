# SOC Framework — Enterprise Simulation

## SOC Operating Model

This lab models an internal corporate SOC operating under defined response SLAs and severity classification.

---

## Incident Classification

| Category | Examples |
|----------|----------|
| Credential Access | Brute force, password spraying |
| Execution | Suspicious PowerShell, encoded commands |
| Privilege Escalation | Unauthorized admin group additions |
| Lateral Movement | SMB pivoting |
| Impact | Ransomware, encryption activity |

---

## Investigation Standards

Each investigation must include:

- Executive Summary
- Alert Metadata
- Initial Triage Assessment
- Technical Investigation
- Evidence Tables
- MITRE ATT&CK Mapping
- Impact Assessment
- Response Actions
- Detection Engineering Improvements
- Escalation Decision
- Evidence References

---

## SOC Escalation Criteria

Escalation required if:

- Malicious external source confirmed
- Privileged account impacted
- Successful execution observed
- Lateral movement detected
- Data exfiltration indicators present
