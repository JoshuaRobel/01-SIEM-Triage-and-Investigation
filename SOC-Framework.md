# Security Operations Framework

## SOC Model

This lab simulates an internal enterprise SOC supporting a mid-sized corporate environment.

### Environment Assumptions
- Hybrid Windows Active Directory
- 500–1500 endpoints
- SIEM: Wazuh/ELK
- EDR deployed on all endpoints
- MFA enforced for privileged accounts
- Centralized log aggregation

---

## Severity Matrix

| Severity | Description | Example |
|----------|------------|--------|
| Low | Informational / benign anomaly | Failed logon from mistyped password |
| Medium | Suspicious activity requiring investigation | Repeated failed logons |
| High | Confirmed malicious activity | Successful brute force |
| Critical | Active compromise / ransomware / data exfiltration | Encryption or domain admin takeover |

---

## SLA Targets

| Severity | Response SLA | Escalation SLA |
|----------|-------------|---------------|
| Medium | 30 minutes | 1 hour |
| High | 15 minutes | 30 minutes |
| Critical | Immediate | Immediate |

---

## SOC Workflow

1. Alert Ingestion
2. Initial Triage
3. Technical Investigation
4. Impact Assessment
5. Containment
6. Escalation (if required)
7. Detection Improvement Feedback
