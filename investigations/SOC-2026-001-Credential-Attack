# CASE ID: SOC-2026-001
# Incident Type: Credential Access — Brute Force
# Severity: High
# Status: Escalated

---

# 1. Executive Summary

On 01 Feb 2026, the SIEM generated an alert indicating repeated failed authentication attempts targeting user account **j.smith** on host **WIN-SRV-01**.

Analysis confirmed 47 failed login attempts within a 5-minute window originating from external IP 185.234.10.77. Threat intelligence enrichment classified the IP as high confidence malicious.

The account was locked automatically. No successful authentication occurred. Due to malicious source reputation and credential attack pattern, the case was escalated to Tier 2.

---

# 2. Alert Metadata

| Field | Value |
|-------|--------|
| Detection Source | SIEM |
| Rule | Excessive Failed Logons |
| First Seen | 2026-02-01 14:02 UTC |
| Host | WIN-SRV-01 |
| Target Account | j.smith |
| Source IP | 185.234.10.77 |

---

# 3. Initial Triage

- 47 Event ID 4625 entries detected
- Logon Type: 3 (Network)
- Account lockout (Event ID 4740) confirmed
- No 4624 successful logon observed
- Source external to corporate network

Assessment: Suspicious → Full investigation required.

---

# 4. Technical Investigation

## 4.1 Log Analysis

Query:

```text
event.code:4625 AND host.name:"WIN-SRV-01"
