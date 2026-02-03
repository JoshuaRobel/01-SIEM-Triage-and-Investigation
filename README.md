# 01 — SIEM Triage & Investigation
## Enterprise SOC Simulation (Splunk-Based)

This repository simulates a corporate Security Operations Center (SOC) responsible for monitoring, investigating, and responding to security alerts across a Windows enterprise environment using Splunk Enterprise.

The documentation follows structured internal SOC reporting standards, including:

- Executive summaries
- Severity classification
- SLA alignment
- Technical investigation
- MITRE ATT&CK mapping
- Risk assessment
- Containment and response actions
- Detection engineering feedback

---

# 🏢 Simulated Corporate Environment

- 1,000+ Windows endpoints
- Hybrid Active Directory
- Splunk Enterprise for centralized logging
- EDR deployed on all endpoints
- MFA enforced on privileged accounts
- Perimeter firewall with geo-blocking

---

# 🚦 SOC Severity Matrix

| Severity | Description | Response SLA |
|----------|------------|--------------|
| Low | Informational / benign anomaly | 4 hours |
| Medium | Suspicious activity requiring investigation | 30 minutes |
| High | Confirmed malicious activity | 15 minutes |
| Critical | Active compromise | Immediate |

---

# 🔎 Investigations

| Case ID | Incident Type | Severity | Status |
|---------|--------------|----------|--------|
| SOC-2026-001 | Credential Access — Brute Force | High | Escalated |
| SOC-2026-002 | Execution + Command & Control | High | Contained |

Each investigation includes:

- Structured triage workflow
- SPL queries used
- Evidence collection
- Threat intelligence enrichment
- Impact analysis
- Response documentation

---

# 📂 Repository Structure

- investigations
- screenshots
- SOC-Framework.md

---

# 🎯 Purpose

This project demonstrates hands-on SOC Level 1 capability using enterprise-grade documentation standards aligned with real-world corporate SOC workflows.

