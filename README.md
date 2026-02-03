# 01 — SIEM Triage and Investigation
## Enterprise SOC Simulation Lab

This repository simulates an internal enterprise Security Operations Center (SOC) responsible for monitoring, triaging, investigating, and responding to security alerts across a hybrid Windows/Linux environment.

The objective of this lab is to demonstrate:

- Enterprise alert triage workflow
- Log correlation and pivot analysis
- Threat intelligence enrichment
- MITRE ATT&CK mapping
- Impact assessment and risk rating
- Escalation decision-making
- Detection engineering feedback loop

---

## 🏢 Simulated Corporate Environment

- ~1,000 Windows endpoints
- Hybrid Active Directory environment
- Centralized logging (SIEM: Wazuh/ELK simulation)
- Endpoint Detection & Response (EDR)
- MFA enforced on privileged accounts
- Perimeter firewall with geo-blocking

---

## 📊 SOC Severity Matrix

| Severity | Description | Response SLA |
|----------|------------|--------------|
| Low | Benign anomaly | 4 hours |
| Medium | Suspicious activity | 30 minutes |
| High | Confirmed malicious activity | 15 minutes |
| Critical | Active compromise | Immediate |

---

## 🔎 Investigations

| Case ID | Incident Type | Severity | Status |
|---------|--------------|----------|--------|
| SOC-2026-001 | Credential Access — Brute Force | High | Escalated |
| SOC-2026-002 | Suspicious PowerShell Execution | High | Contained |

---

## 🔁 SOC Workflow Demonstrated

1. Alert ingestion
2. Initial triage
3. Technical investigation
4. Threat intelligence enrichment
5. Impact assessment
6. Containment
7. Escalation (if required)
8. Detection improvement feedback

---

## 📂 Repository Structure

- investigations
- playbooks
- iocs
- screenshots
- SOC-Framework.md

---

## 🎯 Purpose

This project is designed to reflect real-world corporate SOC documentation standards rather than lab-style writeups.
