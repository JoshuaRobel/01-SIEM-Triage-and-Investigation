# 01 — SIEM Triage and Investigation (Wazuh/ELK)

> **Goal:** Build SOC Level 1 job-ready evidence — alert triage, investigation, documentation, and escalation decisions.

## What this repo shows
- Practical SOC workflow (monitor → triage → investigate → enrich → document → escalate/close)
- Repeatable templates/playbooks
- Evidence artifacts (screenshots, logs, queries, timelines)

## Quick links
- 📁 Investigations: `./investigations/`
- 🧭 Playbooks: `./playbooks/`
- 🧾 IOC Lists: `./iocs/`

## Scope
- Ingest Windows + Linux logs into SIEM
- Generate alerts (auth anomalies, suspicious process, policy changes)
- Investigate alerts and document outcomes
- Tune detections to reduce false positives

## Minimum deliverables (to be “portfolio-ready”)
- 8+ investigations written in SOC format
- 2 playbooks (e.g., brute force, suspicious PowerShell)
- 1 IOC list per incident cluster
- Screenshots of dashboards + saved queries

## Investigation index
Create links as you add cases:
- [INV-001 — <Title>](./investigations/INV-001-<title>.md)
- [INV-002 — <Title>](./investigations/INV-002-<title>.md)

## Environment notes
- SIEM: Wazuh / ELK
- Endpoints: Windows + Linux
- Timezone handling: document timestamps consistently

