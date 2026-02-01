
# INV-001 — Windows Brute Force / Authentication Anomaly Triage (SOC Level 1)

> **THM SOC L1 alignment:** SOC Internals • Windows Security Monitoring • SIEM Triage for SOC • Threat Analysis Tools • Cyber Defence Frameworks

---

## Alert Summary
- **Alert name:** Windows Authentication Anomaly / Brute Force Suspected
- **Alert severity (initial):** Medium
- **SIEM source:** Wazuh / ELK (or <YOUR_SIEM>)
- **Detected on:** <DATE> <TIMEZONE>
- **Time window investigated:** <START_TS> → <END_TS>
- **Primary affected asset:** `<HOSTNAME>` (`<ASSET_IP>`)
- **Primary account(s):** `<USERNAME>` (and any others)
- **Suspected source IP(s):** `<SRC_IP_1>`, `<SRC_IP_2>`
- **Ticket / Case ID:** INV-001

### Screenshots to add
- `screenshots/INV-001-01-alert.png` (alert overview)
- `screenshots/INV-001-02-log-query.png` (query + results)
- `screenshots/INV-001-03-timeline.png` (event timeline)
- `screenshots/INV-001-04-enrichment.png` (IP reputation/WHOIS)

---

## 5Ws (SOC)
- **Who:** `<SRC_IP_1>` targeting `<USERNAME>` on `<HOSTNAME>`
- **What:** Repeated failed logon attempts consistent with brute force / password spraying behavior
- **When:** `<START_TS> → <END_TS>` (see timeline below)
- **Where:** Windows authentication logs from `<HOSTNAME>` ingested into SIEM (`<LOG_SOURCE>`)
- **Why:** Likely attempt to gain unauthorized access (credential guessing) leading to potential account compromise

---

## Initial Triage Decision
### Quick checks performed
- [ ] Confirm alert time window and asset identity
- [ ] Validate event types match authentication failures
- [ ] Identify if attempts are external (internet) or internal (LAN/VPN)
- [ ] Check whether any failures turned into a successful login
- [ ] Check whether targeted user is privileged (admin/service account)
- [ ] Check whether the source IP matches known corporate IPs / VPN / monitoring tools

### Triage verdict (initial)
- **Classification:** ☐ Benign ☐ Suspicious ✅ Malicious (suspected)
- **Rationale (1–2 lines):** Multiple failed logons from a single IP in short interval; no approved maintenance activity known; behavior matches brute force pattern.

---

## Evidence Collected

### Key Windows events (examples)
> Replace these with your actual events. Common Windows security Event IDs:
> - **4625** Failed logon
> - **4624** Successful logon
> - **4740** Account locked out
> - **4768/4769** Kerberos auth events (domain context)

#### Evidence Table
| Timestamp | Host | Event ID | User | Source IP | Logon Type | Outcome | Notes |
|---|---|---:|---|---|---:|---|---|
| `<TS_1>` | `<HOSTNAME>` | 4625 | `<USERNAME>` | `<SRC_IP_1>` | `<TYPE>` | Fail | `<reason/substatus>` |
| `<TS_2>` | `<HOSTNAME>` | 4625 | `<USERNAME>` | `<SRC_IP_1>` | `<TYPE>` | Fail | `<reason/substatus>` |
| `<TS_3>` | `<HOSTNAME>` | 4625 | `<USERNAME>` | `<SRC_IP_1>` | `<TYPE>` | Fail | `<reason/substatus>` |
| `<TS_4>` | `<HOSTNAME>` | 4624 | `<USERNAME>` | `<SRC_IP_1>` | `<TYPE>` | Success? | Only if present |

**Screenshot:** `screenshots/INV-001-02-log-query.png`

---

## SIEM Queries Used (Copy/Paste)
> Use whichever platform you actually have. Keep the one you used, delete the rest.

### Option A — Elastic / KQL style (example)
```text
event.code:4625 AND host.name:"<HOSTNAME>" AND user.name:"<USERNAME>" AND source.ip:"<SRC_IP_1>"
