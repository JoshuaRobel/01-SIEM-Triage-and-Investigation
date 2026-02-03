CASE ID: SOC-2026-001
Incident Type: Credential Access — Brute Force

Severity: High
Status: Escalated

1. Executive Summary

On 01 February 2026, Splunk generated an alert for excessive failed authentication attempts targeting user account j.smith on server WIN-SRV-01.

Analysis identified 47 failed Windows Event ID 4625 events within a five-minute window originating from external IP address 185.234.10.77.

Threat intelligence enrichment confirmed the source IP has a high malicious confidence rating.

No successful authentication (Event ID 4624) was observed. The account was automatically locked (Event ID 4740) after threshold breach.

Due to confirmed malicious IP reputation and credential attack behavior, the case was escalated to Tier 2 SOC.

2. Alert Metadata
Field	Value
Detection Source	Splunk Enterprise
Detection Rule	Excessive Failed Logons
First Seen	2026-02-01 14:02:12 UTC
Last Seen	2026-02-01 14:07:01 UTC
Host	WIN-SRV-01
Target Account	j.smith
Source IP	185.234.10.77
Logon Type	3 (Network)
3. Initial Triage

47 instances of Event ID 4625 identified

No matching Event ID 4624 (successful login)

Event ID 4740 confirmed account lockout

Source IP external to corporate IP range

No scheduled red team or penetration test activity

Assessment: Activity consistent with brute force credential attack.

4. Technical Investigation
4.1 Failed Authentication Analysis (SPL)

SPL Query Used:

index=wineventlog EventCode=4625 host="WIN-SRV-01"
| stats count by Account_Name, Source_Network_Address
| sort - count

Findings:

47 failed attempts within 5 minutes

All attempts targeted account: j.smith

Source IP: 185.234.10.77

Attempt rate: ~2–3 per second

No additional user accounts targeted

No correlated successful authentication events

4.2 Successful Logon Verification (SPL)

SPL Query Used:

index=wineventlog (EventCode=4624 OR EventCode=4740) host="WIN-SRV-01"
| table _time, EventCode, Account_Name, Source_Network_Address

Results:

No EventCode 4624 entries for j.smith

Single EventCode 4740 confirming account lockout

No abnormal login activity following lockout

5. Threat Intelligence Enrichment

Source IP: 185.234.10.77

Intelligence Source	Result
GeoIP	Russia
ASN	Offshore Hosting Provider
AbuseIPDB	92% Malicious Confidence
VirusTotal	12 Security Vendor Detections
Known Botnet Activity	Previously Reported

Conclusion: High confidence malicious infrastructure.

6. MITRE ATT&CK Mapping
Tactic	Technique	ID
Credential Access	Brute Force	T1110
7. Impact Assessment

Successful Authentication: No

Privilege Escalation: Not Observed

Lateral Movement: Not Observed

Persistence Mechanisms: Not Observed

Data Access: Not Observed

Risk Rating: High
Although no compromise occurred, the confirmed malicious origin and attack pattern represent elevated risk to enterprise credentials.

8. Response Actions

Perimeter firewall block implemented for source IP

User account temporarily disabled

Password reset enforced

Monitoring window extended for 24 hours

Threat hunt executed across domain controllers:

index=wineventlog EventCode=4625 Source_Network_Address="185.234.10.77"

No additional hosts impacted.

9. Detection Engineering Improvements

Lower failed login threshold from 50 → 20 attempts

Implement correlation between 4625 bursts and 4624 success events

Add detection for single IP targeting multiple accounts

Enable geo-velocity anomaly detection

10. Escalation Decision

Escalated to Tier 2 SOC.

Reason: Confirmed malicious IP performing credential attack behavior against enterprise asset.

11. Evidence References

../screenshots/SOC-2026-001-alert.png

../screenshots/SOC-2026-001-splunk-query.png

../screenshots/SOC-2026-001-enrichment.png
