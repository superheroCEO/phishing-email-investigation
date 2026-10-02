# SOC Tier 1 Investigation Ticket

## Alert Information

**Alert Type:** Phishing Email / Suspicious URL
**Event Time:** 2026-09-29 09:17:35 -0700
**Affected User:** `employee@northstar.example`
**Affected Host:** `WIN-EMP-042`
**Severity:** High
**Disposition:** **TRUE POSITIVE — PHISHING**
**Escalation:** Tier 2 / Incident Response

---

## Alert

Payroll-themed email received with subject:

> Action Required: Update Your Direct Deposit Information

**Sender:** `payroll@northstar-hr-support.example`
**Reply-To:** `payroll-team@protonmail.com`
**URL:** `https://northstar-hr-support.example/payroll/verify`

---

## Investigation Findings

* Email authentication: **SPF SoftFail, DKIM None, DMARC Fail**
* Sender domain and phishing URL correlated to `203.0.113.45`
* Workstation accessed the phishing URL and submitted data via:

  * `POST /payroll/verify`
  * `POST /collect`
* Subsequent Microsoft 365 password attempts originated from `203.0.113.45`; **all observed attempts failed**
* EDR observed `chrome.exe` spawning `rundll32.exe` to execute `update.dll`
* EDR detected **Suspicious DLL Execution**, terminated the process, and quarantined the DLL
* User reported the phishing message; mailbox remediation was completed
* No suspicious inbox rules, forwarding, unexpected delegates, or suspicious sessions identified

---

## Disposition

**TRUE POSITIVE — PHISHING**

Confirmed phishing incident involving user interaction with the phishing site, observed data submission, attempted credential use, and an attempted malicious DLL execution that was prevented by EDR.

**Not established:**

* Successful account takeover
* Successful Microsoft 365 authentication from the phishing infrastructure
* Successful malware execution
* Persistent malware
* Successful exfiltration beyond the observed phishing-site submissions

---

## Response / Escalation

* Phishing message reported and removed.
* Phishing domain blocked by security controls.
* Escalate to Tier 2 / Incident Response for credential-exposure and endpoint follow-up.
* Reset affected user credentials according to IR procedures.
* Confirm EDR quarantine and perform endpoint follow-up scanning.
* Continue monitoring the affected account for suspicious authentication.
* Search for additional copies of the phishing email and related indicators.

---

## Analyst Note

User interaction with the phishing infrastructure is confirmed. Credential-abuse attempts were observed but unsuccessful, and EDR prevented the observed DLL execution attempt.

No successful account takeover or successful malware execution is established by the available telemetry.
