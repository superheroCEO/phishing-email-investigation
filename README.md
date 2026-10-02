# Phishing Email Investigation — Payroll / Credential Harvesting

A simulated **SOC Tier 1 phishing investigation** involving a payroll-themed social-engineering email, user interaction with a fraudulent website, attempted credential use, and an endpoint execution attempt prevented by EDR.

The investigation correlates **email artifacts, DNS, threat intelligence, network telemetry, identity telemetry, endpoint telemetry, and Microsoft 365 audit data** to determine the scope and outcome of the incident.

> **Training Project:** All organizations, users, domains, telemetry, and indicators are synthetic. IP addresses use documentation-only ranges.

---

## Investigation Overview

**Incident Type:** Phishing / Credential Exposure Attempt / Malware Execution Attempt
**Affected User:** `employee@northstar.example`
**Affected Host:** `WIN-EMP-042`
**Severity:** High
**Disposition:** **True Positive — Phishing**

### Attack Flow

```text
Phishing Email
      ↓
Header / Authentication Analysis
      ↓
DNS + Threat Intelligence
      ↓
User Accesses Phishing URL
      ↓
Data Submitted to Phishing Infrastructure
      ↓
Identity Investigation
      ↓
Failed Microsoft 365 Authentication Attempts
      ↓
Endpoint Investigation
      ↓
rundll32.exe → update.dll
      ↓
EDR Prevention + Quarantine
      ↓
Microsoft 365 Audit / Mailbox Remediation
      ↓
Evidence Correlation + Tier 1 Disposition
```

---

## Incident Summary

The investigation began with a payroll-themed email requesting that the recipient verify direct-deposit information.

Initial phishing indicators included:

* SPF SoftFail
* DKIM None
* DMARC Fail
* Payroll-themed sender and URL
* External `Reply-To` address
* Simulated threat-intelligence classification of the domain and URL as phishing

Network telemetry confirmed that the affected workstation accessed the phishing site and submitted data through:

```text
GET  /payroll/verify
POST /payroll/verify
POST /collect
```

Subsequent identity telemetry showed multiple Microsoft 365 password authentication attempts from the phishing infrastructure. **All observed attempts failed.**

Endpoint telemetry also showed:

```text
chrome.exe
    └── rundll32.exe
          └── update.dll
```

EDR detected the suspicious DLL execution, terminated the process, and quarantined the file.

The user reported the phishing email, and Microsoft 365 audit telemetry confirmed mailbox remediation.

### Outcome

The available evidence did **not** establish:

* Successful account takeover
* Successful Microsoft 365 authentication from the phishing infrastructure
* Successful malware execution
* Persistent malware
* Successful exfiltration beyond the observed phishing-site submissions

---

## Investigation Workflow

### Email Analysis

Reviewed the original email and extracted headers for sender, Reply-To, routing, authentication results, and embedded indicators.

### DNS & Threat Intelligence

Correlated the phishing domain, URL, hostname, and IP address against DNS and simulated threat-intelligence data.

### Network Investigation

Analyzed proxy and DNS telemetry to determine whether the user accessed the phishing infrastructure and submitted information.

### Identity Investigation

Reviewed Microsoft 365 authentication telemetry and distinguished failed password attempts from legitimate token refreshes.

### Endpoint Investigation

Analyzed EDR process, file, and network telemetry to identify the `rundll32.exe → update.dll` execution attempt and confirm EDR prevention.

### Microsoft 365 Investigation

Reviewed message access, phishing reporting, deletion, mailbox rules, forwarding, delegates, and suspicious sessions.

---

## Key Evidence

| Source         | Finding                                               |
| -------------- | ----------------------------------------------------- |
| Email          | Payroll-themed phishing message                       |
| Headers        | SPF SoftFail, DKIM None, DMARC Fail                   |
| DNS / TI       | Phishing domain correlated to observed infrastructure |
| Network        | User accessed URL and submitted data                  |
| Identity       | Multiple failed Microsoft 365 password attempts       |
| Endpoint / EDR | DLL execution attempt detected and prevented          |
| Microsoft 365  | User reported message; mailbox remediation completed  |

---

## SOC Skills Demonstrated

* Phishing triage
* Email header analysis
* IOC extraction and correlation
* DNS investigation
* Threat-intelligence enrichment
* Network/proxy log analysis
* Identity and authentication analysis
* Endpoint/EDR investigation
* Microsoft 365 audit analysis
* Timeline construction
* Cross-source evidence correlation
* True-positive / false-positive disposition
* Tier 1 escalation
* Incident documentation

---

## Repository Structure

```text
phishing-email-investigation/
│
├── artifacts/
│   ├── email.eml
│   ├── extracted-iocs.md
│   └── headers.txt
│
├── case/
│   ├── final-report.md
│   ├── investigation-notes.md
│   └── ticket.md
│
└── evidence/
    ├── domain-dns.md
    ├── endpoint-telemetry.log
    ├── identity-telemetry.log
    ├── m365-audit.log
    ├── network-telemetry.log
    └── threat-intel.md
```

### `artifacts/`

Original phishing artifacts and extracted indicators used to begin the investigation.

### `evidence/`

Simulated security telemetry and threat-intelligence enrichment used during the investigation.

### `case/`

Analyst working notes, operational SOC ticket, and final incident report.

---

## Investigation Outcome

**True Positive — Phishing**

The evidence supports a phishing incident with confirmed user interaction and data submission, followed by unsuccessful credential-abuse attempts and an endpoint execution attempt prevented by EDR.

Successful account takeover, successful malware execution, and persistent compromise were **not established** by the available telemetry.

---

## Disclaimer

This repository is a **synthetic cybersecurity training project** created to demonstrate SOC investigation and incident-response skills.

All organizations, users, domains, email addresses, hostnames, telemetry, hashes, and other indicators are fictional.

The IP addresses use documentation-only ranges and are not intended to represent real infrastructure or threat-intelligence reputation.
