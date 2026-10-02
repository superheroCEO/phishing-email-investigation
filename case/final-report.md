# Phishing Incident Investigation Report

**Incident Date:** 2026-09-29
**Affected User:** `employee@northstar.example`
**Affected Host:** `WIN-EMP-042`
**Incident Type:** Phishing / Credential Exposure Attempt / Malware Execution Attempt
**Severity:** High
**SOC Disposition:** True Positive — Phishing

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Incident Overview](#incident-overview)
3. [Incident Timeline](#incident-timeline)
4. [Investigation Findings](#investigation-findings)

   * [Email Analysis](#email-analysis)
   * [Network Activity](#network-activity)
   * [Identity Activity](#identity-activity)
   * [Endpoint Activity](#endpoint-activity)
   * [Microsoft 365 Activity](#microsoft-365-activity)
5. [Impact Assessment](#impact-assessment)
6. [Response and Containment](#response-and-containment)
7. [Remaining Risks and Unresolved Questions](#remaining-risks-and-unresolved-questions)
8. [Recommendations](#recommendations)
9. [Final Assessment](#final-assessment)

---

## Executive Summary

An employee received a fraudulent payroll email requesting verification of direct-deposit information. The employee followed the embedded link and interacted with the fraudulent website, where information was submitted.

Following the interaction, multiple attempts were made to use the employee's identity to authenticate to Microsoft 365. All observed password attempts failed.

Endpoint security also identified an attempted execution of a suspicious DLL on the employee's workstation. Endpoint security detected the activity, terminated the process, and quarantined the DLL.

The employee reported the phishing message, and the message was removed from the mailbox. Available investigation data does not show a successful account takeover, successful malware execution, or persistent mailbox compromise.

---

## Incident Overview

### Initial Email

**Time:** `2026-09-29 09:17:35 -0700`

**Sender:** `payroll@northstar-hr-support.example`

**Reply-To:** `payroll-team@protonmail.com`

**Subject:**

> Action Required: Update Your Direct Deposit Information

**URL:**

`https://northstar-hr-support.example/payroll/verify`

The message used a payroll-related pretext and requested that the recipient verify direct-deposit information.

Email authentication results were:

* SPF: SoftFail
* DKIM: None
* DMARC: Fail

The sender domain and embedded URL used the same domain, while the Reply-To address used an unrelated external mailbox.

---

## Incident Timeline

| Time | Event |
|---|---|
| 09:17:35 | Phishing email timestamp; workstation accessed `/payroll/verify` |
| 09:17:36 | POST request submitted to `/payroll/verify` |
| 09:17:38 | Data submitted to `/collect` |
| 09:17:40 | Suspicious `update.dll` created on workstation |
| 09:17:41 | `rundll32.exe` attempted to execute `update.dll`; EDR prevented execution |
| 09:17:42 | Microsoft 365 audit confirms phishing email delivery |
| 09:17:44–09:18:02 | Multiple failed Microsoft 365 password attempts from phishing infrastructure |
| 09:18:03 | User searched for direct-deposit verification information |
| 09:18:22 | User reported the email as phishing |
| 09:18:24–09:18:26 | Phishing message moved to Deleted Items and soft-deleted |
| 09:24:38–09:25:03 | Mailbox rules, forwarding, delegates, and suspicious sessions reviewed |
| 09:31:00 | Subsequent access to phishing domain blocked by threat intelligence |
| 09:31:07–09:31:26 | Additional failed Microsoft 365 password attempts |
| 09:34:29 | Phishing message hard-deleted |
| 10:26:14 | Additional failed Microsoft 365 password attempt |

---

# Investigation Findings

## Email Analysis

The message presented as a payroll notification and instructed the employee to verify direct-deposit information.

Several indicators supported the phishing assessment:

* SPF authentication resulted in SoftFail.
* No DKIM signature was present.
* DMARC authentication failed.
* The Reply-To address differed from the apparent organizational sender.
* The embedded URL used a payroll-themed domain.
* Simulated threat-intelligence enrichment classified the domain and URL as phishing indicators.

The email therefore presented multiple indicators consistent with a credential-harvesting phishing attempt.

---

## Network Activity

Network telemetry confirmed that the affected workstation accessed the phishing infrastructure.

Observed activity included:

```text
GET  /payroll/verify
POST /payroll/verify
POST /collect
```

The workstation subsequently accessed:

`login.northstar-hr-support.example`

Additional telemetry showed the user searching for direct-deposit verification information and later accessing the organization's phishing-reporting page.

The observed POST requests confirm that information was submitted to the phishing infrastructure. The available telemetry does not identify exactly what information was submitted.

---

## Identity Activity

Microsoft 365 authentication telemetry showed multiple password authentication attempts originating from `203.0.113.45`, the IP associated with the phishing infrastructure.

All observed attempts failed with:

> Invalid username or password

Legitimate Microsoft 365 token refreshes continued from the user's known workstation.

No successful password authentication originating from the phishing infrastructure was identified in the investigation data.

This supports an attempted use of the employee's credentials without establishing successful account compromise.

---

## Endpoint Activity

EDR telemetry showed the following sequence on `WIN-EMP-042`:

```text
chrome.exe
    └── rundll32.exe
          └── update.dll
```

The DLL was created in the user's temporary directory and identified as a PE32 file.

At `09:17:41`, EDR detected:

**Suspicious DLL Execution**

The security control then:

* Terminated `rundll32.exe`
* Quarantined `update.dll`

The telemetry establishes an attempted DLL execution and successful EDR prevention.

It does **not** establish successful malware execution or provide enough evidence to determine exactly how the DLL was introduced to the workstation.

---

## Microsoft 365 Activity

Microsoft 365 audit telemetry confirmed that the user accessed the phishing message and subsequently reported it.

Mailbox remediation included:

* Moving the message to Deleted Items
* Soft deletion
* Later hard deletion

Mailbox security checks identified:

* No inbox rules
* Forwarding disabled
* No unexpected delegates
* No suspicious sessions

These findings provide no evidence of persistent mailbox manipulation within the available telemetry.

---

# Impact Assessment

### Confirmed

* Employee received a phishing email.
* Employee accessed the phishing site.
* Information was submitted to the phishing infrastructure.
* Attempts were made to authenticate to Microsoft 365 using the employee's identity.
* The observed password attempts failed.
* A suspicious DLL execution attempt occurred on the workstation.
* EDR prevented the observed execution and quarantined the DLL.

### Not established

* Successful account takeover
* Successful Microsoft 365 authentication from the phishing infrastructure
* Successful malware execution
* Persistent malware
* Successful exfiltration beyond the observed phishing-site submissions
* Direct-deposit or financial-account changes
* Attacker identity

---

# Response and Containment

The phishing message was reported by the employee and removed from the mailbox.

Security controls subsequently blocked access to the phishing domain.

Endpoint security prevented the observed DLL execution attempt and quarantined the associated file.

Mailbox security settings and sessions were reviewed for signs of persistence or unauthorized access, with no suspicious findings identified in the available telemetry.

The incident was escalated for credential-exposure and endpoint follow-up.

---

# Remaining Risks and Unresolved Questions

The investigation confirms that information was submitted to the phishing infrastructure, but the available telemetry cannot determine exactly what information was entered.

Because authentication attempts followed the phishing interaction, credential exposure remains a concern even though all observed password attempts failed.

The endpoint telemetry confirms an attempted DLL execution that was prevented. Additional endpoint review is appropriate to verify that no residual artifacts or persistence mechanisms remain.

The available evidence also does not establish whether the phishing campaign affected other employees.

---

# Recommendations

1. Reset the affected user's credentials according to incident-response procedures.
2. Continue monitoring the account for successful authentication from unfamiliar infrastructure.
3. Confirm the EDR quarantine and perform follow-up endpoint scanning.
4. Search the environment for additional copies of the phishing message.
5. Search for the associated domain, URL, IP, hostname, and file hash across available security telemetry.
6. Maintain blocking for the identified phishing infrastructure.
7. Review whether additional users received or interacted with the same phishing campaign.

---

# Final Assessment

The investigation confirmed a phishing incident involving a fraudulent payroll-themed email, user interaction with the associated phishing site, observed data submission, attempted credential use, and an attempted malicious DLL execution.

The observed Microsoft 365 authentication attempts were unsuccessful, and endpoint security prevented the observed DLL execution attempt.

Based on the available investigation data, **successful account takeover, successful malware execution, and persistent compromise were not established**.
