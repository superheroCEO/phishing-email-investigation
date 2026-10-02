# Threat Intelligence Enrichment

## Investigation Scope

This enrichment was performed against indicators extracted from the suspicious payroll email.

**Email timestamp:** `2026-09-29 09:17:35 -0700`

**Primary indicators:**

* Domain: `northstar-hr-support.example`
* URL: `https://northstar-hr-support.example/payroll/verify`
* Sending IP: `203.0.113.45`
* Reply-To: `payroll-team@protonmail.com`

> **Lab note:** This investigation uses synthetic indicators and documentation-only IP ranges. The threat-intelligence results below are simulated enrichment for SOC training and should not be interpreted as live Internet reputation data.

---

## Domain Intelligence

### Indicator

```text
northstar-hr-support.example
```

### Simulated Reputation Result

```text
Indicator: northstar-hr-support.example
Type: Domain
Disposition: Suspicious
Confidence: Medium
Tags:
  - phishing
  - payroll-lure
  - credential-harvesting
First Seen: 2026-09-29
```

### Observations

The domain name uses an HR/payroll-related naming convention:

```text
northstar-hr-support.example
```

This naming is consistent with the social-engineering theme observed in the email.

The domain was first observed in the simulated intelligence dataset on the same date as the phishing message.

No historical reputation was identified before the observed campaign activity.

### Correlation

The domain is present in:

```text
From:
payroll@northstar-hr-support.example
```

and:

```text
URL:
https://northstar-hr-support.example/payroll/verify
```

The domain also resolves to:

```text
203.0.113.45
```

as documented in `evidence/domain-dns.md`.

---

## URL Intelligence

### Indicator

```text
https://northstar-hr-support.example/payroll/verify
```

### Simulated URL Analysis

```text
URL: https://northstar-hr-support.example/payroll/verify

Classification: Phishing
Confidence: High

Observed behavior:
  - HTTP 200 response
  - Payroll-themed verification page
  - Requests direct-deposit information
  - Attempts to collect employee information
```

### Simulated Sandbox Result

```text
HTTP Status: 200
Page Title: Direct Deposit Verification
Content Category: Credential / Financial Information Collection

Observed form fields:
  Employee ID
  Password
  Routing Number
  Account Number
```

The observed URL is therefore consistent with the social-engineering objective established by the email subject and body:

```text
Action Required: Update Your Direct Deposit Information
```

The `/payroll/verify` path also directly reinforces the payroll pretext.

---

## IP Intelligence

### Indicator

```text
203.0.113.45
```

### Address Classification

```text
Address: 203.0.113.45
Range: TEST-NET-3
Purpose: Documentation / training
Production reputation: Not applicable
```

Because this address belongs to a documentation-only range, a real-world IP reputation determination would not be meaningful.

For this exercise, the address is retained as an investigation IOC because it appears in the email's `Received` header and resolves from the simulated phishing domain.

### Correlation

The same address appears in multiple evidence sources:

```text
Received:
mail.northstar-hr-support.example (203.0.113.45)
```

and:

```text
DNS A Record:
northstar-hr-support.example -> 203.0.113.45
```

This provides infrastructure correlation even though the address itself cannot provide meaningful production reputation data.

---

## Reply-To Intelligence

### Indicator

```text
payroll-team@protonmail.com
```

### Observations

The message uses:

```text
From:
payroll@northstar-hr-support.example
```

but specifies:

```text
Reply-To:
payroll-team@protonmail.com
```

The Reply-To address is therefore outside the sender's apparent organizational domain.

This creates a meaningful identity mismatch:

```text
Visible sender:
northstar-hr-support.example

Reply destination:
protonmail.com
```

The mismatch does not independently prove malicious activity, but it is relevant to phishing triage because responses to the message would be directed to a separate external mailbox.

No additional reputation determination is made for the Proton Mail address based solely on the supplied evidence.

---

## Indicator Correlation

| Indicator                           | Type     | Simulated TI Result                   | Correlation                   |
| ----------------------------------- | -------- | ------------------------------------- | ----------------------------- |
| `northstar-hr-support.example`      | Domain   | Suspicious / phishing                 | Sender + URL                  |
| `/payroll/verify`                   | URL      | Phishing / information collection     | Email hyperlink               |
| `203.0.113.45`                      | IP       | Synthetic training IOC                | DNS + Received header         |
| `payroll-team@protonmail.com`       | Email    | External / no independent disposition | Reply-To                      |
| `mail.northstar-hr-support.example` | Hostname | Associated infrastructure             | Received header + reverse DNS |

---

## Threat Intelligence Assessment

The available enrichment increases the suspicion associated with the email.

The strongest TI correlations are:

1. The sender domain is associated with a payroll-themed phishing classification in the simulated intelligence dataset.
2. The embedded URL is classified as a phishing page designed to collect sensitive employee and financial information.
3. The domain, URL, and sending infrastructure are internally correlated.
4. The Reply-To address redirects communication to an unrelated external mailbox.
5. The sending domain has limited historical presence in the simulated intelligence dataset.

However, threat intelligence alone does not establish whether the recipient interacted with the URL or whether information was submitted.

Those questions require additional telemetry.

### Evidence Required Next

The following sources should be investigated:

```text
Network telemetry
    ↓
Determine whether the recipient accessed the phishing URL.

Identity telemetry
    ↓
Determine whether authentication activity followed the phishing event.

Endpoint telemetry
    ↓
Determine whether the recipient's device interacted with the site
or downloaded/executed additional content.

M365 audit telemetry
    ↓
Determine whether the mailbox, message, or account generated
additional relevant activity.
```

## Indicators for Downstream Correlation

```text
Domain:
northstar-hr-support.example

URL:
https://northstar-hr-support.example/payroll/verify

IP:
203.0.113.45

Hostname:
mail.northstar-hr-support.example

Reply-To:
payroll-team@protonmail.com

Recipient:
employee@northstar.example

Email Timestamp:
2026-09-29 09:17:35 -0700
```
