# Investigation Notes

## Case Opened

**Date:** 2026-09-29
**Alert:** Suspicious payroll-themed email
**User:** `employee@northstar.example`
**Host:** `WIN-EMP-042`

Initial alert indicates a payroll-related email asking the user to verify direct-deposit information.

### Initial indicators

* Sender: `payroll@northstar-hr-support.example`
* Reply-To: `payroll-team@protonmail.com`
* URL: `https://northstar-hr-support.example/payroll/verify`
* Message time: `09:17:35 -0700`

Initial concern: possible phishing / credential harvesting.

---

## Email / Header Review

Reviewed extracted headers.

Authentication results:

* SPF: SoftFail
* DKIM: None
* DMARC: Fail

Sender domain:

`northstar-hr-support.example`

Reply-To:

`payroll-team@protonmail.com`

The Reply-To does not match the apparent sender organization.

Email theme is payroll/direct deposit and creates urgency.

**Assessment:** suspicious email. Need to determine whether the user interacted with the URL.

---

## DNS / Threat Intelligence Pivot

Queried the phishing domain.

`northstar-hr-support.example` resolves to:

`203.0.113.45`

This matches the IP in the email's `Received` header.

Reverse DNS:

`203.0.113.45 -> mail.northstar-hr-support.example`

SPF record:

`v=spf1 -all`

DMARC policy:

`p=reject`

Simulated TI enrichment identifies the domain as suspicious/phishing and the URL as a phishing page designed to collect employee/financial information.

IP is documentation-only TEST-NET-3, so no real-world reputation determination is possible.

**Assessment:** infrastructure is internally correlated. Need network telemetry to determine whether the user actually visited the site.

---

## Network Pivot

Searched network telemetry for:

`employee@northstar.example`

and:

`northstar-hr-support.example`

At `09:17:35`:

* Workstation `10.20.14.57` accessed `/payroll/verify`
* HTTP status `200`

At `09:17:36`:

* `POST /payroll/verify`
* HTTP `302`

At `09:17:38`:

* `POST /collect`
* HTTP `200`

This confirms the workstation did more than receive the email; it accessed the phishing infrastructure and submitted data.

Additional activity:

* `login.northstar-hr-support.example` accessed at `09:17:41`
* Threat-intelligence block recorded at `09:17:42` against `198.51.100.200`
* User searched Google for `direct deposit verification` at `09:18:03`
* User accessed the organization's phishing-reporting page at `09:18:22`
* Repeat access to the phishing domain was blocked at `09:18:18`

**Assessment:** confirmed user interaction with the phishing site and confirmed data submission.

Question to answer next: did the user provide credentials, and was there any resulting account activity?

---

## Identity Pivot

Reviewed authentication telemetry for `employee@northstar.example`.

Legitimate activity before the phishing event:

`09:16:58` — Microsoft 365 password authentication succeeded from internal IP `10.20.14.57`.

Beginning at `09:17:44`:

* Source: `203.0.113.45`
* Application: Microsoft 365
* Authentication method: Password
* Result: FAILURE
* Failure reason: Invalid username or password
* Device: Unknown

Additional failures occurred at:

* `09:17:46`
* `09:17:49`
* `09:17:54`
* `09:18:02`

Later failures from the same IP:

* `09:31:07`
* `09:31:13`
* `09:31:26`
* `10:26:14`

All observed password attempts failed.

Legitimate token refreshes from `10.20.14.57` continued.

Important distinction: the successful events after the phishing activity are `TokenRefresh` events from the user's known workstation, not successful password logins from the phishing infrastructure.

**Assessment:** credential abuse was attempted from the phishing infrastructure, but no successful Microsoft 365 password authentication was observed.

Need endpoint review.

---

## Endpoint Pivot

Reviewed EDR telemetry for `WIN-EMP-042`.

At `09:17:35`:

`chrome.exe` connected to `northstar-hr-support.example`.

At `09:17:39`:

Chrome created:

`C:\Users\employee\Downloads\Direct_Deposit_Verification.html`

At `09:17:40`:

Chrome created:

`C:\Users\employee\AppData\Local\Temp\update.dll`

File type:

`PE32`

At `09:17:41`:

`chrome.exe` spawned:

`rundll32.exe`

Command line:

`rundll32.exe C:\Users\employee\AppData\Local\Temp\update.dll,Start`

EDR detected:

`Suspicious DLL Execution`

EDR then:

* terminated `rundll32.exe`
* quarantined `update.dll`

Need to avoid assuming exactly how the DLL was introduced or executed. Telemetry establishes the sequence, but not the precise mechanism by which the phishing interaction led to the DLL execution attempt.

At `09:17:44` the user opened a Google search for direct-deposit verification.

At `09:18:21` the user opened the organization's phishing-reporting page.

At `09:19:04` the downloaded HTML file was deleted.

At `09:31:00` another connection to the phishing domain was blocked by threat intelligence.

**Assessment:** malicious-code execution was attempted and prevented by EDR. Successful execution is not established.

---

## Microsoft 365 / Mailbox Review

Confirmed delivery of the phishing message at `09:17:42`.

User accessed the message at:

`09:17:47` — MessageBind
`09:17:48` — MessageRead

At `09:18:22`:

User reported the message as phishing.

Mailbox remediation followed:

* `09:18:24` — moved to Deleted Items
* `09:18:26` — soft deleted
* `09:34:29` — hard deleted

Additional mailbox review:

* Inbox rules: `0`
* Forwarding: disabled
* Unexpected delegates: `0`
* Suspicious sessions: `0`

User also searched for:

`direct deposit verification`

and:

`northstar-hr-support.example`

No suspicious mailbox persistence identified.

**Assessment:** mailbox activity supports the user's report and subsequent remediation. No evidence of mailbox persistence or suspicious account session was identified in the supplied telemetry.

---

## Correlation / Working Assessment

Evidence now forms the following sequence:

1. Payroll-themed phishing email delivered.
2. User opened the message.
3. User accessed the phishing URL.
4. Data was submitted to the phishing infrastructure.
5. `update.dll` was created on the workstation.
6. `rundll32.exe` attempted to execute the DLL.
7. EDR detected, terminated, and quarantined the execution.
8. Password authentication attempts against Microsoft 365 originated from the phishing infrastructure.
9. All observed password attempts failed.
10. User reported the phishing email.
11. Mailbox remediation was performed.
12. Mailbox persistence checks found no suspicious configuration.
13. Additional access to the phishing domain was blocked.

### Established

* Phishing email
* User interaction with phishing site
* Data submission to phishing infrastructure
* Attempted credential use
* Attempted malicious DLL execution
* EDR prevention/quarantine
* Mailbox remediation

### Not established

* Successful account takeover
* Successful Microsoft 365 password authentication from the phishing infrastructure
* Successful malware execution
* Persistent malware
* Successful data exfiltration beyond the observed POST activity
* Direct-deposit/account changes
* Attacker identity

### Remaining question

The telemetry supports that information was submitted to the phishing site, followed by failed authentication attempts. The exact information submitted cannot be determined from the available logs.

---

## Disposition

**True Positive — Phishing**

Escalate to Tier 2 / Incident Response for credential-exposure review and endpoint follow-up.

Recommended follow-up:

* Reset affected user credentials according to IR procedures.
* Continue monitoring the account for successful authentication from unfamiliar infrastructure.
* Confirm EDR quarantine and perform endpoint follow-up scanning.
* Search for additional copies of the phishing message and associated indicators.
* Maintain blocking for the phishing domain and associated indicators.
