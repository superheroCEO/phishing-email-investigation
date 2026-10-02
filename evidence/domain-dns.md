# Domain / DNS Investigation

## Investigated Domain

**Domain:** `northstar-hr-support.example`
**Observed URL:** `https://northstar-hr-support.example/payroll/verify`
**Observed sender:** `payroll@northstar-hr-support.example`
**Observed sending IP:** `203.0.113.45`
**Email timestamp:** `2026-09-29 09:17:35 -0700`

## DNS Resolution

### A Record

```text
$ dig +short A northstar-hr-support.example

203.0.113.45
```

**Result:** The phishing domain resolves to `203.0.113.45`.

This matches the source IP identified in the email's `Received` header:

```text
Received: from mail.northstar-hr-support.example (203.0.113.45)
```

### MX Record

```text
$ dig +short MX northstar-hr-support.example

10 mail.northstar-hr-support.example.
```

The domain publishes an MX record pointing to `mail.northstar-hr-support.example`.

### Nameservers

```text
$ dig +short NS northstar-hr-support.example

ns1.example-dns.net.
ns2.example-dns.net.
```

## SPF

```text
$ dig +short TXT northstar-hr-support.example

"v=spf1 ~all"
```

The domain's SPF record does not authorize `203.0.113.45` to send mail on its behalf.

This is consistent with the email authentication results:

```text
spf=softfail smtp.mailfrom=northstar-hr-support.example
```

and:

```text
Received-SPF: SoftFail
domain of northstar-hr-support.example
does not designate 203.0.113.45 as permitted sender
```

## DKIM

No DKIM public key was identified for the observed message.

The email authentication results report:

```text
dkim=none
```

No DKIM signature was present in the supplied message headers.

## DMARC

```text
$ dig +short TXT _dmarc.northstar-hr-support.example

"v=DMARC1; p=reject; rua=mailto:dmarc@northstar.example"
```

The domain publishes a DMARC policy of `reject`.

The observed message nevertheless failed DMARC:

```text
dmarc=fail header.from=northstar-hr-support.example
```

## Reverse DNS

```text
$ dig +short -x 203.0.113.45

mail.northstar-hr-support.example.
```

The reverse DNS result is consistent with the hostname presented in the email's `Received` header.

## DNS Timeline

```text
2026-09-29 09:17:35 -0700
Email message generated/sent with From:
payroll@northstar-hr-support.example

2026-09-29 09:17:38 -0700
Receiving infrastructure records connection from:
203.0.113.45
Hostname:
mail.northstar-hr-support.example

2026-09-29 09:17:38 -0700
DNS A record for northstar-hr-support.example:
203.0.113.45
```

## Initial DNS Assessment

The domain resolves to the same IP address identified in the email's `Received` header. The sending infrastructure therefore appears internally consistent at the DNS level.

However, the observed message failed the recipient organization's DMARC check, had no DKIM signature, and was not authorized by the domain's SPF policy.

The domain also uses a naming convention intended to resemble an HR/payroll support service:

```text
northstar-hr-support.example
```

The email's visible sender and embedded URL use this same domain, while the `Reply-To` address redirects responses to:

```text
payroll-team@protonmail.com
```

The DNS evidence alone does not establish whether the infrastructure was compromised, intentionally established for phishing, or otherwise malicious. Additional threat-intelligence, network, identity, endpoint, and M365 evidence is required.

## Indicators for Correlation

| Indicator        | Value                                                 | Source                 |
| ---------------- | ----------------------------------------------------- | ---------------------- |
| Domain           | `northstar-hr-support.example`                        | Extracted URL          |
| URL              | `https://northstar-hr-support.example/payroll/verify` | Email body             |
| Sending hostname | `mail.northstar-hr-support.example`                   | Received header        |
| Sending IP       | `203.0.113.45`                                        | Received header / DNS  |
| Sender           | `payroll@northstar-hr-support.example`                | From / Return-Path     |
| Reply-To         | `payroll-team@protonmail.com`                         | Email header           |
| SPF              | SoftFail / unauthorized sender                        | Authentication-Results |
| DKIM             | None                                                  | Authentication-Results |
| DMARC            | Fail                                                  | Authentication-Results |
