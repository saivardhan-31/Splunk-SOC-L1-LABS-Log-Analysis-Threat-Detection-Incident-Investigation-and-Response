# Lab 09 – Phishing Email Analysis and Data Exfiltration Investigation

## Objective
Analyze email logs to identify suspicious phishing emails, correlate email activity with proxy logs, investigate suspicious URL access, and check for potential data exfiltration using email and network-related evidence in Splunk.

## Data Sources
- `email_logs.csv`
- `proxy_logs.csv`
- Splunk index: `main`

## Investigation and Analysis

### 1. Identify Suspicious Emails

**SPL Query**
```spl
source="email_logs.csv" index="main"
| where spam_score > 5.0
| table timestamp,sender,recipient,attachment,spam_score,subject,src_ip
| sort timestamp
```

**Findings**

Identified six email events with spam scores above 5. Examples included:

- **Possible business email compromise (BEC):** Sender `ceo@acceptech.local.phishing.xyz`, subject `Confidential: Please wire transfer $50,000`, spam score `9.2`.
- **Suspicious password-reset email:** Sender `it-support@abctech-helpdesk.tk`, subject `URGENT: Your account will be locked - Reset password NOW`, attachment `password_reset_form.html`, spam score `8.7`.

The sender domains, urgent language, financial request, and password-reset theme were suspicious indicators requiring investigation.

### 2. Investigate Proxy Activity

**SPL Query**
```spl
source="proxy_logs.csv" index="main" user=mwilson
| table timestamp,dest_url,status_code
| sort timestamp
```

**Findings**

- Investigated proxy activity associated with user `mwilson`.
- Identified requests to `http://abctech-helpdesk.tk/login` at `2024-03-15 09:35:00`.
- The recorded HTTP status was `200`, indicating a successful HTTP response.
- The suspicious URL and timestamp aligned with the password-reset email activity observed at `09:35:00`.

This correlation supports the finding that the suspicious login URL was requested. The logs alone do not prove that the recipient submitted credentials or that an account was compromised.

### 3. Correlate Email and Proxy Logs

Compared email and proxy records using timestamps, suspicious domains, URLs, and user activity.

**Investigation sequence:**

1. Identified suspicious emails using spam scores and message content.
2. Extracted the suspicious password-reset domain from the email evidence.
3. Searched proxy logs for requests to the corresponding login URL.
4. Compared timestamps to establish a possible relationship between the email and web activity.
5. Used the results to identify activity requiring further investigation.

### 4. Investigate Potential Data Exfiltration

**SPL Query**
```spl
source="email_logs.csv" index="main" size_bytes > 1000000
| table timestamp,sender,recipient,attachment,subject,spam_score,src_ip,size_bytes,category
```

**Findings**

The investigation identified three matching events at `2024-03-15 04:30:00` involving:

- Sender: `rthompson@acceptech.local`
- Recipient: `tbrooks.personal@external-mail.local`
- Attachment: `customer_data_export.zip`
- Subject: `FWD: Customer Database Export`
- Size: `15,728,640` bytes per event
- Category: `MALICIOUS`

The external-looking recipient, large archive attachment, and malicious classification are suspicious indicators of possible data transfer outside the organization.

**Assessment:** The email records raise a potential data-exfiltration concern. However, the provided evidence does not independently establish that the attachment was successfully delivered, downloaded, or transferred to an unauthorized destination. Further investigation should correlate email delivery records, proxy or network transfer logs, endpoint activity, and file-access evidence.

## Key Findings

- Identified six high-spam-score email events.
- Flagged a suspicious financial-transfer email and a password-reset email.
- Correlated the password-reset email's timestamp with proxy requests to its associated login URL.
- Observed an HTTP `200` response for the suspicious login URL.
- Identified email records involving a large customer-data archive sent to an external-looking address.
- Documented the evidence and limitations relevant to phishing investigation and potential data exfiltration.

## Skills Practiced

Splunk | SPL | Email Log Analysis | Phishing Investigation | Proxy Log Analysis | Timestamp Correlation | Suspicious URL Investigation | Data Exfiltration Indicators | SOC Investigation | Evidence-Based Reporting

## Evidence

Screenshots document:

1. High-spam-score email identification.
2. Suspicious sender, recipient, subject, attachment, and source IP analysis.
3. Proxy activity associated with `mwilson`.
4. Requests to the suspicious password-reset URL.
5. Large email attachment analysis related to possible data exfiltration.

## Conclusion

Investigated suspicious email activity in Splunk and correlated email records with proxy logs to identify access to a suspicious password-reset URL. Also identified email records involving a large customer-data archive sent to an external-looking recipient, raising a potential data-exfiltration concern. The investigation demonstrates an evidence-based SOC workflow for phishing triage, log correlation, and identifying activity that warrants further incident investigation.
