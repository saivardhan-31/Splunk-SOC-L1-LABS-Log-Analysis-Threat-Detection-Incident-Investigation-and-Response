# Lab 11 – Password Spraying Detection and Investigation

## Objective
Detect suspicious authentication activity by identifying a source IP targeting multiple user accounts, analyzing failed logons, reviewing the attack timeline, and checking for successful authentication.

## Investigation and Analysis

### 1. Identify Suspicious Source IP

**SPL Query**
```spl
source="windows_security_logs.csv" index="main" event_id="4625"
| stats dc(user) as unique_user_targeted, count as total_failures by source_ip
| where unique_user_targeted > 5
| sort user
```

**Findings**
- Suspicious source IP: `203.0.113.77`
- Unique users targeted: 18
- Total failed logons: 162

**What happened:** The source IP generated failed authentication attempts against 18 different user accounts. This pattern is consistent with a potential password-spraying attack and required further investigation.

### 2. Identify Targeted User Accounts

**SPL Query**
```spl
source="windows_security_logs.csv" index="main" event_id="4625" source_ip=203.0.113.77
| stats count by user
| sort user
```

**Findings**
- 18 user accounts were identified.
- Each account had 9 failed logon events.

**What happened:** The failed attempts were distributed across multiple accounts instead of being limited to a single user. This pattern supported investigating possible password spraying or other automated authentication activity.

### 3. Analyze the Attack Timeline

**SPL Query**
```spl
source="windows_security_logs.csv" index="main" event_id="4625" source_ip=203.0.113.77
| stats count by timestamp,user
| sort timestamp
```

**Findings**
- The displayed results began at approximately `2024-03-15 10:05:00`.
- User entries appeared at 30-second intervals in the displayed results.

**What happened:** Timestamp analysis helped establish the sequence of failed authentication attempts and examine how the activity was distributed across the targeted accounts.

### 4. Verify Windows Authentication Events

**SPL Query**
```spl
source="windows_security_logs.csv" index="main" event_id="4625" source_ip=203.0.113.77
| stats count by event_id,event_name
```

**Findings**

| Event ID | Event Name | Count |
|---|---|---:|
| 4625 | FailedLogon | 162 |

**What happened:** All 162 matching events were failed-logon events. This confirmed repeated authentication failures associated with the identified source IP.

### 5. Check for Successful Authentication

**SPL Query**
```spl
source="windows_security_logs.csv" index="main" source_ip=203.0.113.77 event_id="4624"
| stats count by user,source_ip,event_name
```

**Purpose:** Check whether any successful Windows logon events were recorded for the same source IP.

**Investigation status:** The available screenshots confirm failed authentication but do not show the result of this successful-logon query. Therefore, successful compromise cannot be confirmed from the current evidence.

## Key Observations
- Identified source IP `203.0.113.77` as suspicious.
- Observed 162 failed logons targeting 18 unique users.
- Confirmed Windows Event ID `4625` (`FailedLogon`).
- Identified the targeted accounts and examined the event timeline.
- Prepared a follow-up investigation using Event ID `4624` to check for successful authentication.
- The observed pattern is consistent with a potential password-spraying attack, but the available evidence does not independently prove the attack method or successful compromise.

## Skills Practiced
Splunk SPL | Windows Security Logs | Event ID Analysis | Authentication Log Analysis | Password Spraying Detection | Source IP Investigation | Timeline Analysis | SOC Alert Triage

## Evidence
Include the screenshots captured during the investigation:

1. **Source IP Detection** – Identified `203.0.113.77`, 18 unique targeted users, and 162 failed logons.
2. **Targeted User Analysis** – Displayed the 18 user accounts and their failed-logon counts.
3. **Timeline Investigation** – Reviewed timestamps and the sequence of authentication failures.
4. **Event ID Verification** – Confirmed 162 matching Event ID `4625` events.
5. **Successful Logon Check** – Add the screenshot of the Event ID `4624` query after running it, to document whether successful logons were found.

## Conclusion
Investigated suspicious authentication activity in Splunk and identified 162 failed logons associated with source IP `203.0.113.77` across 18 user accounts. The distribution of failures was consistent with a potential password-spraying attempt. The investigation demonstrated how to identify suspicious authentication patterns, analyze targeted users, establish a timeline, and prepare to verify successful authentication. Further evidence is required to determine whether any account was successfully compromised.
