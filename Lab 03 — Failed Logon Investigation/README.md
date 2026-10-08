# Lab 03 – Failed Logon Investigation

## Objective
Investigate Windows failed logon events in Splunk to identify suspicious authentication activity, affected users, source IPs, failure reasons, and logon types.

## Splunk Investigation

### 1. Identify Failed Logon Activity

```spl
source="windows_security_logs.csv" index="main" event_id="4625"
| stats count by user
| sort - count

The search returned 1,950 failed logon events.
The user rthompson had the highest number of failed logons with 360 events, making the account a priority for further investigation.

2. Investigate the Affected User
source="windows_security_logs.csv" index="main" event_id="4625" user=rthompson
| table timestamp,source_ip,event_name,logon_type,failure_reason,logon_type_name

The investigation showed:
- User: rthompson
- Failed events: 360
- Event: FailedLogon
- Source IP: 203.0.113.50
- Failure reason: Bad password
- Logon type: 3
- Logon type name: Network

3. Examine Event Context
source="windows_security_logs.csv" index="main" event_id="4625" user=rthompson
| table timestamp,source_ip,event_name,logon_type,failure_reason,logon_type_name,category,description

The events associated with 203.0.113.50 were categorized as MALICIOUS in the dataset and contained the description:
Brute force attempt against rthompson.

4. Build the Authentication Timeline
source="windows_security_logs.csv" index="main" event_id="4625" user=rthompson
| table timestamp,source_ip,event_name,logon_type,failure_reason,logon_type_name,category,description
| sort timestamp

The timeline showed normal failed-logon activity from an internal source such as 10.10.2.101, including events described as user password mistakes.
Later, a distinct sequence appeared from 203.0.113.50 against rthompson.
The suspicious sequence showed repeated failed network logons at short intervals, with Bad password as the failure reason.

Investigation Findings
- rthompson was the most frequently targeted account in the failed-logon dataset.
- The account generated 360 failed logon events.
- Suspicious activity originated from 203.0.113.50.
- The authentication attempts used Network Logon Type 3.
- The repeated attempts occurred at short, regular intervals.
- The dataset explicitly categorized these events as MALICIOUS.
- The event description identified the activity as a brute-force attempt.
- Other failed logons from 10.10.2.101 were categorized as Normal and described as user password mistakes, providing useful comparison/context.

SOC Investigation Workflow
Failed Logons → Identify High-Frequency User → Investigate Source IP → Analyze Failure Reason → Examine Logon Type → Build Timeline → Distinguish Normal vs Suspicious Activity
Skills Practiced
Splunk | SPL | Windows Event ID 4625 | Failed Logon Analysis | Authentication Investigation | Source IP Analysis | Timeline Analysis | Brute-Force Detection | SOC Alert Investigation

Evidence
Screenshots demonstrate:
1. Failed logon frequency by user
2. Investigation of rthompson
3. Source IP and authentication details
4. Malicious brute-force event context
5. Chronological comparison of normal and suspicious failed logons

Conclusion
Successfully investigated Windows failed logon activity in Splunk and identified a suspicious brute-force authentication sequence targeting rthompson from 203.0.113.50. The investigation used event frequency, source IP, failure reason, logon type, event classification, and timeline analysis to distinguish suspicious authentication behavior from normal password failures.
