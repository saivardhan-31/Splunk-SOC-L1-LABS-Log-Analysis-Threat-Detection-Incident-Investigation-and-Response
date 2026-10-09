# Lab 06 – SSH Log Analysis and Authentication Investigation

## Objective

Analyze Linux SSH authentication logs in Splunk to investigate successful logins, failed password attempts, source IP addresses, and potential brute-force activity.

## Dataset

- Log file: `auth.log`
- Splunk Index: `main`
- Sourcetype: `syslog`
- Log source: Linux SSH authentication events

## Splunk Analysis

### 1. Review SSH Authentication Logs

```spl
source="auth.log" index="main" sourcetype="syslog"
| head 20
```

Reviewed SSH authentication events, including accepted public-key logins and associated usernames, source IP addresses, and Linux hosts.

### 2. Identify Failed Password Attempts

```spl
source="auth.log" index="main" sourcetype="syslog" "Failed password"
| table _time,host,_raw
```

The search returned **300 failed-password events**. Repeated SSH authentication failures were observed on `LNX-WEB-001`, targeting the `root` account.

### 3. Extract and Count Source IP Addresses

```spl
source="auth.log" index="main" sourcetype="syslog" "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort -count
```

The extracted source IP `203.0.113.50` was associated with all **300 failed-password events** returned by this search.

### 4. Investigate the Source IP

```spl
source="auth.log" index="main" sourcetype="syslog" "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| search src_ip="203.0.113.50"
```

Reviewed the matching events and observed repeated attempts against `root` at short intervals, consistent with password-guessing or brute-force behavior in the dataset.

### 5. Review Accepted Password Authentication

```spl
source="auth.log" index="main" sourcetype="syslog" "Accepted password"
| rex field=_raw "for (?<username>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time,host,src_ip,username
```

This search returned **one event**. The event showed an accepted-password login for `root` from `203.0.113.50` on `LNX-WEB-001`.

### 6. Review All Events Associated with the Source IP

```spl
source="auth.log" index="main" sourcetype="syslog" "203.0.113.50"
| table _time,host,_raw
| sort -_time
```

Reviewed events associated with the source IP to examine the available authentication context and compare activity.

## Key Observations

- SSH authentication logs were searchable in Splunk.
- The failed-password search returned 300 events.
- `203.0.113.50` was associated with all 300 failed-password events in the search.
- Repeated failures targeted the `root` account on `LNX-WEB-001`.
- A separate accepted-password event showed a successful authentication for `root` from the same IP.
- The combination of repeated failures and an accepted login warrants further investigation; the available evidence alone does not establish whether the accepted login resulted from a successful brute-force attack.

## Skills Practiced

Splunk | SPL | Linux Authentication Logs | SSH Log Analysis | Failed Login Investigation | Source IP Extraction with `rex` | Authentication Correlation | Brute-Force Detection | SOC Investigation

## Evidence

Screenshots demonstrate:

1. Initial SSH authentication log review
2. Failed-password event analysis
3. Source IP extraction and event counting
4. Investigation of repeated authentication failures
5. Accepted-password event analysis
6. Review of events associated with the source IP

## Conclusion

Successfully analyzed Linux SSH authentication logs in Splunk, identified repeated failed login attempts against `root`, extracted and counted the associated source IP, and reviewed an accepted-password event from the same IP. This investigation demonstrates how a SOC analyst can correlate authentication events to identify suspicious activity and determine when further investigation is required.
