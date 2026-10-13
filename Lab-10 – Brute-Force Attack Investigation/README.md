# Lab 10 – Brute-Force Attack Investigation

## Objective
Investigate repeated Windows failed logon events in Splunk, identify the targeted user and source IP, check for successful authentication, and correlate Windows Security, VPN, and firewall logs to understand the potential impact.

## Investigation and SPL Queries

### 1. Identify Repeated Failed Logons
```spl
index="main" sourcetype="csv" event_id="4625"
| stats count by user,source_ip
| sort - count
| where count > 20
```

**Findings:**
- User: `rthompson`
- Source IP: `203.0.113.50`
- Failed logon events in the grouped results: **1,256**

The high volume of failed logons from the same source against one account is consistent with brute-force or password-guessing activity.

### 2. Investigate the Targeted Account
```spl
index="main" sourcetype="csv" event_id="4625" user=rthompson
| stats count by user
```

The results showed **1,440 failed logon events** for `rthompson` across the available matching events.

### 3. Identify Source IPs
```spl
index="main" sourcetype="csv" event_id="4625" user=rthompson
| stats count by source_ip
```

| Source IP | Failed logons |
|---|---:|
| `203.0.113.50` | 1,256 |
| `10.10.2.101` | 184 |

The external-looking source `203.0.113.50` generated most of the failed logons. The internal address also appeared in the events and should be investigated in context rather than automatically treated as malicious.

### 4. Check for Successful Authentication
```spl
index="main" sourcetype="csv" user=rthompson source_ip=203.0.113.50
| stats count by event_id,event_name
```

The results showed:
- Event ID `4625` — FailedLogon: **1,256**
- Event ID `4624` — SuccessfulLogon: **24**

Successful logons were present for the account in the filtered results. Further event-level verification is needed to establish whether any successful logon came from the suspected source IP and whether it occurred after the failed attempts.

### 5. Review VPN Activity
```spl
index="main" source="vpn_logs.csv" user=rthompson
| table timestamp,event,source_ip,assigned_ip,category
| sort timestamp
```

The VPN logs included `VPN_CONNECT` events associated with `rthompson`. Events from `203.0.113.50` were marked `MALICIOUS` and showed the assigned IP `172.16.0.99`. Other VPN connections were categorized as `Normal`.

This correlation identifies VPN activity associated with the suspicious source in the dataset. The repeated records should be checked for uniqueness before treating them as separate connection attempts.

### 6. Check Firewall Activity
```spl
index="main" source="firewall_logs.csv" src_ip=203.0.113.50
| stats count by dst_port,action
| sort - count
```

The results showed **471 firewall events** from `203.0.113.50`, all marked `ALLOW`, targeting destination port `445`.

This indicates that the firewall logs recorded allowed traffic from the suspicious source to port 445. It does not, by itself, prove that the attacker gained access to the service or compromised the host.

### 7. Review Event Descriptions
```spl
index="main" (user=rthompson OR src_ip=203.0.113.50) category="MALICIOUS"
| table timestamp,event_id,user,source_ip,description
| sort timestamp
```

The event descriptions explicitly included **“Brute force attempt against rthompson.”** Repeated Event ID `4625` records were visible around `2024-03-15 02:15:00`, followed by further attempts.

## Investigation Summary

The investigation identified a high-volume failed-logon pattern targeting `rthompson`, primarily from `203.0.113.50`. The dataset also contained successful logon events for the account, VPN records categorized as malicious for the suspicious source, and allowed firewall traffic to port 445.

Together, these findings warrant investigation of a potential brute-force attack and possible follow-on access. However, the available screenshots do not conclusively establish that the successful logons originated from the suspicious source or that the host was compromised.

## Skills Practiced
Splunk SPL | Windows Event ID Analysis | Failed and Successful Logon Investigation | Source IP Analysis | VPN Log Correlation | Firewall Log Analysis | Event Timeline Review | Cross-Source Investigation

## Evidence
Include screenshots showing:
1. Failed logons grouped by user and source IP.
2. Failed-logon counts for `rthompson`.
3. Source IP breakdown.
4. Failed versus successful logon event counts.
5. VPN activity for the account.
6. Firewall traffic from `203.0.113.50`.
7. Event descriptions identifying brute-force attempts.

## Conclusion
Performed a multi-source Splunk investigation of suspected brute-force activity by correlating Windows Security, VPN, and firewall logs. Identified the primary source IP, quantified failed authentication events, checked for successful logons, and examined related network activity to assess potential impact.
