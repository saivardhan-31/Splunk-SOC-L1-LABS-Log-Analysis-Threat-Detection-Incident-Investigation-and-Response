# Lab 07 – Firewall Log Analysis and Network Traffic Investigation

## Objective

Analyze firewall logs in Splunk to understand allowed and denied traffic, identify high-activity source IPs, investigate destination ports, and examine suspicious network communication and data-transfer patterns.

## Dataset

- Source: `firewall_logs.csv`
- Splunk Index: `main`
- Sourcetype: `csv`
- Events analyzed: 6,197

## Splunk Analysis

### 1. Firewall Action Analysis

```spl
source="firewall_logs.csv" index="main" sourcetype="csv"
| stats count by action
```

Results:

- `ALLOW` — 5,197 events
- `DENY` — 1,000 events

This provided an overview of permitted and blocked network traffic.

### 2. Source IP Analysis

```spl
source="firewall_logs.csv" index="main" sourcetype="csv"
| stats count by src_ip
| sort - count
```

The highest event counts included:

- `203.0.113.50` — 157
- `10.10.2.101` — 133
- `10.10.5.102` — 124
- `10.10.3.103` — 120
- `10.10.3.104` — 115

This helped identify frequently observed source IP addresses for further investigation.

### 3. Destination IP and Port Analysis

```spl
source="firewall_logs.csv" index="main" sourcetype="csv"
| stats count by dst_ip,dst_port
| sort - count
```

The results showed repeated traffic involving destination `203.0.113.1` on ports `3389`, `23`, `22`, and `8080`.

Other observed traffic included destination `10.10.50.1` on port `445` and destination `203.0.113.50` on ports `4444` and `443`.

This provided visibility into destination-port activity and helped identify connections requiring further review.

### 4. Allowed Traffic on Selected Ports

```spl
source="firewall_logs.csv" index="main" action="ALLOW"
| where dst_port!=80 AND dst_port!=53
| stats count by dst_ip,dst_port
| sort - count
```

The filtered results included:

- `10.10.50.1:445` — 157 events
- `203.0.113.50:4444` — 30 events
- `203.0.113.50:443` — 10 events

This analysis focused on allowed traffic excluding destination ports 80 and 53. The results help prioritize connections for contextual investigation; a port number alone does not establish malicious activity.

### 5. Investigate a Specific Destination IP

```spl
source="firewall_logs.csv" index="main" dst_ip="203.0.113.50"
| table timestamp,src_ip,dst_ip,dst_port,bytes_sent,bytes_received,action,category
| sort timestamp
```

The search returned **40 events**.

The results included traffic from `10.10.2.101` to `203.0.113.50` on ports `443` and `4444`. These events were marked `ALLOW` and categorized as `MALICIOUS` in the dataset.

The `bytes_sent` and `bytes_received` fields provided additional context about traffic volume.

### 6. Investigate High-Volume Transfers

```spl
source="firewall_logs.csv" index="main" dst_ip="203.0.113.50"
| where bytes_sent>100000
| table timestamp,src_ip,dst_ip,dst_port,bytes_sent,bytes_received,action,category
| sort bytes_sent
```

The search returned **10 events** with more than 100,000 bytes sent.

The results showed repeated allowed connections to destination port `443`, with substantial outbound byte counts. The dataset categorized these events as `MALICIOUS`.

These patterns warrant further investigation into the communicating hosts, destination, timing, and nature of the transferred data. High transfer volume alone does not prove data exfiltration.

## Key Observations

- Analyzed 6,197 firewall events.
- Identified 5,197 allowed events and 1,000 denied events.
- Ranked source IPs by event frequency.
- Examined destination IP and port combinations.
- Filtered allowed traffic on selected ports.
- Investigated 40 events involving `203.0.113.50`.
- Identified 10 events exceeding the selected outbound-byte threshold.
- Used the dataset's `MALICIOUS` classification to prioritize traffic for investigation.
- Compared traffic direction, ports, actions, and byte counts to understand network communication patterns.

## SOC Investigation Workflow

**Firewall Logs → Allow/Deny Analysis → Source IP Investigation → Destination IP/Port Analysis → Traffic Filtering → Byte-Volume Analysis → Suspicious Traffic Review**

## Skills Practiced

Splunk | SPL | Firewall Log Analysis | Network Traffic Investigation | Source/Destination IP Analysis | Port Analysis | Traffic Filtering | Data-Transfer Analysis | SOC Investigation

## Evidence

Screenshots demonstrate:

1. Firewall allow/deny counts
2. Source IP frequency analysis
3. Destination IP and port analysis
4. Allowed traffic filtering
5. Destination-specific traffic investigation
6. High-volume transfer analysis

## Conclusion

Successfully analyzed firewall logs in Splunk to investigate permitted and denied traffic, identify high-frequency source IPs, examine destination ports, and review suspiciously categorized network connections. Traffic-volume analysis provided additional context for prioritizing events for further investigation.
