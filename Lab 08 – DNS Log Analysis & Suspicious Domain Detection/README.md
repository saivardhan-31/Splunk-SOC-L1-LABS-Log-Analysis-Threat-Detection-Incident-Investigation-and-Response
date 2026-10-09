# Lab 08 – DNS Log Analysis & Suspicious Domain Detection

## Objective
Analyze DNS logs in Splunk to identify frequently queried domains, investigate NXDOMAIN responses, detect suspicious domain patterns, and examine DNS activity associated with potentially malicious domains and response IPs.

## Dataset
- **Source:** `dns_logs.csv`
- **Splunk Index:** `main`
- **Events analyzed:** 10,107

## Splunk Analysis

### 1. Frequently Queried Domains

```spl
source="dns_logs.csv" index="main"
| stats count by query
| sort - count
| head 20
```

Identified frequently queried domains, including GitHub, Slack, Stack Overflow, Salesforce, Microsoft services, and Google. The results also contained unusual `.xyz` domains with low query counts.

### 2. NXDOMAIN Analysis by Source IP

```spl
source="dns_logs.csv" index="main" response=NXDomain
| stats count by src_ip
| sort - count
```

Identified **100 NXDOMAIN events** associated with source IP `10.10.2.101`.

NXDOMAIN indicates that the requested domain name could not be resolved because the DNS response reported that the name did not exist.

### 3. Chronological NXDOMAIN Investigation

```spl
source="dns_logs.csv" index="main" response=NXDomain src_ip="10.10.2.101"
| table timestamp,query,response
| sort timestamp
```

Reviewed DNS queries from `10.10.2.101` chronologically. The results included repeated requests for randomly structured `.xyz` domains, with NXDOMAIN responses.

This pattern was investigated as a potential indicator of Domain Generation Algorithm (DGA) activity.

### 4. Malicious DNS Event Investigation

```spl
source="dns_logs.csv" index="main" category="MALICIOUS"
| table timestamp,query,src_ip,response
| sort -timestamp
```

Identified **107 events** categorized as `MALICIOUS` in the dataset.

Examples included:
- `cobalt-c2-beacon.info`
- `dnscat2-beacon.xyz`
- `secure-check-now.net`
- `cdn-fast-delivery.ru`
- `update-service.tk`
- `randomdomain123.biz`

The displayed results associated these DNS queries with source IP `10.10.2.101` and showed `203.0.113.50` in the response field.

### 5. Investigating DNS Responses for `203.0.113.50`

```spl
source="dns_logs.csv" index="main" response="203.0.113.50"
| table timestamp,src_ip,query,response,category
| sort timestamp
```

Investigated DNS records containing `203.0.113.50` in the response field to examine the relationship between the source host, queried domains, and DNS responses.

The analysis connected suspicious DNS query activity from `10.10.2.101` with records containing the response IP `203.0.113.50`.

**SOC interpretation:** This relationship warrants further investigation for possible command-and-control (C2)-related activity. A DNS response containing an IP address does not, by itself, prove that a direct connection was established with that IP.

## Key Observations

- Analyzed 10,107 DNS events in Splunk.
- Identified frequently queried domains and unusual domain names.
- Found 100 NXDOMAIN events associated with `10.10.2.101`.
- Observed repeated queries for randomly structured `.xyz` domains.
- Identified 107 events labeled `MALICIOUS` by the dataset.
- Investigated DNS records containing `203.0.113.50` in the response field.
- Practiced correlating source IPs, queried domains, DNS responses, timestamps, and event categories.

## Skills Practiced

Splunk | SPL | DNS Log Analysis | NXDOMAIN Investigation | Suspicious Domain Detection | DGA Indicators | Source IP Analysis | DNS Threat Hunting | Event Correlation

## Evidence

Screenshots demonstrate:
1. Frequently queried domain analysis.
2. NXDOMAIN event counts grouped by source IP.
3. Chronological investigation of NXDOMAIN queries.
4. DNS events categorized as malicious.
5. Investigation of DNS records containing `203.0.113.50`.

## Conclusion

Used Splunk to analyze DNS logs, investigate NXDOMAIN responses, identify unusual domain patterns, and examine DNS records associated with suspicious domains and response IPs. This lab strengthened DNS-based threat-hunting and investigation skills relevant to SOC Analyst L1 workflows.

*Note: Findings are based on the supplied dataset. NXDOMAIN responses and unusual domain patterns are investigation indicators, not standalone proof of DGA malware or a successful compromise.*
