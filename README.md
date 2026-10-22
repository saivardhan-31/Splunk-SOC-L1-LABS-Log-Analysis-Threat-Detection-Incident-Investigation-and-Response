# Splunk-SOC-L1-LABS-Log-Analysis-Threat-Detection-Incident-Investigation-and-Response
## Project Overview

This project demonstrates practical SOC Analyst Level 1 skills through security log analysis, threat detection, incident investigation, and incident response exercises using Splunk and Kali Linux.

The project includes 14 Splunk log-analysis labs using available security log datasets and three Kali Linux-based practical investigations covering phishing email analysis, digital forensics, and end-to-end SOC L1 incident investigation.

The goal is to investigate suspicious activity, correlate events across log sources, reconstruct incident timelines, identify indicators of compromise, and document evidence-based findings.

## Objectives

- Analyze security logs using Splunk Search Processing Language (SPL).
- Investigate authentication failures, suspicious account activity, and privilege changes.
- Identify suspicious processes, PowerShell commands, and potential malware behavior.
- Correlate endpoint, authentication, DNS, firewall, VPN, and email evidence.
- Investigate phishing indicators, suspicious network communication, and potential data exfiltration.
- Practice digital forensics and structured incident investigation.
- Document findings and conclusions in a format relevant to SOC workflows.

## Tools and Technologies

- **SIEM and log analysis:** Splunk, SPL
- **Investigation environment:** Kali Linux
- **Windows telemetry:** Windows Security Logs, Sysmon, PowerShell logs
- **Linux telemetry:** SSH and authentication logs
- **Network telemetry:** Firewall, DNS, VPN, and proxy logs
- **Email investigation:** Email security logs and phishing indicators
- **Investigation techniques:** Event correlation, timeline analysis, suspicious activity detection, digital forensics, and incident response

## Project Labs

### Part 1: Splunk Log Analysis and Threat Investigation

#### Lab 1 – Windows Log Analysis
Analyzed Windows security events to understand authentication activity, process creation, event fields, and common Windows logging patterns.

#### Lab 2 – Windows Security Event Analysis
Examined Windows event IDs, including 4624, 4625, 4688, 4672, 4720, 4728, 4732, and 7045, to investigate successful and failed logons, process activity, privileged access, account creation, group changes, and service installation.

#### Lab 3 – Failed Logon Investigation
Investigated Event ID 4625, examined repeated authentication failures, identified targeted accounts and source IP addresses, and reviewed failure reasons and logon types.

#### Lab 4 – Process Creation Log Analysis
Analyzed Event ID 4688 and process-creation records to identify unusual process activity, suspicious parent processes, and potentially malicious command execution.

#### Lab 5 – New User Account Creation Investigation
Investigated Event ID 4720 and related group membership events to identify suspicious account creation and potential unauthorized addition of an account to privileged groups.

#### Lab 6 – SSH Authentication Investigation
Analyzed Linux SSH authentication logs for failed password attempts and accepted logins, including repeated attempts against privileged accounts.

#### Lab 7 – Firewall Log Analysis
Examined allowed and denied network traffic, source and destination IP addresses, destination ports, and high-volume transfers to identify potentially suspicious network activity.

#### Lab 8 – DNS Log Analysis and Suspicious Domain Detection
Investigated DNS responses, NXDOMAIN events, repeated suspicious domain queries, and potentially malicious domain indicators. Reviewed available DNS evidence for possible command-and-control activity.

#### Lab 9 – Phishing Email Analysis and Potential Data Exfiltration
Analyzed email logs using spam scores, sender information, subjects, recipients, and attachment details to identify suspicious messages. Correlated email and proxy logs to investigate requests to suspicious URLs and reviewed records associated with a potentially sensitive external email transfer.

#### Lab 10 – Brute-Force Attack Investigation
Analyzed repeated Windows authentication failures, targeted accounts, source IP addresses, VPN activity, and firewall records. Reviewed related successful-logon events as part of the investigation.

#### Lab 11 – Password Spraying Detection
Investigated repeated authentication failures across multiple user accounts from a common source IP. Used unique-user counts and failure totals to identify a password-spraying pattern.

#### Lab 12 – Suspicious PowerShell Activity Detection
Reviewed PowerShell script-block and command activity for suspicious downloads, encoded commands, credential-dumping attempts, security-control modification attempts, account creation, file archiving, and executable downloads.

#### Lab 13 – Privilege Escalation Investigation
Correlated privileged logon events, account and group membership changes, process creation records, and service installation events to investigate potential privilege escalation and persistence.

#### Lab 14 – Malware Infection Investigation
Correlated Sysmon process creation, process-access, network connection, and file-creation events to investigate suspicious PowerShell activity, potential credential dumping, suspicious outbound connections, and potentially malicious files.

### Part 2: Kali Linux Practical Investigations

#### Lab 15 – Phishing Email Analysis
Performed a practical investigation focused on phishing email indicators and suspicious links. The objective was to assess potential phishing activity and document relevant findings.

#### Lab 16 – Digital Forensics Investigation
Performed a practical digital forensics investigation focused on examining available evidence, identifying suspicious artifacts, and supporting an evidence-based investigation.

#### Lab 17 – End-to-End SOC L1 Incident Investigation and Response
Performed a practical SOC-style investigation covering the incident investigation workflow, analysis of available evidence, assessment of suspicious activity, and incident response considerations.

*These three labs represent the practical investigations performed. Specific commands, artifacts, and outcomes should be documented alongside each lab's evidence.*

## Investigation Workflow

The project follows a structured investigation approach:

1. **Data selection:** Identify the relevant log source and fields.
2. **Search and filtering:** Use SPL to filter events by event ID, user, IP address, timestamp, domain, or activity type.
3. **Detection:** Identify repeated failures, unusual commands, suspicious account changes, or anomalous network behavior.
4. **Correlation:** Compare related events across available log sources.
5. **Timeline reconstruction:** Sort events chronologically to understand the possible sequence of activity.
6. **Evidence review:** Examine supporting event records and available indicators.
7. **Assessment:** Document observations, potential impact, and limitations of the evidence.
8. **Reporting:** Record the investigation steps, relevant queries, findings, and conclusion.

## Key Findings and Investigation Scenarios

The available datasets provided examples of:

- Repeated Windows and SSH authentication failures.
- A password-spraying pattern involving multiple user accounts.
- Suspicious account creation and privileged group membership changes.
- Potentially malicious PowerShell commands and credential-dumping activity.
- Suspicious file creation and process access involving LSASS.
- DNS queries involving suspicious domains and possible command-and-control indicators.
- Email and proxy records associated with potential phishing activity.
- High-volume transfers and email attachments investigated for possible data exfiltration.
- Suspicious service installation and potential persistence activity.

These findings demonstrate investigation techniques using the supplied logs. They do not independently establish that every attempted action succeeded or that data was definitively exfiltrated.

## Skills Demonstrated

- Splunk searching and SPL-based filtering
- Windows Security Event ID analysis
- Sysmon event correlation
- Linux SSH authentication investigation
- Firewall, DNS, VPN, proxy, and email log analysis
- Brute-force and password-spraying investigation
- Suspicious PowerShell and process analysis
- Account management and privilege escalation investigation
- Malware behavior and potential command-and-control investigation
- Phishing analysis and digital forensics
- Incident timeline reconstruction
- Evidence-based investigation documentation
- SOC L1 incident triage and response workflow

## Project Scope and Limitations

- The Splunk investigations documented here use available security log datasets.
- Findings depend on the events and fields present in those datasets.
- A suspicious command, connection, or transfer is an indicator for further investigation; it is not automatically proof of successful compromise or data exfiltration.
- The three Kali Linux practical investigations are included as separate practical exercises within this portfolio project.
- A separate real-time Splunk lab involving monitored endpoints and controlled attack simulations is outside the scope of this README until its activities are completed and documented.

## Conclusion

This project demonstrates hands-on practice with SIEM-based security monitoring, log analysis, threat detection, event correlation, and incident investigation. It combines Windows and Linux telemetry analysis with network and email investigations and Kali Linux practical exercises to build foundational skills relevant to a SOC Analyst L1 role.

The project will be expanded as additional labs are completed and their queries, screenshots, evidence, and findings are documented.

---

**Project focus:** SOC Analyst L1  
**Primary tool:** Splunk  
**Supporting environment:** Kali Linux  
**Core areas:** Log Analysis | Threat Detection | Incident Investigation | Digital Forensics | Incident Response
