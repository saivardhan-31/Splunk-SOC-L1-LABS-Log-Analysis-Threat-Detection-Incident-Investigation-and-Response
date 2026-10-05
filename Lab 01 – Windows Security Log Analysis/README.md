## Lab 01 – Windows Security Log Analysis
## Objective
Analyze Windows Security logs in Splunk to understand authentication, process creation, user activity, source IPs, workstations, and logon types.
Dataset
- Source: windows_security_logs.csv
- Splunk Index: main
- Sourcetype: csv
- Events analyzed: 8,499

## Splunk Analysis

## 1. Initial Log Review
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main"
| head 5

Reviewed the first events to understand the structure and contents of the Windows Security log dataset.
Observed events including:
- Process Creation — Event ID 4688
- Successful Logon — Event ID 4624
- powershell.exe
- svchost.exe
- acrobat.exe
- explorer.exe
## 2. Field Analysis
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main"
| table timestamp,user,workstation,source_ip,logon_type_name

Analyzed important fields including:
- Timestamp
- User
- Workstation
- Source IP
- Logon Type
## 3. Authentication Activity
Reviewed different Windows logon types present in the dataset, including:
- Network
- Interactive
- RemoteInteractive
The dataset contained authentication activity associated with different users, workstations, and internal source IP addresses.

## Key Observations
- Windows Security events were successfully ingested and searchable in Splunk.
- Event ID 4624 was observed for successful logon activity.
- Event ID 4688 was observed for process creation.
- Multiple users and workstations were present in the dataset.
- Internal source IP addresses were associated with authentication events.
- Different logon types provided additional context for user activity.
- Process creation events included applications such as PowerShell, svchost.exe, Acrobat, and Explorer.

## Skills Practiced
Splunk | SPL | Windows Security Logs | Event Analysis | Authentication Analysis | Process Analysis | Log Analysis
Evidence
Screenshots included in this lab demonstrate:
1. Initial Windows Security event review
2. Event and field inspection
3. Successful logon analysis
4. SPL table-based field analysis
5. Windows authentication activity

## Conclusion
Successfully analyzed a controlled Windows Security log dataset in Splunk and identified key authentication, process, user, workstation, and network-related fields that can be used for further SOC investigations.
