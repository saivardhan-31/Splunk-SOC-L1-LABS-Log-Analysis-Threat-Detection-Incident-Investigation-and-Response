# Lab 04 – Process Creation Log Analysis

## Objective

Analyze Windows process creation events in Splunk to understand process activity, parent-child relationships, users, workstations, command lines, and potentially suspicious process activity.

## Dataset

- Source: `windows_security_logs.csv`
- Splunk Index: `main`
- Event ID: `4688` — Process Creation

## Splunk Analysis

### 1. Process Frequency Analysis

```spl
source="windows_security_logs.csv" index="main" event_id="4688"
| stats count by process_name
| sort - count

The search returned 12,024 process creation events.
Frequently observed processes included:
- word.exe — 537
- acrobat.exe — 531
- iexplore.exe — 531
- chrome.exe — 528
- explorer.exe — 528
- thunderbird.exe — 528
- mmc.exe — 525
- winrar.exe — 525
- msedge.exe — 519
- powershell.exe — 501

2. Process and Parent Process Analysis
source="windows_security_logs.csv" index="main" event_id="4688"
| table timestamp,user,workstation,process_name,parent_process,command_line
| sort timestamp

Analyzed:
- Process creation time
- User
- Workstation
- Process name
- Parent process
- Command line
Examples included powershell.exe, cmd.exe, msedge.exe, outlook.exe, thunderbird.exe, word.exe, and other Windows applications.

3. Process Creation Context
source="windows_security_logs.csv" index="main" event_id="4688"
| table timestamp,user,workstation,process_name,parent_process,command_line,description
| sort timestamp

The description field provided additional context for the process creation events, including messages indicating that the process was created.

4. Malicious Process Activity
source="windows_security_logs.csv" index="main" event_id="4688" category="MALICIOUS"
| stats count by user

The search identified 32 malicious process creation events, all associated with:
- User: rthompson
- Event ID: 4688
Further analysis was performed using:
source="windows_security_logs.csv" index="main" event_id="4688" category="MALICIOUS"
| stats count by user,parent_process

The results showed:
- User: rthompson
- Parent Process: cmd.exe
- Events: 32
This provided an additional process lineage indicator for the malicious events associated with the account.

Key Observations
- Event ID 4688 was used to investigate Windows process creation.
- The dataset contained 12,024 process creation events.
- Multiple applications and system processes were observed.
- Parent-child process relationships were available for investigation.
- User and workstation fields provided additional execution context.
- Command-line information was available for process analysis.
- 32 events were explicitly categorized as MALICIOUS by the dataset.
- All 32 malicious process creation events were associated with rthompson.
- cmd.exe was identified as the parent process for those 32 malicious events.

SOC Investigation Workflow
Process Creation Events → Process Frequency → Parent-Child Analysis → User/Workstation Context → Command-Line Analysis → Malicious Event Filtering → Process Lineage

Skills Practiced
- Splunk
- SPL
- Windows Event ID 4688
- Process Creation Analysis
- Parent-Child Process Analysis
- Process Lineage
- Command-Line Analysis
- Timeline Analysis
- Windows Security Log Analysis
- Suspicious Process Investigation

Evidence
Screenshots demonstrate:
1. Process frequency analysis
2. Chronological process creation analysis
3. Process creation with additional event context
4. Malicious process events associated with rthompson
5. Parent-process analysis showing cmd.exe

Conclusion
Successfully analyzed Windows process creation activity in Splunk using Event ID 4688. The investigation covered process frequency, execution context, parent-child relationships, timelines, and maliciously categorized process events. The analysis identified a set of 32 malicious process creation events associated with rthompson and cmd.exe as the parent process, providing useful context for further SOC investigation.
