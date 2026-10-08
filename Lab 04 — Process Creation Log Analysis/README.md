# Lab 04 – Process Creation Log Analysis

## Objective
Analyze Windows process creation events in Splunk to understand executed processes, parent processes, users, workstations, command lines, and process activity over time.

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

Analyzed the relationship between:
- User
- Workstation
- Created process
- Parent process
- Command line
- Timestamp
Examples observed included processes such as powershell.exe, cmd.exe, msedge.exe, outlook.exe, thunderbird.exe, and word.exe.

3. Process Creation Context
source="windows_security_logs.csv" index="main" event_id="4688"
| table timestamp,user,workstation,process_name,parent_process,command_line,description
| sort timestamp

The description field provided additional context for the process creation events, such as:
Process <process_name> created.
The chronological view helped establish when processes were created and which parent process was associated with them.

Key Observations
- Event ID 4688 was used to analyze Windows process creation activity.
- The dataset contained 12,024 process creation events.
- Multiple applications and system processes were observed.
- Parent-child process relationships were available for investigation.
- User and workstation information provided additional context for each process.
- Command-line information was available for process investigation.
- Sorting events chronologically helped establish process activity timelines.

Skills Practiced
Splunk | SPL | Windows Event ID 4688 | Process Creation Analysis | Parent-Child Process Analysis | Command-Line Analysis | Timeline Analysis | Windows Log Analysis
Evidence

Screenshots demonstrate:
1. Process frequency analysis
2. Process and parent-process investigation
3. Chronological process creation analysis with additional event context

Conclusion
Successfully analyzed Windows process creation logs in Splunk using Event ID 4688. The investigation covered process frequency, parent-child relationships, users, workstations, command lines, and chronological process activity.
