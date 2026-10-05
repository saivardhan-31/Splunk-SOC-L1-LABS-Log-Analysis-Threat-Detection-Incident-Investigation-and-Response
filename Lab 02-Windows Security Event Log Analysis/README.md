## Objective
The objective of this lab was to perform Windows Security Log analysis in Splunk and understand how different Windows Event IDs can be used to investigate user activity, authentication events, process execution, and potentially malicious activity.
This lab was performed using the Windows security log dataset:
windows_security_logs.csv

The logs were indexed in Splunk under:
index="main"

## 1. Windows Event ID Analysis
Splunk Query
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main"
| stats count by event_id,event_name
| sort -count

## Analysis
The query was used to identify the different Windows Event IDs present in the dataset and determine how frequently each event occurred.
The analysis returned 8,499 events across the following Event IDs:
## Event ID	Event Name	Count
4688	ProcessCreation	4,008
4624	SuccessfulLogon	3,003
4625	FailedLogon	975
4672	SpecialPrivilegesAssigned	501
4720	UserAccountCreated	4
7045	NewServiceInstalled	4
4728	UserAddedToGlobalGroup	3
4732	UserAddedToLocalGroup	1


## SOC Relevance
This provided an initial overview of the Windows security activity in the dataset.
Important events include:
- 4624 — Successful logon
- 4625 — Failed logon
- 4688 — Process creation
- 4672 — Special privileges assigned
- 4720 — User account creation
- 7045 — New service installation
- 4728 — User added to a global security group
- 4732 — User added to a local security group
These Event IDs can be useful during SOC investigations because they provide visibility into authentication, process execution, privilege changes, account activity, and persistence-related activity.
## 2. Successful Logon Analysis
Event ID
4624

Event ID 4624 represents a successful logon.
Splunk Query
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main" event_id="4624"
| stats count by user

## Analysis
The query was used to determine how many successful logon events were associated with each user.
The search returned 3,003 successful logon events.
Examples of users identified included:
- Administrator
- amartin
- asanchez
- bmorris
- crogers
- cwhite
- da_hrobinson
- da_iwalker
- dlee
- dreed
- ecook
- eharris
- fclark
- fmorgan
- gbell
- glewis
- hmurphy
- hrobinson
This analysis helps a SOC analyst understand which accounts are generating successful authentication activity.
## 3. Identifying Users With the Highest Successful Logons
Splunk Query
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main" event_id="4624"
| stats count by user
| sort - count

Results
The results were sorted from highest to lowest number of successful logons.
Examples from the results:
User	Successful Logons
cwhite	68
jsmith	67
jwalker	63
da_iwalker	62
jscott	61
sprice	61
tphillips	61
pbrooks	60
yedwards	60
kgreen	59
nwood	59
qkelly	59
svc_splunk	58
wevans	58
nnelson	57


## SOC Relevance
Sorting authentication events by user helps an analyst identify accounts with unusually high authentication activity.
In a real SOC investigation, an analyst could further investigate:
- High-frequency authentication
- Service accounts
- Privileged accounts
- Unusual login times
- Authentication from unexpected systems
- Successful logons following multiple failed logons
The high number alone does not indicate malicious activity. Additional context would be required.
## 4. Process Creation Analysis
Event ID
4688

Event ID 4688 represents process creation.
Splunk Query
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main" event_id="4688"
| table timestamp,user,process_name,parent_process,command_line

## Analysis
The search returned 4,008 process creation events.
The following fields were examined:
- timestamp
- user
- process_name
- parent_process
- command_line

## Example events included:
User	Process	Parent Process
jsmith	thunderbird.exe	powershell.exe
bmorris	outlook.exe	explorer.exe
sprice	chrome.exe	svchost.exe
ibailey	notepad.exe	explorer.exe
wevans	winlogon.exe	cmd.exe
jrivera	winlogon.exe	powershell.exe
zstewart	svchost.exe	powershell.exe
dlee	powershell.exe	svchost.exe
dlee	lsass.exe	explorer.exe
fmorgan	notepad.exe	powershell.exe
lward	7z.exe	cmd.exe
nnelson	services.exe	explorer.exe


## SOC Relevance
Process creation logs are extremely useful during endpoint investigations.
A SOC analyst can compare:
Process → Parent Process → Command Line → User → Timestamp

to identify suspicious process execution.
For example, the following parent-child relationships would deserve additional investigation in a real environment:
powershell.exe → unusual application
cmd.exe → unexpected executable
Office application → powershell.exe
Browser → command shell

However, a suspicious parent-child relationship is an investigation indicator, not automatically proof of compromise.
## 5. Chronological Process Analysis
Splunk Query
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main" event_id="4688"
| table timestamp,user,process_name,parent_process,command_line
| sort timestamp

## Analysis
The process creation events were sorted chronologically to establish a timeline of process execution.
This produced a timeline beginning on:
2024-03-01

Examples included:
08:02:39  pmitchell   thunderbird.exe   cmd.exe
08:27:19  zstewart    msedge.exe        explorer.exe
08:28:33  mbaker      thunderbird.exe   svchost.exe
08:28:59  mrichardson outlook.exe       powershell.exe
08:32:00  ladams      word.exe          explorer.exe
08:33:43  ecook       iexplore.exe      powershell.exe
08:56:54  kcox        cmd.exe           cmd.exe
09:00:24  vparker     powershell.exe    svchost.exe
09:00:32  jscott      msedge.exe        svchost.exe

## SOC Relevance
Chronological ordering is useful when constructing an incident timeline.
For example:
Initial activity
       ↓
Process execution
       ↓
Child process creation
       ↓
Additional activity
       ↓
Potential malicious behavior

This approach helps an analyst understand what happened first and what happened afterward rather than examining individual events in isolation.

## 6. Malicious Event Analysis
The dataset also contained a category field that could be used to identify events categorized as malicious.
Splunk Query
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main" category="malicious"
| table timestamp,event_id,event_name,user,workstation,description
| sort timestamp

Results
The search returned:
190 events

The results contained repeated failed logon events associated with a brute-force activity.
Example:
Timestamp	Event ID	Event	User	Workstation	Description
2024-03-15 02:15:00	4625	FailedLogon	rthompson	WIN-FIN-001	Brute force attempt against rthompson
2024-03-15 02:15:08	4625	FailedLogon	rthompson	WIN-FIN-001	Brute force attempt against rthompson
2024-03-15 02:15:16	4625	FailedLogon	rthompson	WIN-FIN-001	Brute force attempt against rthompson
2024-03-15 02:15:24	4625	FailedLogon	rthompson	WIN-FIN-001	Brute force attempt against rthompson
2024-03-15 02:15:32	4625	FailedLogon	rthompson	WIN-FIN-001	Brute force attempt against rthompson


The events continued at regular intervals.

## 7. Brute-Force Activity Identified
From the malicious-event search, the following activity was observed:
Event ID:       4625
Event Name:     FailedLogon
User:           rthompson
Workstation:    WIN-FIN-001
Activity:       Brute-force attempt

The repeated failed logons occurred within a short time period:
02:15:00
02:15:08
02:15:16
02:15:24
02:15:32
02:15:40
02:15:48
02:15:56
02:16:04
02:16:12
...

This pattern is consistent with repeated authentication attempts against the same account.
SOC Interpretation
A sequence of repeated Event ID 4625 events targeting the same account can be an indicator of:
- Password guessing
- Brute-force authentication
- Automated authentication attempts
- Misconfigured applications or services
In this dataset, the description field explicitly identifies the activity as a brute-force attempt.

## 8. Investigation Approach Used
During this lab, the analysis followed a basic SOC investigation workflow:
Windows Security Logs
        ↓
Identify Event IDs
        ↓
Analyze Authentication Events
        ↓
Identify High-Activity Users
        ↓
Analyze Process Creation
        ↓
Build Process Timeline
        ↓
Filter Malicious Events
        ↓
Investigate Repeated Failed Logons
        ↓
Identify Brute-Force Activity

## 9. Splunk Queries Used
Event overview
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main"
| stats count by event_id,event_name
| sort -count

Successful logons by user
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main" event_id="4624"
| stats count by user

Highest successful logons
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main" event_id="4624"
| stats count by user
| sort - count

Process creation
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main" event_id="4688"
| table timestamp,user,process_name,parent_process,command_line

Chronological process timeline
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main" event_id="4688"
| table timestamp,user,process_name,parent_process,command_line
| sort timestamp

Malicious events
source="D:\\SOC-Logs\\windows_security_logs.csv" index="main" category="malicious"
| table timestamp,event_id,event_name,user,workstation,description
| sort timestamp

## 10. Skills Practiced
Through this lab, I practiced:
- Windows Security Event Log analysis
- Windows Event ID identification
- Splunk SPL queries
- stats command
- sort command
- table command
- User activity analysis
- Successful logon analysis
- Failed logon analysis
- Process creation analysis
- Parent-child process analysis
- Timeline creation
- Malicious event filtering
- Brute-force activity identification
- Basic SOC investigation methodology
## 11. Key Takeaways
This lab demonstrated how a SOC analyst can use Windows Security Logs in Splunk to move from large volumes of raw events to meaningful security observations.
The main observations from the dataset were:
- 4,008 process creation events were present.
- 3,003 successful logon events were present.
- 975 failed logon events were present.
- 501 special privilege assignment events were present.
- 190 events were categorized as malicious.
- Repeated 4625 FailedLogon events showed a brute-force attempt against rthompson on WIN-FIN-001.
- Event ID 4688 provided process and parent-process information useful for endpoint investigation.
The lab helped build practical experience in using Splunk to search, filter, aggregate, sort, and investigate Windows security events.
