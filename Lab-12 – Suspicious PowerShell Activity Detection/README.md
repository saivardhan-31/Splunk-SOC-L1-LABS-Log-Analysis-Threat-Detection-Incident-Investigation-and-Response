# Lab 12 – Suspicious PowerShell Activity Detection

## Objective
Analyze PowerShell logs in Splunk to identify suspicious script execution, investigate potentially malicious commands, and detect indicators of payload downloads, encoded commands, credential dumping, and defense evasion.

## Dataset
- **Log Source:** `powershell_logs.csv`
- **Splunk Index:** `main`
- **Total Events Reviewed:** 2,010

## Splunk Investigation

### 1. Initial PowerShell Log Review

```spl
source="powershell_logs.csv" index="main"
| table timestamp,user,script_block,category
| sort timestamp
```

Reviewed PowerShell activity using timestamps, user accounts, script blocks, and event categories. Normal administrative commands such as `Get-Service`, `Get-NetAdapter`, and `Get-Process` were also present.

### 2. Identify Malicious PowerShell Events

```spl
source="powershell_logs.csv" index="main" category="MALICIOUS"
| table timestamp,user,script_block,category
| sort timestamp
```

Identified **10 events categorized as `MALICIOUS`**, associated with user `rthompson` on March 15, 2024. These events contained several suspicious PowerShell commands.

### 3. Investigate Payload Downloads

```spl
source="powershell_logs.csv" index="main"
| search script_block="*DownloadString*" OR script_block="*DownloadFile*" OR script_block="*WebClient*"
| table timestamp,user,script_block,category
| sort timestamp
```

Identified commands attempting to retrieve remote content from `203.0.113.50`:

- **03:05:00:** Used `DownloadString` to retrieve `payload.ps1`.
- **03:55:00:** Used `DownloadFile` to retrieve `ransomware.exe` and save it as `C:\Windows\Temp\update.exe`.

These commands indicate suspicious payload retrieval activity. The logs alone do not confirm successful downloads or execution.

### 4. Detect Encoded PowerShell Commands

```spl
source="powershell_logs.csv" index="main"
| search script_block="*-enc*" OR script_block="*-EncodedCommand*"
| table timestamp,user,script_block,category
| sort timestamp
```

Found an encoded PowerShell command at **03:07:00** associated with `rthompson`. Encoded commands can conceal their contents and require further analysis.

### 5. Investigate Credential-Dumping Activity

```spl
source="powershell_logs.csv" index="main"
| search script_block="*mimikatz*" OR script_block="*DumpCreds*"
| table timestamp,user,script_block,category
| sort timestamp
```

At **03:10:00**, the logs recorded:

```text
Invoke-Mimikatz -DumpCreds
```

This command is associated with credential-dumping activity and represents a significant security investigation indicator.

## What Happened? — Findings

The suspicious PowerShell events showed the following sequence:

- **03:05:** Remote PowerShell script retrieval.
- **03:07:** Encoded PowerShell command execution attempt.
- **03:10:** Mimikatz credential-dumping command.
- **03:11:** Command attempting to disable Microsoft Defender real-time monitoring.
- **03:11:30:** Command attempting to add an exclusion for `C:\Windows\Temp`.
- **03:12:** Execution of a local PowerShell script.
- **03:14:** Command attempting to create a user named `hacker`.
- **03:50:** Archiving files from `C:\Finance\*` into `C:\Windows\Temp\data.zip`.
- **03:52:** Encoding the archive into `data.b64`.
- **03:55:** Attempted download of a file named `ransomware.exe`.

The sequence is consistent with a possible compromise involving payload retrieval, credential access, defense evasion, account creation, data staging, and potential ransomware delivery.

**Investigation note:** The observed commands do not independently prove that every action succeeded, that data was exfiltrated, or that ransomware executed. Additional endpoint, process, network, and file-system evidence would be required to confirm the impact.

## Skills Practiced

- Splunk SPL and log filtering
- PowerShell script-block analysis
- Suspicious command and payload detection
- Encoded command investigation
- Credential-dumping indicators
- Defense evasion detection
- Security incident triage

## Evidence

Include the screenshots demonstrating:

1. Initial PowerShell log review.
2. Filtering of the 10 malicious events.
3. Payload download investigation.
4. Encoded PowerShell command detection.
5. Credential-dumping command investigation.

## Conclusion

Successfully analyzed PowerShell logs in Splunk and identified suspicious commands associated with a potential security incident. Investigated indicators of remote payload retrieval, encoded commands, credential dumping, defense evasion, account creation, and data staging. This lab demonstrates a practical SOC L1 workflow for detecting suspicious PowerShell activity, examining event timelines, and identifying evidence requiring further investigation.
