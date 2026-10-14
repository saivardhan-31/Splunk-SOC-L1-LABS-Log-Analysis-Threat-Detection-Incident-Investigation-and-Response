# Lab 13 – Privilege Escalation Investigation

## Objective
Investigate Windows Security logs in Splunk to identify suspicious privilege assignments, unauthorized group membership changes, administrative command execution, and potentially malicious service installations.

## Dataset
- **Log Source:** `windows_security_logs.csv`
- **Splunk Index:** `main`
- **Investigation Focus:** Privileged activity, group modifications, process creation, and service installation

## Splunk Investigation

### 1. Analyze Special Privilege Assignments — Event ID 4672

```spl
source="windows_security_logs.csv" index="main" event_id=4672
| table timestamp,user,workstation,privileges,category
```

Reviewed events associated with special privileges. The results included privileges such as `SeDebugPrivilege` and `SeImpersonatePrivilege`, which can provide powerful access to system processes or user security contexts.

The initial search returned 5,010 events. These assignments are not automatically malicious; the associated user, workstation, and surrounding activity must be examined.

### 2. Identify Suspicious Privilege Assignments

```spl
source="windows_security_logs.csv" index="main" event_id=4672 category="MALICIOUS"
| table timestamp,user,workstation,privileges
```

Identified 10 events categorized as `MALICIOUS`, associated with user `rthompson` on workstation `WIN-FIN-001` at **03:12 on March 15, 2024**.

The recorded privileges were:
- `SeDebugPrivilege`
- `SeTcbPrivilege`
- `SeBackupPrivilege`

These privileges can enable powerful system operations. Their presence in the maliciously categorized events warranted further investigation.

### 3. Investigate User and Group Membership Changes

```spl
source="windows_security_logs.csv" index="main" (event_id=4728 OR event_id=4732)
| table timestamp,user,member_added,group,category
```

Investigated:
- **Event ID 4728:** Member added to a security-enabled global group.
- **Event ID 4732:** Member added to a security-enabled local group.

The results showed events associated with `rthompson`, where the account `hacker` was added to the `Administrators` group and categorized as `MALICIOUS`.

This is a significant privilege-escalation indicator because administrative group membership can grant elevated permissions.

### 4. Examine Process Creation — Event ID 4688

```spl
source="windows_security_logs.csv" index="main" event_id=4688 user=rthompson
| search process_name="net.exe" OR process_name="whoami.exe" OR process_name="nltest.exe"
| table timestamp,process_name,command_line
```

Investigated process creation events to identify commands that could be used for account manipulation or system discovery.

The results included:

- `net user hacker P@ssw0rd /add`
- `net localgroup administrators hacker /add`

These commands indicate attempts to create a local account named `hacker` and add it to the local Administrators group. The repeated records in the dataset should not be interpreted as separate successful account creations without further validation.

### 5. Investigate New Service Installation — Event ID 7045

```spl
source="windows_security_logs.csv" index="main" event_id=7045 user=rthompson
| table timestamp,user,service_name,service_binary,start_type,category
```

The results showed a service named `WindowsUpdater` with the binary path:

```text
C:\Windows\Temp\malware.exe
```

The service was configured with an `Automatic` start type and categorized as `MALICIOUS`.

A service running from a temporary directory under a generic updater name is suspicious and may indicate persistence. Further validation would be needed to establish whether the service was successfully installed and executed.

## What Happened? — Investigation Findings

The logs revealed a suspicious sequence of activity associated with `rthompson` on `WIN-FIN-001`:

1. **03:12** — Special privileges were recorded, including `SeDebugPrivilege`, `SeTcbPrivilege`, and `SeBackupPrivilege`.
2. **03:12–03:14** — Process creation records showed commands attempting to create the `hacker` account and add it to the Administrators group.
3. **03:16** — Group membership events showed `hacker` associated with the `Administrators` group.
4. **03:25** — A suspicious `WindowsUpdater` service referenced `C:\Windows\Temp\malware.exe` and used automatic startup.

Taken together, these findings are consistent with a potential privilege-escalation and persistence scenario involving account manipulation and a suspicious service.

**Investigation note:** The dataset contains events categorized as malicious, but log records alone do not prove that every action succeeded or establish the full attack chain. Correlating authentication events, process details, service creation records, and endpoint evidence would help confirm the outcome.

## Skills Practiced
- Splunk SPL and Windows Security log analysis
- Event ID investigation: 4672, 4728, 4732, 4688, and 7045
- Privileged account activity analysis
- Suspicious group membership detection
- Process command-line investigation
- Service installation and persistence indicators
- Security incident triage and event correlation

## Evidence
Include the following screenshots in the GitHub lab folder:

1. Special privilege assignment analysis — Event ID 4672.
2. Malicious privilege assignment events for `rthompson`.
3. Group membership investigation showing `hacker` added to `Administrators`.
4. Process creation analysis showing the `net user` and `net localgroup` commands.
5. Service installation analysis showing `WindowsUpdater`, its binary path, and automatic startup configuration.

## Conclusion
Successfully investigated Windows Security logs in Splunk for suspicious privileged activity, group membership changes, administrative commands, and service installation. The findings identified indicators consistent with potential privilege escalation and persistence. This lab demonstrates a practical SOC L1 workflow for investigating privileged activity, correlating related Windows events, and identifying suspicious account and service changes for further incident response.
