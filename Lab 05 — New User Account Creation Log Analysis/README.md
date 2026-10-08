# Lab 05 – New User Account Creation Log Analysis

## Objective

Analyze Windows user account creation events in Splunk to identify newly created accounts, the account-creating user, workstation context, department information, and potentially suspicious account creation activity.

## Splunk Analysis

### 1. Identify New User Account Creation

```spl
source="windows_security_logs.csv" index="main" event_id="4720"
| stats count by user
| sort timestamp

The search returned 16 events.
Account creation activity was associated with:
- da_robinson — 12 events
- rthompson — 4 events

2. Analyze New Account Details
source="windows_security_logs.csv" index="main" event_id="4720"
| table timestamp,user,new_account,new_account_fullname,new_account_dept,workstation,category
| sort timestamp

The investigation identified newly created accounts and their associated context.

Examples included:
Creating User	New Account	Full Name	Department	Workstation	Category
da_robinson	bfields	Barbara Fields	Finance	DC-PRIMARY-001	Normal
rthompson	hacker	hacker	Unknown	WIN-FIN-001	MALICIOUS
da_robinson	tneman	Tom Newman	HR	DC-PRIMARY-001	Normal
da_robinson	jmason	James Mason	Sales	DC-PRIMARY-001	Normal


3. Investigate Related Group Membership Changes
source="windows_security_logs.csv" index="main" (event_id="4728" OR event_id="4732")
| table timestamp,user,member_added,group,category
| sort timestamp

The investigation showed group membership activity involving newly added users.
Normal examples included:
- tneman → Domain Admins
- bfields → Helpdesk
- jmason → Remote Desktop Users

A suspicious entry showed:
- User performing action: rthompson
- Member added: hacker
- Group: Administrators
- Category: MALICIOUS

Key Observations
- Event ID 4720 was used to analyze Windows user account creation.
- The dataset contained 16 account creation events.
- da_robinson was associated with 12 account creation events.
- rthompson was associated with 4 account creation events.
- Several normal accounts were created with organizational context such as Finance, HR, and Sales.
- A suspicious account named hacker was created by rthompson.
- The hacker account was categorized as MALICIOUS in the dataset.
- Related group membership events showed the hacker account being added to the Administrators group.
- This provided additional context for investigating potentially unauthorized account creation and privilege assignment.

SOC Investigation Workflow
User Account Creation → Identify Creating User → Analyze New Account → Review Workstation/Department → Check Group Membership → Identify Suspicious Account/Privilege Assignment

Skills Practiced
Splunk | SPL | Windows Event ID 4720 | User Account Creation Analysis | Account Management Logs | Group Membership Analysis | Privilege Investigation | Timeline Analysis | SOC Investigation

Evidence
Screenshots demonstrate:
1. Account creation activity by user
2. Detailed analysis of newly created accounts
3. Related group membership changes and suspicious administrative activity

Conclusion
Successfully analyzed Windows user account creation activity in Splunk using Event ID 4720. The investigation identified normal account creation activity as well as a suspicious hacker account associated with rthompson. Related group membership analysis showed the account being added to the Administrators group, providing additional context for potential account compromise and privilege escalation investigation.
