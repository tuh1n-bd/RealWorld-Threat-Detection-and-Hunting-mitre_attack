[MITRE_dashboard.xml.txt](https://github.com/user-attachments/files/21716229/MITRE_dashboard.xml.txt)# RealWorld Threat Detection and Hunting — MITRE ATT&CK Splunk Detections

Welcome to the **RealWorld Threat Detection and Hunting** repository, focused on advanced Splunk SPL queries and dashboards designed to detect and investigate real-world cyber attack scenarios mapped to the MITRE ATT&CK framework.

----------------------------------------------------------------------------------------

## Overview

This repository contains a collection of Splunk detection queries created to identify attacker techniques and suspicious behaviors within Windows environments. The detections are aligned with MITRE ATT&CK tactics and techniques, providing security analysts with effective tools for threat hunting and incident investigation.

The following detection queries have been successfully tested and are included:
1.1, 1.2, 1.3, 1.4, 1.5, 1.7, 1.9, 1.11, 1.12, 1.13, 1.14, 1.16, 1.19, 1.26, 1.27, 1.28, 1.33, 1.35, 1.37, 1.40, 1.41, 1.47, 1.50


- **queries/** — Contains individual SPL queries for each detection use case.
- **dashboards/** — Contains Splunk dashboard XML files for visualization.
- **README.md** — This documentation file.

-----------------------------------------------------------------------------------------

## Sample Detection Description




🔹  Detection 1.1 — Successful Logon Event Tracking
MITRE Technique: [T1078] Valid Accounts (Track successful logons using EventID
4624 )

Explanation:
•	EventID=4624: Indicates a successful logon.
•	LogonType: Identifies how the user logged on (e.g., RDP, local, network).
•	This is useful to baseline normal login behavior.

spl:
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv" EventID=4624
| stats count by Account_Name, ComputerName, Source_IP, LogonType
| sort - count

🔹  Detection 1.2 – Multiple Failed Logon Attempts by Single Source IP
MITRE Technique: [T1110] Brute Force
Goal: Detect brute-force attacks from a single source IP attempting multiple logins.
 
🔍 Explanation
•	EventID=4625: This represents failed logon attempts in Windows security logs.
•	Source_IP and Account_Name: Grouped to identify if a single IP is trying many different or same usernames.
•	count >= 5: Threshold to flag potential brute force.
•	Use Case: An attacker may guess passwords by repeatedly trying logins — this identifies such patterns.
spl:
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv"
EventID=4625
| stats count by Source_IP, Account_Name
| where count >= 5
| sort - count

🔹 Detection 1.3 — Successful Logon After Multiple Failures
MITRE Technique: [T1110] Brute Force → Credential Access
Goal: Detect cases where a user had multiple failed logon attempts followed by a successful one — indicating possible password guessing success.
🔍 Explanation
•	EventID 4625: Failed logon attempt.
•	EventID 4624: Successful logon.
•	We group events by Account_Name and Source_IP to correlate activity.
•	Logic:
o	If a user has ≥3 failed attempts (4625) followed by at least 1 success (4624), it's highly suspicious.
•	Use Case: Brute-force password guessing that eventually succeeds.

spl:
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv"
(EventID=4625 OR EventID=4624)
| stats values(EventID) as event_list count(eval(EventID=4625)) as failed_attempts,
        count(eval(EventID=4624)) as success_count by Account_Name, Source_IP
| where failed_attempts >= 3 AND success_count >= 1

🔹 Detection 1.4 — Privileged Logon Detection
MITRE Technique: [T1078.002] Valid Accounts: Domain Accounts
Goal: Detect logon events where privileged (admin-level) accounts are used — especially if unexpected.
🔍 Explanation
•	EventID 4624: Successful logon.
•	ElevatedPrivileges="Yes": Indicates admin-level privileges were used.
•	LogonType:
o	Type 2 = Interactive (local)
o	Type 3 = Network
o	Type 10 = Remote (RDP)
Logic: We want to catch high-privilege accounts logging into systems, especially if the account is not commonly used or seen before.

spl:
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv"
EventID=4624 AND ElevatedPrivileges="Yes"
| stats count by Account_Name, Source_IP, ComputerName, LogonType

🔹 Detection 1.5 — Rare User Logon Detection
MITRE Technique: [T1078] Valid Accounts
Goal: Identify user accounts that log in very rarely, which could indicate account compromise, misuse, or initial foothold.

🔍 Explanation
•	EventID 4624 = successful logon events.
•	stats count by Account_Name = total number of logons per user.
•	eventstats avg(count) = calculate average logons across all users.
•	where count < avg_logons = show users logging in less than average.
•	Assumption: Rare logons might indicate newly active accounts used by attackers (e.g., old unused or service accounts).

spl:
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv" EventID=4624
| stats count by Account_Name
| eventstats avg(count) as avg_logons
| where count < avg_logons
| sort count

🔹 Detection 1.7 — Multiple Failed Logons Followed by Success
MITRE ATT&CK Technique: [T1110] Brute Force
Objective: Detect brute force attempts — several failed login attempts followed closely by a successful login from the same IP and user.

🔍 Explanation Breakdown
•	EventID=4625: Failed logon
•	EventID=4624: Successful logon
•	stats values(EventID): Collects both successful and failed attempts
•	failed_count >= 3: Looks for 3+ failed attempts
•	last_event = 4624: Indicates a successful login happened at the end, which can suggest a brute-force success.

spl:
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv" (EventID=4625 OR EventID=4624)
| stats values(EventID) as event_list count(eval(EventID=4625)) as failed_count latest(EventID) as last_event by Account_Name, Source_IP
| where failed_count >= 3 AND last_event=4624

🔸 Detection 1.9 — Logon from Multiple Locations by Same User
📖 MITRE ATT&CK Mapping
•	Technique: T1078 – Valid Accounts
•	Tactic: Credential Access / Defense Evasion
Goal: Detect if a single user logs in from multiple different Source IPs in a short time — a common sign of credential compromise or lateral movement.

🧠 Explanation of SPL:
Part	What It Does
index="sim1" sourcetype="cvs"	Searches your dataset
stats dc(Source_IP)	Counts distinct IPs per user
values(Source_IP)	Lists the IPs each user logged in from
BY Account_Name	Groups the stats per user
where unique_ips > 1	Filters for users who logged in from more than one IP
sort - unique_ips	Sorts users by highest number of IPs used

spl:
index="sim1" sourcetype="cvs"
| stats dc(Source_IP) AS unique_ips values(Source_IP) AS ips_list BY Account_Name
| where unique_ips > 1
| sort - unique_ips

🔸 Detection 1.11 — Suspicious Use of Service Accounts
________________________________________
📖 MITRE ATT&CK Mapping
•	Technique: T1078.003 – Valid Accounts: Local Accounts
•	Tactic: Initial Access / Persistence / Privilege Escalation
________________________________________
🎯 Objective
Detect service accounts (e.g., accounts like svc_, admin$, or backup_user) being used interactively or in ways that aren't typical (such as interactive logins or lateral movement).

🔍 Explanation of SPL
SPL Component	Meaning
like(Account_Name, "svc_%")	Detects service accounts with naming conventions like svc_
like(Account_Name, "%$")	Detects Windows built-in/admin accounts ending in $
stats count BY ...	Shows number of times these accounts appeared
sort - count	Prioritizes most active service accounts

spl:
index="sim1" sourcetype="cvs"
| where like(Account_Name, "svc_%") OR like(Account_Name, "%$") OR like(Account_Name, "backup_%")
| stats count BY Account_Name, ComputerName, Source_IP
| sort - count

🔸 Detection 1.12 — Multiple Hosts Accessed by Same User in Short Time
________________________________________
📖 MITRE ATT&CK Mapping
•	Technique: T1021 – Remote Services
•	Tactic: Lateral Movement
________________________________________
🎯 Objective
Detect users who access multiple different hosts within a short time window, indicating potential lateral movement activity.

🔍 Explanation of SPL
SPL Component	Purpose
bin _time span=10m	Buckets time into 10-minute windows
dc(ComputerName)	Counts distinct hosts accessed
values(ComputerName)	Lists those hosts
where unique_hosts >= 3	Filters users who accessed 3+ different systems in 10 minutes
sort - _time	Shows latest activity first

spl:
index="sim1" sourcetype="cvs"
| bin _time span=10m
| stats dc(ComputerName) AS unique_hosts values(ComputerName) AS hosts BY Account_Name, _time
| where unique_hosts >= 3
| sort - _time

🔸 Detection 1.13 — Suspicious Use of Encoded Commands
________________________________________
📖 MITRE ATT&CK Mapping
•	Technique: T1059.001 – Command and Scripting Interpreter: PowerShell
•	Tactic: Execution
________________________________________
🎯 Objective
Detect the use of encoded PowerShell commands, which is a common obfuscation technique used by attackers to hide malicious activity.

🔍 Explanation of SPL
SPL Part	Role
CommandLine="*powershell*"	Detects usage of PowerShell
CommandLine="*-enc*" OR "-e *"	Looks for encoded/shortened command switches
table	Displays relevant fields for analysis
sort - _time	Shows recent activity first

spl:
index="sim1" sourcetype="cvs"
| search CommandLine="*powershell*" CommandLine="*-enc*" OR CommandLine="*-e *"
| table _time Account_Name ComputerName CommandLine MITRE_Technique
| sort - _time

🔸 Detection 1.14 — Use of Mimikatz or Credential Dumping Tools
________________________________________
📖 MITRE ATT&CK Mapping
•	Technique: T1003 – OS Credential Dumping
•	Tactic: Credential Access
________________________________________
🎯 Objective
Detect execution of Mimikatz or other known credential dumping tools, often used by attackers to extract passwords and hashes from memory or SAM/LSASS.

🔍 Explanation of SPL
SPL Part	Description
CommandLine="*mimikatz*"	Direct detection of Mimikatz
CommandLine="*lsass*"	LSASS often targeted for dumping credentials
CommandLine="*sekurlsa*" / *logonpasswords*	Common Mimikatz modules
table	Returns key investigation fields
sort - _time	Recent activity on top

spl:
index="sim1" sourcetype="cvs"
| search CommandLine="*mimikatz*" OR CommandLine="*lsass*" OR CommandLine="*sekurlsa*" OR CommandLine="*logonpasswords*"
| table _time Account_Name ComputerName CommandLine MITRE_Technique
| sort - _time

🔸 Detection 1.16 — PowerShell Base64 Encoded Execution
________________________________________
📖 MITRE ATT&CK Mapping
•	Technique: T1059.001 – Command and Scripting Interpreter: PowerShell
•	Tactic: Execution
________________________________________
🎯 Objective
Detect obfuscated or encoded PowerShell execution, often used by attackers to bypass security controls.
________________________________________
🧠 SPL Detection Logic
spl:
index="sim1" sourcetype="cvs"
| search CommandLine="*powershell*" CommandLine="*-enc*" 
| table _time Account_Name ComputerName CommandLine MITRE_Technique
| sort - _time
________________________________________
🔍 Explanation of SPL
SPL Part	Description
CommandLine="*powershell*"	Finds any PowerShell execution
CommandLine="*-enc*"	Targets the -enc or -encodedCommand flag, which is used to run base64-encoded PowerShell commands
table	Filters output to the essential fields
sort - _time	Shows the most recent events first

🔸 Detection 1.19 — PowerShell Base64 Encoded Commands
________________________________________
📖 MITRE ATT&CK Mapping
•	Technique: T1059.001 – Command and Scripting Interpreter: PowerShell
•	Tactic: Execution
________________________________________
🎯 Objective
Detect PowerShell commands that use Base64-encoded payloads via -enc or -encodedCommand. This is a common obfuscation method used by attackers to hide their real commands.
________________________________________
🧠 SPL Detection Logic
spl:
index="sim1" sourcetype="cvs"
| search CommandLine="*powershell*" (CommandLine="*-enc*" OR CommandLine="*-encodedCommand*")
| table _time Account_Name ComputerName CommandLine MITRE_Technique
| sort - _time
________________________________________
🔍 Explanation of SPL
SPL Segment	Explanation
CommandLine="*powershell*"	Filters PowerShell executions
*-enc* or *-encodedCommand*	Detects Base64-encoded payload usage
table	Displays essential context fields
sort - _time	Shows most recent events first

🔸 Detection 1.26 — Credential Dumping via Mimikatz
MITRE Technique: T1003 – OS Credential Dumping
🔍 SPL Query:
spl:
index="sim1" sourcetype="cvs"
CommandLine="*mimikatz*"
| stats count by Account_Name, CommandLine, ComputerName, _time
🧠 Explanation:
•	mimikatz.exe is a well-known tool for stealing plaintext passwords, hashes, and Kerberos tickets.
•	Even a reference to mimikatz in CommandLine is highly suspicious.




=================================================
=================================================

# Image:
https://media.licdn.com/dms/image/v2/D4E22AQGOeOq4c0fSbg/feedshare-shrink_1280/B4EZifgqgQGUAk-/0/1755022797670?e=1758153600&v=beta&t=Z-QAgthdES_RezGf2BZzkKrF4iuQRiFz6k0-IDd0azM


How to Use
Clone this repository:

git clone https://github.com/tuh1n-bd/RealWorld-Threat-Detection-and-Hunting-mitre_attack.git
cd RealWorld-Threat-Detection-and-Hunting-mitre_attack

Import the SPL queries into your Splunk instance.

Load the dashboards to visualize detection results.

Customize and test detections against your own datasets.

Requirements

Splunk Enterprise 8.x or newer

Windows Security event logs indexed in Splunk

Basic understanding of SPL and MITRE ATT&CK framework

About Me
I am a cybersecurity enthusiast specializing in detection engineering and threat hunting using Splunk. This repository demonstrates my practical skills aligned with real-world attack techniques.

Contact
For questions or collaboration, reach me at:
Email: tuhin.teach@gmail.com
GitHub: tuhinexpert

Thank you for visiting my repository!
