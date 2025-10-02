[MITRE_dashboard.xml.txt](https://github.com/user-attachments/files/21716229/MITRE_dashboard.xml.txt)# RealWorld Threat Detection and Hunting — MITRE ATT&CK Splunk Detections




Short pitch: A curated collection of Splunk SPL detections and dashboards mapped to the MITRE ATT&CK framework for Windows environments—ready for recruiters and hiring managers to evaluate your detection engineering skills.

Table of contents

1. Overview

2. Key features (what recruiters care about)

3. Detections included (summary table)

4. Quick demo (screenshots & expected outputs)

5. Install & run (step-by-step)

6. Importing dashboards & saved searches (examples)

7. Alert & priority guidance (how to tune)

8. Test data & validation (how to reproduce detections)

9. Contributing / License / Contact

1. Overview
   ---

This project demonstrates practical detection engineering for Windows environments using Splunk. The detections are mapped to MITRE ATT&CK techniques and built as modular SPL queries and XML dashboards so they can be imported into a Splunk app or used standalone.

Business value: Reduce dwell time by surfacing suspicious authentication patterns, credential dumping, obfuscated PowerShell usage, remote file downloads, and lateral movement indicators.

2. Key features (what recruiters care about)
   ---

 MITRE ATT&CK mapping for each detection (clear tactic & technique).

 Modular SPL files per detection so reviewers can run just one query.

 Dashboards & visualizations showing detection counts, trending, and affected hosts.

 Saved searches & alert examples for operationalizing detections.

 Testing instructions and sample logs to validate results.

 Clear README + demo screenshots so a recruiter can quickly understand scope and impact.

3. Detections included (summary table)
   --
ID	MITRE Technique	Short description
1.1	T1078	Successful logon tracking (EventID 4624)
1.2	T1110	Multiple failed logons (4625) — brute-force detection
1.3	T1110 → T1078	Failed attempts followed by success (compromised credentials)
1.4	T1078.002	Privileged logon detection (ElevatedPrivileges=Yes)
1.7	T1110	Multiple failed then success (time-correlated)
1.9	T1078	Logon from multiple source IPs (unique ip detection)
1.11	T1078.003	Suspicious service account use
1.12	T1021	Multiple hosts accessed by same user (lateral movement)
1.13–1.19	T1059.001	PowerShell obfuscation & base64 encoded commands
1.26, 1.47	T1003	Mimikatz / credential dumping detections
1.28, 1.40	T1105	Invoke-WebRequest / remote file download
1.33, 1.35, 1.37, 1.50	T1059, T1033	Command-shell activity & reconnaissance

5. Quick demo (screenshots & expected outputs)
   ---

(Include a few small screenshots in dashboards/ and link them here. Each screenshot should have a caption explaining what the reviewer is seeing: e.g. “Dashboard: Base64 PowerShell executions prioritized by host.”)

5. Install & run (step-by-step)
   ---

Prerequisites: Splunk Enterprise 8.x+, access to Windows Security logs indexed into Splunk.

Clone repository:

```
git clone https://github.com/tuh1n-bd/RealWorld-Threat-Detection-and-Hunting-mitre_attack.git
```

cd RealWorld-Threat-Detection-and-Hunting-mitre_attack

Import the dashboard XML files into Splunk (Settings → Dashboards → Import).

Copy queries/*.spl contents into new saved searches or run them manually to validate.

Tune thresholds and time windows in savedsearches.conf.example (below) to minimize false positives.

6. Importing dashboards & saved searches (examples)
   --

savedsearches.conf.example — create this under $SPLUNK_HOME/etc/apps/YourApp/local/savedsearches.conf

[Detect_Brute_Force_1.2]
search = index="sim1" sourcetype="cvs" EventID=4625 | stats count by Source_IP, Account_Name | where count >= 5
cron_schedule = */5 * * * *
disabled = 0
alert.severity = 3
alert.suppress = 0
alert.track = 1
[Detect_PowerShell_Base64_1.19]
search = index="sim1" sourcetype="cvs" CommandLine="*powershell*" (CommandLine="*-enc*" OR CommandLine="*-encodedCommand*") | table _time Account_Name ComputerName CommandLine
cron_schedule = */10 * * * *
disabled = 0
alert.severity = 4

Note: These are examples — tune where thresholds and cron_schedule for your environment.

7. Alert & priority guidance (how to tune)

High severity: Credential dumping (mimikatz), encoded payload execution, suspicious account privilege escalation.

Medium severity: Multiple failed logons, RDP logons from atypical geolocations.

Low severity: Single whoami commands, 1–2 failed attempts.

Suggested workflow: Have high severity trigger immediate analyst notification; medium queue for triage; low for hunting dashboards.


## Sample Detection Description




 Detection 1.1 — Successful Logon Event Tracking
MITRE Technique: [T1078] Valid Accounts (Track successful logons using EventID
4624 )
---
Explanation:
•	EventID=4624: Indicates a successful logon.
•	LogonType: Identifies how the user logged on (e.g., RDP, local, network).
•	This is useful to baseline normal login behavior.

spl:
```
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv" EventID=4624
| stats count by Account_Name, ComputerName, Source_IP, LogonType
| sort - count
```

<img width="1203" height="711" alt="mitre7" src="https://github.com/user-attachments/assets/b4270732-6107-41f8-97c2-0fd49ebacc6b" />

 Detection 1.2 – Multiple Failed Logon Attempts by Single Source IP
MITRE Technique: [T1110] Brute Force
Goal: Detect brute-force attacks from a single source IP attempting multiple logins.
 ----
 
 Explanation
•	EventID=4625: This represents failed logon attempts in Windows security logs.
•	Source_IP and Account_Name: Grouped to identify if a single IP is trying many different or same usernames.
•	count >= 5: Threshold to flag potential brute force.
•	Use Case: An attacker may guess passwords by repeatedly trying logins — this identifies such patterns.
spl:
```
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv"
EventID=4625
| stats count by Source_IP, Account_Name
| where count >= 5
| sort - count
```

🔹 Detection 1.3 — Successful Logon After Multiple Failures
MITRE Technique: [T1110] Brute Force → Credential Access
Goal: Detect cases where a user had multiple failed logon attempts followed by a successful one — indicating possible password guessing success.
--

Explanation:
•	EventID 4625: Failed logon attempt.
•	EventID 4624: Successful logon.
•	We group events by Account_Name and Source_IP to correlate activity.
•	Logic:
o	If a user has ≥3 failed attempts (4625) followed by at least 1 success (4624), it's highly suspicious.
•	Use Case: Brute-force password guessing that eventually succeeds.

spl:
```
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv"
(EventID=4625 OR EventID=4624)
| stats values(EventID) as event_list count(eval(EventID=4625)) as failed_attempts,
        count(eval(EventID=4624)) as success_count by Account_Name, Source_IP
| where failed_attempts >= 3 AND success_count >= 1
```

<img width="1209" height="700" alt="mitre2" src="https://github.com/user-attachments/assets/88a432b1-c4d8-44d4-a954-6ab6f9906aec" />

 Detection 1.4 — Privileged Logon Detection
MITRE Technique: [T1078.002] Valid Accounts: Domain Accounts
Goal: Detect logon events where privileged (admin-level) accounts are used — especially if unexpected.
---
 Explanation
•	EventID 4624: Successful logon.
•	ElevatedPrivileges="Yes": Indicates admin-level privileges were used.
•	LogonType:
o	Type 2 = Interactive (local)
o	Type 3 = Network
o	Type 10 = Remote (RDP)
Logic: We want to catch high-privilege accounts logging into systems, especially if the account is not commonly used or seen before.

spl:
```
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv"
EventID=4624 AND ElevatedPrivileges="Yes"
| stats count by Account_Name, Source_IP, ComputerName, LogonType
```

🔹 Detection 1.5 — Rare User Logon Detection
MITRE Technique: [T1078] Valid Accounts
Goal: Identify user accounts that log in very rarely, which could indicate account compromise, misuse, or initial foothold.
----

🔍 Explanation
•	EventID 4624 = successful logon events.
•	stats count by Account_Name = total number of logons per user.
•	eventstats avg(count) = calculate average logons across all users.
•	where count < avg_logons = show users logging in less than average.
•	Assumption: Rare logons might indicate newly active accounts used by attackers (e.g., old unused or service accounts).

spl:
```
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv" EventID=4624
| stats count by Account_Name
| eventstats avg(count) as avg_logons
| where count < avg_logons
| sort count
```

🔹 Detection 1.7 — Multiple Failed Logons Followed by Success
MITRE ATT&CK Technique: [T1110] Brute Force
Objective: Detect brute force attempts — several failed login attempts followed closely by a successful login from the same IP and user.
---

 Explanation Breakdown
•	EventID=4625: Failed logon
•	EventID=4624: Successful logon
•	stats values(EventID): Collects both successful and failed attempts
•	failed_count >= 3: Looks for 3+ failed attempts
•	last_event = 4624: Indicates a successful login happened at the end, which can suggest a brute-force success.

spl:
```
index="sim1" sourcetype="cvs" source="SecurityLogs_MITRE_Advanced_sample.csv" (EventID=4625 OR EventID=4624)
| stats values(EventID) as event_list count(eval(EventID=4625)) as failed_count latest(EventID) as last_event by Account_Name, Source_IP
| where failed_count >= 3 AND last_event=4624
```

 Detection 1.9 — Logon from Multiple Locations by Same User
 MITRE ATT&CK Mapping
•	Technique: T1078 – Valid Accounts
•	Tactic: Credential Access / Defense Evasion
Goal: Detect if a single user logs in from multiple different Source IPs in a short time — a common sign of credential compromise or lateral movement.
--

 Explanation:
index="sim1" sourcetype="cvs"	Searches your dataset
stats dc(Source_IP)	Counts distinct IPs per user
values(Source_IP)	Lists the IPs each user logged in from
BY Account_Name	Groups the stats per user
where unique_ips > 1	Filters for users who logged in from more than one IP
sort - unique_ips	Sorts users by highest number of IPs used

spl:
```
index="sim1" sourcetype="cvs"
| stats dc(Source_IP) AS unique_ips values(Source_IP) AS ips_list BY Account_Name
| where unique_ips > 1
| sort - unique_ips
```

<img width="1215" height="708" alt="mitre4" src="https://github.com/user-attachments/assets/6125a307-3544-45d4-9735-7407b6e7fedb" />


 Detection 1.11 — Suspicious Use of Service Accounts
 MITRE ATT&CK Mapping
•	Technique: T1078.003 – Valid Accounts: Local Accounts
•	Tactic: Initial Access / Persistence / Privilege Escalation
--

Objective
Detect service accounts (e.g., accounts like svc_, admin$, or backup_user) being used interactively or in ways that aren't typical (such as interactive logins or lateral movement).

Explanation:
SPL Component	Meaning
like(Account_Name, "svc_%")	Detects service accounts with naming conventions like svc_
like(Account_Name, "%$")	Detects Windows built-in/admin accounts ending in $
stats count BY ...	Shows number of times these accounts appeared
sort - count	Prioritizes most active service accounts

spl:
```
index="sim1" sourcetype="cvs"
| where like(Account_Name, "svc_%") OR like(Account_Name, "%$") OR like(Account_Name, "backup_%")
| stats count BY Account_Name, ComputerName, Source_IP
| sort - count
```
🔸 Detection 1.12 — Multiple Hosts Accessed by Same User in Short Time
📖 MITRE ATT&CK Mapping
•	Technique: T1021 – Remote Services
•	Tactic: Lateral Movement
---
Objective
Detect users who access multiple different hosts within a short time window, indicating potential lateral movement activity.

 Explanation of SPL
SPL Component	Purpose
bin _time span=10m	Buckets time into 10-minute windows
dc(ComputerName)	Counts distinct hosts accessed
values(ComputerName)	Lists those hosts
where unique_hosts >= 3	Filters users who accessed 3+ different systems in 10 minutes
sort - _time	Shows latest activity first

spl:
```
index="sim1" sourcetype="cvs"
| bin _time span=10m
| stats dc(ComputerName) AS unique_hosts values(ComputerName) AS hosts BY Account_Name, _time
| where unique_hosts >= 3
| sort - _time
```
<img width="1201" height="706" alt="mitre5" src="https://github.com/user-attachments/assets/941a310f-bdbe-4682-a5a6-c36fafdb2f8d" />


Detection 1.13 — Suspicious Use of Encoded Commands
MITRE ATT&CK Mapping
•	Technique: T1059.001 – Command and Scripting Interpreter: PowerShell
•	Tactic: Execution
--
Objective:
Detect the use of encoded PowerShell commands, which is a common obfuscation technique used by attackers to hide malicious activity.

Explanation:
SPL Part	Role
CommandLine="*powershell*"	Detects usage of PowerShell
CommandLine="*-enc*" OR "-e *"	Looks for encoded/shortened command switches
table	Displays relevant fields for analysis
sort - _time	Shows recent activity first

spl:
```
index="sim1" sourcetype="cvs"
| search CommandLine="*powershell*" CommandLine="*-enc*" OR CommandLine="*-e *"
| table _time Account_Name ComputerName CommandLine MITRE_Technique
| sort - _time
```

Detection 1.14 — Use of Mimikatz or Credential Dumping Tools
MITRE ATT&CK Mapping
•	Technique: T1003 – OS Credential Dumping
•	Tactic: Credential Access
---
Objective:
Detect execution of Mimikatz or other known credential dumping tools, often used by attackers to extract passwords and hashes from memory or SAM/LSASS.

Explanation of SPL
SPL Part	Description
CommandLine="*mimikatz*"	Direct detection of Mimikatz
CommandLine="*lsass*"	LSASS often targeted for dumping credentials
CommandLine="*sekurlsa*" / *logonpasswords*	Common Mimikatz modules
table	Returns key investigation fields
sort - _time	Recent activity on top

spl:
```
index="sim1" sourcetype="cvs"
| search CommandLine="*mimikatz*" OR CommandLine="*lsass*" OR CommandLine="*sekurlsa*" OR CommandLine="*logonpasswords*"
| table _time Account_Name ComputerName CommandLine MITRE_Technique
| sort - _time
```
<img width="1198" height="703" alt="mitre6" src="https://github.com/user-attachments/assets/510a7cad-d3ce-4ffb-b079-bff0760a9ae2" />


Detection 1.16 — PowerShell Base64 Encoded Execution
MITRE ATT&CK Mapping
•	Technique: T1059.001 – Command and Scripting Interpreter: PowerShell
•	Tactic: Execution
----
Objective:
Detect obfuscated or encoded PowerShell execution, often used by attackers to bypass security controls.
________________________________________

spl:
```
index="sim1" sourcetype="cvs"
| search CommandLine="*powershell*" CommandLine="*-enc*" 
| table _time Account_Name ComputerName CommandLine MITRE_Technique
| sort - _time
```
________________________________________
Explanation:
SPL Part	Description
CommandLine="*powershell*"	Finds any PowerShell execution
CommandLine="*-enc*"	Targets the -enc or -encodedCommand flag, which is used to run base64-encoded PowerShell commands
table	Filters output to the essential fields
sort - _time	Shows the most recent events first

🔸 Detection 1.19 — PowerShell Base64 Encoded Commands
📖 MITRE ATT&CK Mapping
•	Technique: T1059.001 – Command and Scripting Interpreter: PowerShell
•	Tactic: Execution
---
Objective
Detect PowerShell commands that use Base64-encoded payloads via -enc or -encodedCommand. This is a common obfuscation method used by attackers to hide their real commands.
________________________________________

spl:
```
index="sim1" sourcetype="cvs"
| search CommandLine="*powershell*" (CommandLine="*-enc*" OR CommandLine="*-encodedCommand*")
| table _time Account_Name ComputerName CommandLine MITRE_Technique
| sort - _time
```
Explanation:
SPL Segment	Explanation
CommandLine="*powershell*"	Filters PowerShell executions
*-enc* or *-encodedCommand*	Detects Base64-encoded payload usage
table	Displays essential context fields
sort - _time	Shows most recent events first

<img width="1203" height="711" alt="mitre7" src="https://github.com/user-attachments/assets/251cd39e-76de-471e-b80d-73865e3fc580" />

____
Image: 1.19, 1.26
-
https://media.licdn.com/dms/image/v2/D5622AQELJ0dkY-fCAg/feedshare-shrink_1280/B56Ziui9LpHkAw-/0/1755275056471?e=1758153600&v=beta&t=3zuuUsTHkz2G1C0jprC2WEUbrEQS3Bjp5SwU_6hkfZQ

 Detection 1.26 — Credential Dumping via Mimikatz
MITRE Technique: T1003 – OS Credential Dumping
--
SPL:
```
index="sim1" sourcetype="cvs"
CommandLine="*mimikatz*"
| stats count by Account_Name, CommandLine, ComputerName, _time
```
_____
Explanation:
•	mimikatz.exe is a well-known tool for stealing plaintext passwords, hashes, and Kerberos tickets.
•	Even a reference to mimikatz in CommandLine is highly suspicious.
____

Detection 1.27 — Base64 Encoded PowerShell Execution
MITRE Technique: T1059.001 – PowerShell
Sub-technique: Obfuscated Command Execution
---
SPL 
```
index="sim1" sourcetype="cvs"
CommandLine="*powershell* -enc*"
| stats count by Account_Name, CommandLine, ComputerName, _time
```
_____
Explanation:
•	This detects powershell -enc, where encoded Base64 commands are run to hide the actual payload.
•	Very common in phishing payloads and malware loaders.

<img width="1204" height="717" alt="mitre8" src="https://github.com/user-attachments/assets/0eefc9a4-c3f8-468e-b673-ce8298dff3e6" />

Image: 1.27 and 1.28
--
https://media.licdn.com/dms/image/v2/D4E22AQE7BfiTzsmV6w/feedshare-shrink_2048_1536/B4EZiplkggGYAs-/0/1755191855853?e=1758153600&v=beta&t=ZCsBEgG3yjk-m9kdrWk7W4Ot_ZHTn6ukS2cQaXNe30w

____
Detection 1.28 — Remote File Download via Invoke-WebRequest
MITRE Technique: T1105 – Ingress Tool Transfer
---
SPL
```
index="sim1" sourcetype="cvs"
CommandLine="*Invoke-WebRequest*"
| stats count by Account_Name, CommandLine, ComputerName, _time
```
______
 Explanation:
•	This detects Invoke-WebRequest, a PowerShell cmdlet used to download tools, payloads, or second-stage malware.
•	Key for detecting infection or initial access phases.
____
Detection 1.33 — Execution of Obfuscated Scripts using cmd.exe /c
MITRE Technique: T1059.003 – Command and Scripting Interpreter: Windows Command Shell
--
SPL:
```
index="sim1" sourcetype="cvs"
CommandLine="*cmd.exe /c*"
| stats count by Account_Name, CommandLine, ComputerName, _time
```
____
Explanation:
•	cmd.exe /c tells Windows to run a command, then exit — often used for automation or obfuscated execution.
•	Often paired with encoded PowerShell or scripting payloads.
___________

<img width="1196" height="707" alt="mitre9" src="https://github.com/user-attachments/assets/630645bb-2126-46b2-853f-e3bd1de0e1d8" />

Image: 1.33, 1.35
--
https://media.licdn.com/dms/image/v2/D4E22AQGOeOq4c0fSbg/feedshare-shrink_1280/B4EZifgqgQGUAk-/0/1755022797670?e=1758153600&v=beta&t=Z-QAgthdES_RezGf2BZzkKrF4iuQRiFz6k0-IDd0azM

Detection 1.35 — Suspicious CommandLine Execution Involving Encoded Scripts
MITRE Technique: T1059.001 – PowerShell
--
SPL:
```
index="sim1" sourcetype="cvs"
CommandLine="*powershell* *-EncodedCommand*"
| stats count by Account_Name, CommandLine, ComputerName, _time
```
___
Explanation:
•	Variation of base64 PowerShell encoding detection.
•	This syntax is typical of obfuscated or malicious scripts run via -EncodedCommand.
____

Detection 1.37 — Suspicious Use of whoami via cmd.exe
MITRE Technique: T1033 – System Owner/User Discovery
--
SPL:
```
index="sim1" sourcetype="cvs"
CommandLine="*cmd.exe*whoami*"
| stats count by Account_Name, CommandLine, ComputerName, _time
```
___
Explanation:
•	Attackers use whoami to learn about the current user context after gaining access.
•	This is useful for privilege escalation decisions.
___

<img width="1198" height="707" alt="mitre10" src="https://github.com/user-attachments/assets/88d55361-764c-44ef-9c42-84c9908c94a7" />

Image: 1.37, 1.40
--
https://media.licdn.com/dms/image/v2/D4E22AQGRUyoDN-qqwA/feedshare-shrink_1280/B4EZijqsJwGYAk-/0/1755092534540?e=1758153600&v=beta&t=qxEBGDXkebBcVvTLmTGxqcl5wfjD6Rq7pA7sICXUyNI

Detection 1.40 — Use of Invoke-WebRequest in PowerShell
MITRE Technique: T1105 – Ingress Tool Transfer
--
SPL:
```
index="sim1" sourcetype="cvs"
CommandLine="*Invoke-WebRequest*"
| stats count by Account_Name, CommandLine, ComputerName, _time
```
Explanation:
•	Invoke-WebRequest is commonly used in PowerShell to download payloads or interact with C2.
•	This detection reveals PowerShell-based download activity.
____________________________

Detection 1.41 — PowerShell Encoded Command Execution
MITRE Technique: T1059.001 – Command and Scripting Interpreter: PowerShell
--
SPL:
```
index="sim1" sourcetype="cvs"
CommandLine="*powershell*"
| search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
| stats count by Account_Name, CommandLine, ComputerName, _time
```
____________________________________________________
Explanation:
•	Attackers use encoded PowerShell to obfuscate commands.
•	-enc or -encodedcommand is a red flag.
____________________

<img width="1208" height="707" alt="mitre11" src="https://github.com/user-attachments/assets/6c9e07c5-9957-4026-9c05-272d6ffbb52d" />

Image: 1.41, 1.47
-
https://media.licdn.com/dms/image/v2/D4D22AQF_swgEUgiX8Q/feedshare-shrink_1280/B4DZiZ6FKiGkAo-/0/1754928797072?e=1758153600&v=beta&t=BipsVUx_gV-H-1nSmzkdY_ihHjQP3acQxCGqT_kTTes

🔹 Detection 1.47 — Execution of Mimikatz
MITRE Technique: T1003 – OS Credential Dumping
--
____________________
SPL:
```
index="sim1" sourcetype="cvs"
CommandLine="*mimikatz*"
| stats count by Account_Name, CommandLine, ComputerName, _time
```
________________________________________________________
Explanation:
•	mimikatz is a well-known tool for dumping credentials from LSASS memory.
•	Any execution of mimikatz.exe should raise high-priority alerts


🔹 Detection 1.50 — Use of whoami Command (Reconnaissance)
MITRE Technique: T1033 – System Owner/User Discovery
--
________________________________________________________
SPL:
```
index="sim1" sourcetype="cvs"
CommandLine="*whoami*"
| stats count by Account_Name, CommandLine, ComputerName, _time
```
_________________________________________________________________
Explanation:
•	whoami is used by attackers to check the current user context, privilege level, or domain info.
•	Often appears early in attack chains as recon.

<img width="1191" height="509" alt="mitre12" src="https://github.com/user-attachments/assets/ae874915-01f8-44af-88a0-a7c35125f830" />


How to Use
---
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
Email: moglibd22@gmail.com
GitHub: tuh1n-bd

Thank you for visiting my repository!
