# RealWorld Threat Detection and Hunting — MITRE ATT&CK Splunk Detections

Welcome to the **RealWorld Threat Detection and Hunting** repository, focused on advanced Splunk SPL queries and dashboards designed to detect and investigate real-world cyber attack scenarios mapped to the MITRE ATT&CK framework.

---

## Overview

This repository contains a collection of Splunk detection queries created to identify attacker techniques and suspicious behaviors within Windows environments. The detections are aligned with MITRE ATT&CK tactics and techniques, providing security analysts with effective tools for threat hunting and incident investigation.

The following detection queries have been successfully tested and are included:
1.1, 1.2, 1.3, 1.4, 1.5, 1.7, 1.9, 1.11, 1.12, 1.13, 1.14, 1.16, 1.19, 1.26, 1.27, 1.28, 1.33, 1.35, 1.37, 1.40, 1.41, 1.47, 1.50


- **queries/** — Contains individual SPL queries for each detection use case.
- **dashboards/** — Contains Splunk dashboard XML files for visualization.
- **README.md** — This documentation file.

---

## Sample Detection Description

### Detection 1.1 — Failed Login Attempts

Detects multiple failed login attempts, which may indicate brute force attacks.

**Key fields:** `EventID=4625`, `Account_Name`, `Source_IP`  
**MITRE Technique:** T1110 - Brute Force

```spl
index=security EventID=4625 | stats count by Account_Name, Source_IP

How to Use
Clone this repository:

git clone https://github.com/tuhinexpert/RealWorld-Threat-Detection-and-Hunting-mitre_attack.git
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
