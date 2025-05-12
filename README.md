# 🛡️ Microsoft Sentinel Use Cases - Curated Playbooks, KQL, and SOAR Insights

Welcome to the **Microsoft Sentinel Use Case Library**, a curated collection of real-world security detection scenarios, complete with:

- ✅ **Analytic Rules** powered by KQL
- 🔁 **Detection Workflows**
- 🤖 **SOAR Automation Examples**
- 📘 **False/True Positive Analysis**

This repository is tailored to empower **SOC Analysts, Detection Engineers, and Threat Hunters** by accelerating detection development, response workflows, and operational maturity within Microsoft Sentinel.

---

## 📂 Folder Structure

/UseCases/
├── BruteForceDetection/
│ ├── workflow.md
│ ├── detection.kql
│ └── playbook.json
├── RansomwareActivity/
├── OAuthConsentGrant/
├── LateralMovement/
├── SuspiciousRegistryChange/
└── README.md

---

## 📊 Analytic Rules (KQL) + Workflow

Each use case includes:

- **Title and Objective**
- **Detection Query (KQL)**
- **MITRE ATT&CK Mapping**
- **Trigger Conditions**
- **Workflow Description**
- **False/True Positive Context**
- **Response Guidance**

---

## 🧠 Example Use Case: RDP Brute Force Detection

### 🔎 Objective
Detect multiple failed RDP login attempts followed by a successful login from the same IP.

### 💻 Query (KQL)

let failedLogins = SecurityEvent
| where EventID == 4625 and AccountType == "User"
| summarize FailedCount = count() by TargetUserName, IPAddress = IPAddress, bin(TimeGenerated, 5m)
| where FailedCount > 10;

let successfulLogins = SecurityEvent
| where EventID == 4624 and LogonType == 10
| project TargetUserName, IPAddress = IPAddress, SuccessTime = TimeGenerated;

failedLogins
| join kind=inner (
    successfulLogins
) on TargetUserName, IPAddress
| where SuccessTime between (TimeGenerated .. TimeGenerated + 10m)
🧭 Workflow
Detect >10 failed logins in 5 min.

Correlate with a successful login from the same IP.

Alert triggered.

⚔️ MITRE ATT&CK
Technique: T1110 (Brute Force)

Tactic: Credential Access

🚦 FP/TP Analysis
False Positives: Misconfigured login clients, VPN IP reuse.

True Positives: Unfamiliar IPs, repeated brute force behavior.

🛠️ SOAR Playbook
Auto-block IP using Firewall or Conditional Access.

Notify SOC via Teams.

Enrich IP with Threat Intelligence.

🔁 SOAR Examples
Playbook Name	Purpose
AutoBlockIP-OnAlert	Automatically block source IPs in Azure NSG/Firewall.
NotifySOC-Teams: Send alert + entity summary to the Teams channel.
Enrich-With-TI	Query TI platforms (VirusTotal, MISP) for context.
ContainHost-Isolate: Isolate the compromised host via Defender for Endpoint.

🔐 Sample Use Cases
Use Case	Description	MITRE
OAuth Consent Grant Abuse	Detect risky OAuth app approvals by users.	T1528
Ransomware File Encryption	Detect extension renames + ransom notes.	T1486
Pass-the-Hash via NTLM: Detect lateral movement using NTLM logins.	T1550.002
Unfamiliar Country Login	Detect logins from unusual geolocations.	T1078
Suspicious Registry Changes	Detect registry persistence attempts.	T1112

📬 Contributing
We welcome community contributions! Open a PR or issue if you have a useful KQL, response workflow, or SOAR automation.

🧾 License
MIT License

🙋‍♂️ Maintainers
This repo is maintained by security professionals dedicated to advancing SOC capabilities using Microsoft Sentinel.

Have a use case in mind? Open an issue.
