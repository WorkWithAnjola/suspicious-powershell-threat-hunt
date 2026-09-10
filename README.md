# Suspicious PowerShell Hunt & Telemetry Engineering

![Category](https://img.shields.io/badge/Domain-Threat_Hunting_%26_SOC-blue?style=for-the-badge)
![MITRE](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Environment-Windows_11-informational?style=for-the-badge)
![Rule](https://img.shields.io/badge/Detection-Sigma-orange?style=for-the-badge)

## Project Overview
PowerShell remains a primary vector for Living-off-the-Land (LotL) execution, lateral movement, and defense evasion. Adversaries routinely encode payloads or pull tools straight into memory so nothing ever hits disk, easily bypassing standard signature checks.

This project focuses on establishing host-based telemetry, simulating real-world evasion methods, parsing raw event logs to expose de-obfuscated script blocks, and generating automated hunt queries and Sigma detection rules.

> **Key Takeaway:** Standard command-line logging (Event ID 4688) only records what is typed into the shell, such as an unreadable Base64 string. PowerShell Script Block Logging (Event ID 4104) inspects the runtime engine directly, capturing the actual code after it is unpacked in memory.

---

## Technical Stack & Telemetry Setup

* **Operating System:** Windows 11 Enterprise / Pro
* **Sensor Mechanism:** Windows PowerShell Script Block Logging (Event ID 4104)
* **Log Location:** `Applications and Services Logs/Microsoft/Windows/PowerShell/Operational`
* **Policy Location:** Local Group Policy (`gpedit.msc`) under `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`

### Telemetry Baseline Configuration
To achieve complete visibility, I turned on script block logging along with invocation start/stop tracking via Local Group Policy.

<p align="center">
  <img src="01_gpo_scriptblock_logging.png" alt="Script Block Logging GPO Configuration" width="700"/>
</p>
<p align="center"><em>Figure 1: Local Group Policy configuration enabling Script Block Logging and invocation tracking.</em></p>

---

## Adversary Simulation & MITRE ATT&CK

| Phase | Technique | MITRE ID | Tradecraft Summary |
| :--- | :--- | :--- | :--- |
| **Execution / Evasion** | Deobfuscate/Decode Files or Information | **T1027** / **T1059.001** | Obfuscated stager using `-EncodedCommand` (Base64) |
| **Ingress Tool Transfer** | Ingress Tool Transfer | **T1105** / **T1059.001** | In-memory web cradle via `.NET WebClient` and `IEX` |

### Simulation 1: Base64 Obfuscated Execution
Executed a stager passed as an encoded Unicode string designed to bypass static command-line string matching:

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAWwAhAF0AIABNAGEAbABpAGMAaQBvAHUAcwAgAFAAYQB5AGwAbwBhAGQAIABFAHgAZQBjAHUAdABlAGQAIgA=
