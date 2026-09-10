Suspicious PowerShell Hunt & Endpoint Telemetry AnalysisProject OverviewPowerShell remains one of the most common vectors for Living-off-the-Land (LotL) execution, lateral movement, and defense evasion. Threat actors routinely encode commands or leverage in-memory cradles so files never touch the disk, blinding legacy signature detection.The goal of this project was to establish robust endpoint visibility, simulate real-world evasion techniques, examine raw Windows Event logs to extract de-obfuscated script blocks, and build automated hunting queries along with Sigma detection rules.Architecture and Telemetry SetupPlatform: Windows 11Core Sensor: Windows PowerShell Script Block Logging (Event ID 4104)Configuration: Enabled through Local Group Policy (gpedit.msc) under Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging.Adversary Simulations & MITRE ATT&CK MappingScenarioMITRE ATT&CK IDSimulated TechniqueObfuscated StagerT1027 / T1059.001Encoded execution using -EncodedCommand with base64 payloadMemory-Only Web CradleT1105 / T1059.001In-memory code execution via Net.WebClient and Invoke-ExpressionSimulation 1: Base64 ObfuscationTo simulate payload hiding, I executed a script block passed as an encoded Unicode string designed to conceal its intent from command line process creation monitoring:PowerShellpowershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAWwAhAF0AIABNAGEAbABpAGMAaQBvAHUAcwAgAFAAYQB5AGwAbwBhAGQAIABFAHgAZQBjAHUAdABlAGQAIgA=
Simulation 2: In-Memory Web CradleTo simulate fileless staging, I triggered a memory-resident cradle executing directly inside the current session:PowerShell$wc = New-Object System.Net.WebClient; $payload = "Write-Host '[!] Web Cradle Download Executed Successfully' -ForegroundColor Red"; Invoke-Expression $payload
Forensic Analysis & Evidence CollectionStandard command line logs (like Security Event 4688) only record the encoded base64 string. However, PowerShell Script Block Logging (Event ID 4104) intercepts the script at the runtime compiler stage after Windows decodes it in memory.De-obfuscated Artifact ExtractionChecking the Microsoft-Windows-PowerShell/Operational log confirms that Event ID 4104 caught the decoded code cleanly:Key logged artifact:PlaintextCreating Scriptblock text (1 of 1):
Write-Host "[!] Malicious Payload Executed"
Automated Threat HuntingRather than manually sifting through thousands of operational events in Event Viewer, I developed a targeted PowerShell script to extract matching script blocks:PowerShellGet-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 100 | 
Where-Object { $_.Message -match 'Malicious Payload Executed' } | 
Select-Object -First 1 | 
Format-List TimeCreated, Id, @{Name='MatchedScriptBlock'; Expression={($_.Message -split "`r?`n")[0..3] -join "`n"}}
Detection Engineering: Sigma RuleTo automate alerting in enterprise SIEM environments, I wrote a detection rule targeting the specific cmdlets and staging flags observed during the attack:YAMLtitle: Suspicious PowerShell Staging and Web Cradle Execution
id: 9a2f7411-89bc-4321-9def-0123456789ab
status: experimental
description: Identifies suspicious script blocks indicative of base64 obfuscation or remote cradle activity.
logsource:
    product: windows
    service: powershell-operational
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'Net.WebClient'
            - 'DownloadString'
            - 'Invoke-Expression'
            - '-EncodedCommand'
            - 'FromBase64String'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
Strategic Recommendations & Defensive Hardening
To protect public sector infrastructure and enterprise environments from living-off-the-land techniques, security programs must move beyond reactive alerting to layered prevention and policy governance.

What to Implement (Solutions)
Enforce Constrained Language Mode (CLM): Configure PowerShell via AppLocker or Device Guard to operate strictly in Constrained Language Mode for standard endpoints. This restricts dynamic script block execution and neutralizes unauthorized .NET methods such as System.Net.WebClient or API reflection calls.

Centralize Script Block Telemetry (SIEM Forwarding): Ingest Windows Event ID 4104 into a centralized security data lake or SIEM. Correlate rapid bursts of 4104 events with external network requests and child process spawning under powershell.exe to catch multi-stage intrusions early.

Map Security Controls to Governance Frameworks: Align monitoring controls with NIST SP 800-53 (specifically AU-2 Audit Events and SI-4 Information System Monitoring) and CIS Critical Security Controls (Control 8: Audit Log Management) to maintain audit-ready regulatory compliance across government networks.

Mandate Digital Signatures for Admin Workflows: Deploy an execution policy that only permits cryptographically verified, internally signed scripts to run (AllSigned), preventing users from executing unsanctioned scripts pulled from internet repositories.

What to Avoid (Pitfalls to Prevent)
Do Not Rely Solely on Command Line Logging: Security Event ID 4688 or basic Sysmon Event 1 only sees raw inputs. If an adversary passes a base64 encoded string or executes entirely within an interactive console, command line auditing is blinded. Script Block Logging (Event ID 4104) is required to see decoded runtime code.

Do Not Treat Execution Policies as Security Boundaries: Setting Set-ExecutionPolicy Restricted is an operational safety net to stop accidental clicks, not an adversarial boundary. Attackers routinely bypass execution policies using arguments like -ExecutionPolicy Bypass or inline web cradles without triggering alerts.

Avoid Flat, Unmonitored PowerShell Permissions: Never grant domain-wide local administrator rights that permit arbitrary remote PowerShell sessions (WinRM / Enter-PSSession) without baseline tracking, credential hygiene, and just-in-time administrative access controls.
