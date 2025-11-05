# Microsoft Sentinel Hybrid-Cloud SOC Lab

A hands-on detection engineering and automation portfolio built in a hybrid Azure environment.

This project simulates a real-world enterprise SOC. It includes a hybrid-cloud data pipeline, 10 custom analytic rules mapped to the MITRE ATT&CK framework, and a SOAR playbook for automated incident notification.

---

## 1. Lab Architecture

This lab uses a hybrid-cloud model with endpoints in both Azure and on-premise. All logs are ingested into a central Log Analytics Workspace and monitored by Microsoft Sentinel.

![Lab Architecture](Lab-Architecture.md/SOC-Homelab-Architecture)

* **SIEM/SOAR:** Microsoft Sentinel & Azure Logic Apps.
* **Endpoints (Hybrid-Cloud):**
    * **Cloud (Victim):** Windows VM (w/ Sysmon) & Ubuntu VM (w/ auditd).
    * **On-Premise (Victim):** Ubuntu VM (w/ Azure Arc).
* **Data Pipeline:** Azure Monitor Agent (AMA) and Data Collection Rules (DCRs) sending all logs to a central Log Analytics Workspace.

---

## 2. Detection Engineering: 10 Custom Analytic Rules

The core of this project is a portfolio of 10 custom-built KQL analytic rules, developed by simulating attacks and hunting for the resulting telemetry.

### 🖥️ Windows Detections (7 Rules)

<details>
<summary><b>1. RDP Brute Force (T1110.001)</b></summary>

* **Description:** Detects a high volume of failed RDP login attempts (Event ID 4625) from a single IP address in a short time window.
* **KQL:**
    ```kql
    Event
    | where EventID == 4625
    | parse EventData with * 'IpAddress">' IpAddress "<" *
    | where isnotempty(IpAddress) and IpAddress != "-"
    | summarize count() by IpAddress, bin(TimeGenerated, 5m)
    | where count_ > 5
    ```
</details>

<details>
<summary><b>2. Encoded PowerShell (T1059.001)</b></summary>

* **Description:** Detects the execution of PowerShell with encoded command flags (`-e`, `-en`, etc.), a common technique to obfuscate malicious scripts.
* **KQL:**
    ```kql
    Event
    | where EventID == 4688
    | parse EventData with * 'NewProcessName">' Process "<" * 'CommandLine">' CommandLine "<" * 'ParentProcessName">' ParentProcessName "<" *
    | where Process endswith "\\powershell.exe" 
        and (
            CommandLine contains " -e " 
            or CommandLine contains " -en " 
            or CommandLine contains " -enc " 
            or CommandLine contains " -encodedcommand "
            )
    | project TimeGenerated, CommandLine, Process, ParentProcessName
    ```
</details>

<details>
<summary><b>3. Suspicious PowerShell Script Block (T1059.001)</b></summary>

* **Description:** A layered detection that hunts for high-confidence malicious keywords (e.g., `IEX`, `DownloadString`, `Invoke-Mimikatz`) inside PowerShell Script Block logs (Event ID 4104). This catches non-encoded payloads that 4688 might miss.
* **KQL:**
    ```kql
    Event
    | where EventID == 4104
    | parse EventData with * '<Data Name="ScriptBlockText">' ScriptBlockText '</Data>' *
    | where isnotempty(ScriptBlockText)
    | where 
        (
            ScriptBlockText contains "IEX" 
            or ScriptBlockText contains "Invoke-Expression"
            or ScriptBlockText contains "DownloadString"
            or ScriptBlockText contains "FromBase64String"
            or ScriptBlockText contains "Get-NetUser"
            or ScriptBlockText contains "Invoke-Mimikatz"
            or ScriptBlockText contains "System.Net.Sockets.TCPClient"
        )
    | project 
        TimeGenerated, 
        Computer, 
        UserName, 
        RenderedDescription, 
        ScriptBlockText
    | extend 
        HostName = Computer, 
        AccountName = UserName
    ```
</details>

<details>
<summary><b>4. LSASS Credential Dumping (T1003.001)</b></summary>

* **Description:** Detects a non-standard process accessing LSASS memory with high privileges. This is a strong indicator of credential dumping via tools like Mimikatz or `procdump.exe`. (Requires Sysmon Event ID 10).
* **KQL:**
    ```kql
    Event
    | where Source == "Microsoft-Windows-Sysmon" and EventID == 10
    | parse EventData with 
        * 'TargetImage">' TargetImage '</Data>' 
        * 'GrantedAccess">' GrantedAccess '</Data>' 
        * 'SourceImage">' SourceImage '</Data>' *
    | where TargetImage endswith "\\lsass.exe"
    | where not (SourceImage in (
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\System32\\taskmgr.exe",
        "C:\\Windows\\System32\\services.exe",
        "C:\\Windows\\System32\\wininit.exe",
        "C:\\Windows\\System32\\lsm.exe"
        ))
    | where GrantedAccess in (
        "0x1010", "0x1410", "0x1F1FFF", "0x1038", 
        "0x1438", "0x143a", "0x1f0fff", "0x1f2fff", "0x1f3fff"
        )
    | project 
        TimeGenerated, 
        Computer, 
        UserName,
        SourceImage,
        TargetImage,
        GrantedAccess
    | extend 
        HostName = Computer, 
        AccountName = UserName
    ```
</details>

<details>
<summary><b>5. Persistence via Registry Run Key (T1547.001)</b></summary>

* **Description:** Detects modification of a common persistence registry key (Run, RunOnce) by a suspicious command-line tool (`powershell.exe`, `reg.exe`, `cmd.exe`), which is anomalous behavior for legitimate installers.
* **KQL:**
    ```kql
    Event
    | where Source == "Microsoft-Windows-Sysmon" and EventID == 13
    | parse EventData with * 'TargetObject">' TargetObject '</Data>' * 'Image">' Image '</Data>' *
    | where TargetObject contains "CurrentVersion\\Run" 
         or TargetObject contains "CurrentVersion\\RunOnce"
    | where Image endswith "\\reg.exe"
         or Image endswith "\\powershell.exe"
         or Image endswith "\\cmd.exe"
         or Image endswith "\\wscript.exe"
         or Image endswith "\\cscript.exe"
    | project 
        TimeGenerated, 
        Computer, 
        UserName, 
        Image, 
        TargetObject
    | extend 
        HostName = Computer, 
        AccountName = UserName
    ```
</details>

<details>
<summary><b>6. Masquerading System Process (T1036.003)</b></summary>

* **Description:** Detects a common system process (e.g., `svchost.exe`, `lsass.exe`) running from a non-standard, illegitimate directory (e.g., `Desktop`), indicating a masquerading attack.
* **KQL:**
    ```kql
    Event
    | where Source == "Microsoft-Windows-Sysmon" and EventID == 1
    | parse EventData with * 'Image">' Image '</Data>' * 'CommandLine">' CommandLine '</Data>' *
    | where 
        (
            Image has "svchost.exe" or
            Image has "lsass.exe" or
            Image has "wininit.exe" or
            Image has "lsm.exe"
        )
    | where not (Image startswith "C:\\Windows\\System32\\")
    | project 
        TimeGenerated, 
        Computer, 
        UserName, 
        Image,
        CommandLine
    | extend 
        HostName = Computer, 
        AccountName = UserName
    ```
</details>

<details>
<summary><b>7. Persistence via Scheduled Task (T1546.011)</b></summary>

* **Description:** Detects the creation of a scheduled task using suspicious, high-privilege, or frequent triggers (e.g., ONLOGON, ONSTART, SYSTEM), indicating a common persistence technique.
* **KQL:**
    ```kql
    Event
    | where Source == "Microsoft-Windows-Sysmon" and EventID == 1
    | parse EventData with * 'Image">' Image '</Data>' * 'CommandLine">' CommandLine '</Data>' *
    | where Image endswith "\\schtasks.exe"
    | where CommandLine has "/Create" or CommandLine has "/Change"
    | where CommandLine has "/SC ONLOGON"
        or CommandLine has "/SC ONSTART"
        or CommandLine has "/SC MINUTE"
        or CommandLine has "/SC HOURLY"
    | where CommandLine has "/RU SYSTEM" or CommandLine has "SYSTEM"
    | project 
        TimeGenerated, 
        Computer, 
        UserName, 
        Image,
        CommandLine
    | extend 
        HostName = Computer, 
        AccountName = UserName
    ```
</details>

### 🐧 Linux Detections (3 Rules)

<details>
<summary><b>8. Linux Ingress Tool Transfer (T1105)</b></summary>

* **Description:** Detects `wget` or `curl` downloading a potential payload (.sh, .py, .elf) into a world-writable directory (`/tmp`, `/var/tmp`, `/dev/shm`).
* **KQL:**
    ```kql
    Syslog
    | where ProcessName in ("wget", "curl") or SyslogMessage has "wget " or SyslogMessage has "curl "
    | where SyslogMessage has "/tmp/"
        or SyslogMessage has "/var/tmp/"
        or SyslogMessage has "/dev/shm/"
    | where SyslogMessage has ".sh"
        or SyslogMessage has ".py"
        or SyslogMessage has ".elf"
        or SyslogMessage has ".bin"
    | project 
        TimeGenerated, 
        HostName, 
        ProcessName, 
        SyslogMessage
    | extend 
        HostName = HostName, 
        AccountName = UserName
    ```
</details>

<details>
<summary><b>9. Linux SSH Persistence (T1098.004)</b></summary>

* **Description:** Detects a process (`tee`, `echo`, `cat`) appending data to a user's `.ssh/authorized_keys` file, a common persistence technique.
* **KQL:**
    ```kql
    Syslog
    | where SyslogMessage has "type=EXECVE"
    | where SyslogMessage has "authorized_keys"
    | extend 
        A0 = extract('a0="([^"]*)"', 1, SyslogMessage),
        A1 = extract('a1="([^"]*)"', 1, SyslogMessage),
        A2 = extract('a2="([^"]*)"', 1, SyslogMessage)
    | where 
        (
            A0 endswith "tee" or
            A0 endswith "echo" or
            A0 endswith "cat"
        ) and 
        (
            A1 has "authorized_keys" or 
            A2 has "authorized_keys" or
            A1 has ".ssh" or
            A2 has ".ssh"
        )
    | project 
        TimeGenerated, 
        HostName, 
        SyslogMessage,
        A0, // Process
        A1, // Arg 1
        A2  // Arg 2
    | extend 
        HostName = HostName, 
        AccountName = UserName
    ```
</details>

<details>
<summary><b>10. Linux Script Execution from Suspicious Location (T1059.004)</b></summary>

* **Description:** Detects a shell (bash, python, etc.) executing a script from a world-writable directory (`/tmp`, `/var/tmp`, `/dev/shm`), a classic attacker pattern.
* **KQL:**
    ```kql
    Syslog
    | where SyslogMessage has "type=EXECVE"
    | where SyslogMessage has "/tmp/"
        or SyslogMessage has "/var/tmp/"
        or SyslogMessage has "/dev/shm/"
    | parse SyslogMessage with * 'a0="' A0 '"' * 'a1="' A1 '"' *
    | where 
        (
            A0 endswith "bash" or
            A0 endswith "sh" or
            A0 endswith "zsh" or
            A0 endswith "perl" or
            A0 endswith "python"
        ) and (
            A1 startswith "/tmp/" or
            A1 startswith "/var/tmp/" or
            A1 startswith "/dev/shm/"
        )
    | project 
        TimeGenerated, 
        HostName, 
        SyslogMessage,
        A0, // Process (e.g., /bin/bash)
        A1  // Argument (e.g., /tmp/payload.sh)
    | extend 
        HostName = HostName, 
        AccountName = UserName
    ```
</details>

---

## 3. SOAR Automation: Incident-to-Teams Alert

A SOAR playbook was configured using Azure Logic Apps to automate the first step of incident triage.

* **Trigger:** On new "Incident" creation in Microsoft Sentinel.
* **Action:** Parses the incident data (Severity, Title, Description).
* **Response:** Posts a formatted Adaptive Card to a Microsoft Teams channel for immediate SOC analyst review.

#### Workflow:
![Logic App Workflow](Screenshot 2025-11-06 012209.png)

#### Final Alert:
![Teams Alert](Screenshot 2025-11-06 012401.png)

<details>
<summary><b>Adaptive Card JSON Payload</b></summary>

```json
{
  "type": "message",
  "attachments": [
    {
      "contentType": "application/vnd.microsoft.card.adaptive",
      "content": {
        "type": "AdaptiveCard",
        "version": "1.2",
        "body": [
          {
            "type": "TextBlock",
            "text": "New Sentinel Incident Created",
            "weight": "bolder",
            "size": "medium"
          },
          {
            "type": "TextBlock",
            "text": "Title: @{triggerBody()?['properties']?['title']}",
            "wrap": true
          },
          {
            "type": "TextBlock",
            "text": "Severity: @{triggerBody()?['properties']?['severity']}",
            "wrap": true
          },
          {
            "type":* "TextBlock",
            "text": "Description: @{triggerBody()?['properties']?['description']}",
            "wrap": true
          }
        ],
        "$schema": "[http://adaptivecards.io/schemas/adaptive-card.json](http://adaptivecards.io/schemas/adaptive-card.json)"
      }
    }
  ]
}
