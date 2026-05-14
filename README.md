<p align="Center"> <b> SnowTrace </b></p>

<p align="center">
  <img src="snow-trace.png" alt="Agent P - Recon Scout" width="480"/>
</p>

<p align="Center"> <b>Cyber triage toolkit for Windows and Linux incident response. </b></p>

<p align="center">
  <b>Version 1.0</b> · Created by <b>Agent P</b><br/>
SnowTrace collects forensic artifacts from a potentially compromised system and runs them through a browser-based analysis engine that flags indicators of compromise (IOCs), ranked by severity, with remediation playbooks for each finding.
</p>

---

## How It Works

```
Run script on target  →  Upload report to dashboard  →  Review findings  →  Follow remediation steps
```

1. **Download** the collection script for your platform from the dashboard
2. **Run** it on the target system (Administrator / root required for full results)
3. **Upload** the generated `.txt` report to the Analyze tab
4. **Act** on findings — the dashboard links each finding to a remediation playbook

All analysis runs entirely in the browser. No data leaves your machine.

---

## Features

| | |
|---|---|
| **25+ forensic check categories** | Processes, network, persistence, users, logs, and more |
| **100+ IOC detection rules** | Pattern-matched against collected artifacts |
| **4 severity levels** | CRITICAL · HIGH · MEDIUM · LOW · INFO |
| **Cross-platform** | Windows (PowerShell) and Linux (Bash) |
| **Zero dependencies** | No installs, no internet, no backend |
| **Remediation playbooks** | Step-by-step response guides per finding type |

---

## Requirements

| Platform | Requirements |
|---|---|
| **Windows** | PowerShell 5.0+, Administrator privileges |
| **Linux** | Bash, sudo / root access |
| **Dashboard** | Any modern browser (Chrome, Firefox, Edge) |

---

## Quick Start

### Windows

```powershell
# Run as Administrator
powershell -ExecutionPolicy Bypass -File snowtrace_windows.ps1
```

Output: `snowtrace_windows_HOSTNAME_YYYYMMDD_HHmmss.txt`

### Linux

```bash
# Run as root or with sudo
sudo bash snowtrace_linux.sh
```

Output: `snowtrace_linux_HOSTNAME_YYYYMMDD_HHmmss.txt`

### Analyze

Open `index.html` in a browser → go to the **Analyze** tab → drag and drop the report file.

---

## What It Detects

### Windows
- Processes running from `%TEMP%`, `AppData`, or other unusual paths
- Unsigned or tampered binaries
- Network connections to known attacker ports (4444, 31337, 6667, etc.)
- PowerShell abuse — `IEX`, `Invoke-Expression`, `-EncodedCommand`, `certutil`
- Base64-encoded payloads in command history
- Scheduled tasks using `mshta`, `regsvr32`, or `rundll32`
- WMI Event Subscription persistence
- Image File Execution Options (IFEO) debugger hijacking
- Failed login spikes and brute force indicators
- New or unexpected local user accounts
- Disabled Windows Defender
- Security / System event log cleared (Event IDs 1102 / 104)
- LSASS RunAsPPL disabled (credential dumping risk)
- Non-standard Boot Execute entries
- Malicious LSA security/authentication packages (SSP injection, mimilib.dll)
- Named pipes matching known C2 frameworks (Cobalt Strike, Metasploit, Empire, Havoc, Sliver)
- Volume Shadow Copies deleted or missing (ransomware indicator)
- RDP client connection history (lateral movement detection)
- Prefetch files executed from suspicious directories (post-deletion evidence)
- Browser downloads of executable/script file types (`.exe`, `.ps1`, `.bat`, `.vbs`, `.hta`, `.js`)
- Active RDP sessions on port 3389

### Linux
- Processes spawned from `/tmp`, `/dev/shm`, `/var/tmp`
- Cron jobs with reverse-shell or download patterns (`wget`, `curl`, `nc`, `bash -i`)
- Suspicious SSH authorized keys
- Shell history with privilege escalation or lateral movement commands
- Root SSH login permitted (`PermitRootLogin yes`)
- SUID/SGID files outside standard system paths
- World-writable files in system directories
- Custom `/etc/hosts` entries
- Unexpected kernel modules (rootkit indicators)
- `/etc/ld.so.preload` existence (classic rootkit persistence)
- Files with dangerous capabilities (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`)
- Non-standard PAM modules (backdoor detection)
- Shell profile tampering (`.bashrc`, `.profile`, `/etc/profile` with reverse-shell or LD_PRELOAD)
- Immutable files via `chattr +i` (attacker-protected backdoors)
- Shared libraries mapped from `/tmp` or `/dev/shm` in live processes (process injection)
- Processes with deleted memory-mapped files (fileless malware in memory)
- Crypto miner indicators (`xmrig`, `minerd`, `kswapd0`, mining pool port connections)
- System package file tampering (`rpm -Va` / `debsums` / `dpkg -V`)

---

## What Gets Collected

### Windows (22 categories)
System info · Running processes · Network connections · DNS cache · Scheduled tasks · Services · Persistence (registry run keys, WMI, IFEO, AppInit_DLLs, LSA packages, LSASS RunAsPPL, boot execute, network providers) · User accounts · Security events (incl. log clearing) · PowerShell config & history · Recently modified files · Installed software · Firewall rules · Windows Defender status · Suspicious indicators · Prefetch files · Shadow copies · RDP artifacts · USB device history · Named pipes · Persistence extended · Browser downloads & extensions

### Linux (27 categories)
System info · Running processes · Network connections · DNS & hosts · Cron jobs · Startup services · User accounts & sudoers · SSH config & authorized keys · Recently modified files · SUID/SGID files · World-writable files · Auth logs · Shell history · Kernel modules · Installed packages · Firewall rules · Suspicious indicators · ld.so.preload · File capabilities · PAM configuration · Shell profiles · Immutable files · Process memory maps · XDG autostart · Container artifacts · Package integrity · Crypto miner indicators

---

## Dashboard Tabs

| Tab | Purpose |
|---|---|
| **Home** | Overview and 4-step workflow |
| **Download** | Get the collection scripts |
| **Analyze** | Upload and analyze a report |
| **How-To** | Step-by-step usage guide per platform |
| **Remediation** | Interactive playbooks for each finding type |
| **About** | Stack, credits, legal disclaimer |

---

## Tech Stack

**Collection scripts** — PowerShell 5.0+ (Windows), POSIX Bash (Linux)

**Dashboard** — HTML5 (`index.html`) · CSS3 (`styles.css`) · Vanilla JavaScript (`app.js`) · No frameworks, no dependencies · FileReader API for local file parsing · Blob URL for script downloads · HTML entity escaping throughout (XSS-safe)

---

## Legal Disclaimer

SnowTrace is intended for use on systems you own or are explicitly authorized to investigate. Unauthorized use against systems you do not have permission to access may violate computer crime laws. The authors are not responsible for misuse.

---

## Credits

Built by **Agent P**  
Version 1.0
