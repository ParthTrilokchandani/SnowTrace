#Requires -Version 3.0
<#
.SYNOPSIS
    SnowTrace - Windows Compromise Investigation Script
    By Agent P | Version 1.0

.DESCRIPTION
    Collects forensic artifacts for incident response and compromise assessment.
    For complete results, run as Administrator in an elevated PowerShell session.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File snowtrace_windows.ps1
#>

$ErrorActionPreference = "SilentlyContinue"
$timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$hostname   = $env:COMPUTERNAME
$username   = $env:USERNAME
$outputFile = "snowtrace_windows_${hostname}_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ███████╗███╗   ██╗ ██████╗ ██╗    ██╗████████╗██████╗  █████╗  ██████╗███████╗" -ForegroundColor Cyan
Write-Host "  ██╔════╝████╗  ██║██╔═══██╗██║    ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝" -ForegroundColor Cyan
Write-Host "  ███████╗██╔██╗ ██║██║   ██║██║ █╗ ██║   ██║   ██████╔╝███████║██║     █████╗  " -ForegroundColor Cyan
Write-Host "  ╚════██║██║╚██╗██║██║   ██║██║███╗██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  " -ForegroundColor Cyan
Write-Host "  ███████║██║ ╚████║╚██████╔╝╚███╔███╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗" -ForegroundColor Cyan
Write-Host "  ╚══════╝╚═╝  ╚═══╝ ╚═════╝  ╚══╝╚══╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝" -ForegroundColor Cyan
Write-Host "  Windows Compromise Investigation | By Agent P" -ForegroundColor DarkCyan
Write-Host ""

function Write-Log  { param($m) Write-Host "  [>] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "  [X] $m" -ForegroundColor Red }

function Write-Section {
    param([string]$Name, [string]$Content)
    $section = "`r`n[${Name}]`r`n${Content}`r`n[/${Name}]"
    Add-Content -Path $outputFile -Value $section -Encoding UTF8
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Warn "Not running as Administrator - some checks will be limited" }

# ── Report Header ─────────────────────────────────────────────────────────────
$os = Get-WmiObject -Class Win32_OperatingSystem
$header = @"
=== SNOWTRACE INVESTIGATION REPORT ===
Tool: SnowTrace by Agent P
Version: 1.0
Platform: Windows
Date: $timestamp
Hostname: $hostname
User: $username
IsAdmin: $isAdmin
OS: $($os.Caption)
OSVersion: $($os.Version)
Architecture: $($os.OSArchitecture)
LastBoot: $($os.ConvertToDateTime($os.LastBootUpTime))
PSVersion: $($PSVersionTable.PSVersion)
"@
Set-Content -Path $outputFile -Value $header -Encoding UTF8
Write-Log "Output file: $outputFile"
Write-Host ""

# ── 1. SYSTEM INFORMATION ─────────────────────────────────────────────────────
Write-Log "Collecting system information..."
$sysInfo = @"
--- Computer Info ---
$((Get-WmiObject Win32_ComputerSystem | Select-Object Name, Domain, Manufacturer, Model, TotalPhysicalMemory | Format-List | Out-String).Trim())

--- OS Details ---
$((Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime | Format-List | Out-String).Trim())

--- Timezone ---
$((Get-TimeZone | Format-List | Out-String).Trim())

--- Environment Variables ---
$((Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize | Out-String).Trim())
"@
Write-Section "SYSTEM_INFO" $sysInfo

# ── 2. RUNNING PROCESSES ──────────────────────────────────────────────────────
Write-Log "Collecting running processes..."
$processes = Get-WmiObject Win32_Process | ForEach-Object {
    $proc = $_
    $psProc = Get-Process -Id $proc.ProcessId -EA SilentlyContinue
    $sig = $null
    if ($proc.ExecutablePath) {
        try { $sig = (Get-AuthenticodeSignature $proc.ExecutablePath -EA SilentlyContinue).Status } catch {}
    }
    [PSCustomObject]@{
        PID       = $proc.ProcessId
        PPID      = $proc.ParentProcessId
        Name      = $proc.Name
        Path      = $proc.ExecutablePath
        CmdLine   = if ($proc.CommandLine) { $proc.CommandLine.Substring(0, [Math]::Min(120, $proc.CommandLine.Length)) } else { "" }
        User      = $proc.GetOwner().User
        Signature = $sig
        CPU_s     = if ($psProc) { [math]::Round($psProc.CPU, 2) } else { 0 }
        Mem_MB    = [math]::Round($proc.WorkingSetSize / 1MB, 2)
        StartTime = $proc.CreationDate
    }
} | Sort-Object CPU_s -Descending | Format-Table -AutoSize -Wrap | Out-String
Write-Section "RUNNING_PROCESSES" $processes

# ── 3. NETWORK CONNECTIONS ────────────────────────────────────────────────────
Write-Log "Collecting network connections..."
$netData = @"
--- Active TCP Connections ---
$((Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
    @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} |
    Sort-Object State, LocalPort | Format-Table -AutoSize | Out-String).Trim())

--- UDP Endpoints ---
$((Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess,
    @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} |
    Format-Table -AutoSize | Out-String).Trim())

--- IP Configuration ---
$((Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressFamily | Format-Table -AutoSize | Out-String).Trim())

--- DNS Servers ---
$((Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize | Out-String).Trim())

--- HOSTS File ---
$(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -EA SilentlyContinue | Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" } | Out-String)
"@
Write-Section "NETWORK_CONNECTIONS" $netData

# ── 4. DNS CACHE ──────────────────────────────────────────────────────────────
Write-Log "Collecting DNS cache..."
$dnsCache = (Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, Status, TimeToLive | Format-Table -AutoSize | Out-String).Trim()
Write-Section "DNS_CACHE" $dnsCache

# ── 5. SCHEDULED TASKS ────────────────────────────────────────────────────────
Write-Log "Collecting scheduled tasks..."
$tasks = Get-ScheduledTask | ForEach-Object {
    $t = $_
    $info = $t | Get-ScheduledTaskInfo -EA SilentlyContinue
    $actions = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join " | "
    [PSCustomObject]@{
        Name       = $t.TaskName
        Path       = $t.TaskPath
        State      = $t.State
        Author     = $t.Author
        LastRun    = if ($info) { $info.LastRunTime } else { "" }
        NextRun    = if ($info) { $info.NextRunTime } else { "" }
        Actions    = $actions
    }
} | Format-Table -AutoSize -Wrap | Out-String
Write-Section "SCHEDULED_TASKS" $tasks

# ── 6. WINDOWS SERVICES ───────────────────────────────────────────────────────
Write-Log "Collecting services..."
$services = (Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
    Sort-Object State, Name | Format-Table -AutoSize -Wrap | Out-String).Trim()
Write-Section "SERVICES" $services

# ── 7. PERSISTENCE MECHANISMS ─────────────────────────────────────────────────
Write-Log "Collecting persistence mechanisms..."
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
$regRunOutput = foreach ($key in $runKeys) {
    "  Key: $key"
    if (Test-Path $key) {
        $props = (Get-ItemProperty $key).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
        if ($props) { $props | ForEach-Object { "    $($_.Name) = $($_.Value)" } }
        else { "    (empty)" }
    } else { "    (key not found)" }
    ""
}

$wmiFilters    = Get-WMIObject -Namespace root\subscription -Class __EventFilter -EA SilentlyContinue
$wmiConsumers  = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -EA SilentlyContinue
$ifeoPaths     = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -EA SilentlyContinue | ForEach-Object {
    $d = (Get-ItemProperty $_.PSPath -Name Debugger -EA SilentlyContinue).Debugger
    if ($d) { "  $($_.PSChildName) -> Debugger: $d" }
}

$persistData = @"
--- Registry Run Keys ---
$($regRunOutput -join "`r`n")

--- Startup Folder (All Users) ---
$((Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -EA SilentlyContinue | Select-Object Name, FullName, LastWriteTime | Format-Table | Out-String).Trim())

--- Startup Folder (Current User) ---
$((Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -EA SilentlyContinue | Select-Object Name, FullName, LastWriteTime | Format-Table | Out-String).Trim())

--- Winlogon Values ---
$((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -EA SilentlyContinue | Select-Object Shell, Userinit, UserInitMprLogonScript | Format-List | Out-String).Trim())

--- AppInit_DLLs ---
$((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -EA SilentlyContinue).AppInit_DLLs)

--- Image File Execution Options (Debuggers) ---
$(if ($ifeoPaths) { $ifeoPaths -join "`r`n" } else { "  (none)" })

--- WMI Event Filters ---
$(if ($wmiFilters) { $wmiFilters | Select-Object Name, Query | Format-Table | Out-String } else { "  (none)" })

--- WMI Event Consumers ---
$(if ($wmiConsumers) { $wmiConsumers | Select-Object Name, ScriptText, CommandLineTemplate | Format-Table | Out-String } else { "  (none)" })
"@
Write-Section "PERSISTENCE" $persistData

# ── 8. USER ACCOUNTS ──────────────────────────────────────────────────────────
Write-Log "Collecting user account information..."
$userData = @"
--- Local Users ---
$((Get-LocalUser | Select-Object Name, Enabled, SID, LastLogon, PasswordLastSet, PasswordRequired | Format-Table -AutoSize | Out-String).Trim())

--- Local Groups ---
$((Get-LocalGroup | Select-Object Name, SID, Description | Format-Table -AutoSize | Out-String).Trim())

--- Administrators Group Members ---
$((Get-LocalGroupMember -Group "Administrators" -EA SilentlyContinue | Select-Object Name, SID, PrincipalSource | Format-Table -AutoSize | Out-String).Trim())

--- Remote Desktop Users ---
$((Get-LocalGroupMember -Group "Remote Desktop Users" -EA SilentlyContinue | Select-Object Name, SID | Format-Table -AutoSize | Out-String).Trim())
"@
Write-Section "USER_ACCOUNTS" $userData

# ── 9. SECURITY EVENTS ────────────────────────────────────────────────────────
Write-Log "Collecting security events (last 7 days)..."
try {
    $loginEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = @(4624, 4625, 4648, 4720, 4726, 4728, 4732, 4756, 4672)
        StartTime = (Get-Date).AddDays(-7)
    } -MaxEvents 200 -EA Stop | Select-Object TimeCreated, Id,
        @{N='EventType';E={switch($_.Id){
            4624{'[OK] Successful Login'}
            4625{'[!!] FAILED Login'}
            4648{'[>>] Explicit Credentials Used'}
            4720{'[NEW] User Account Created'}
            4726{'[DEL] User Account Deleted'}
            4728{'[GRP] User Added to Global Group'}
            4732{'[ADM] User Added to Administrators'}
            4756{'[GRP] User Added to Universal Group'}
            4672{'[PRIV] Special Privileges Assigned'}
        }}},
        @{N='Details';E={
            if ($_.Message) { $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)) }
        }} | Format-Table -AutoSize -Wrap | Out-String
    Write-Section "SECURITY_EVENTS" $loginEvents
} catch {
    Write-Section "SECURITY_EVENTS" "Unable to read security events - requires Administrator privileges.`r`nError: $_"
}

# ── 10. POWERSHELL HISTORY & CONFIG ──────────────────────────────────────────
Write-Log "Collecting PowerShell configuration and history..."
$histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
$psHistory = if (Test-Path $histPath) {
    Get-Content $histPath -Tail 300 | Out-String
} else { "(no history file found)" }

$psData = @"
--- Execution Policy ---
$((Get-ExecutionPolicy -List | Format-Table | Out-String).Trim())

--- Module Logging ---
$((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -EA SilentlyContinue | Format-List | Out-String).Trim())

--- Script Block Logging ---
$((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -EA SilentlyContinue | Format-List | Out-String).Trim())

--- PowerShell History (last 300 lines) ---
$psHistory
"@
Write-Section "POWERSHELL_INFO" $psData

# ── 11. RECENTLY MODIFIED FILES ───────────────────────────────────────────────
Write-Log "Collecting recently modified files (last 7 days)..."
$scanPaths = @(
    $env:TEMP,
    "$env:SystemRoot\Temp",
    "$env:USERPROFILE\Downloads",
    $env:APPDATA,
    "$env:LOCALAPPDATA\Temp",
    "$env:USERPROFILE\Documents"
)
$recentFiles = foreach ($p in $scanPaths) {
    if (Test-Path $p) {
        Get-ChildItem -Path $p -Recurse -File -EA SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
            Select-Object FullName, LastWriteTime, @{N='Size_KB';E={[math]::Round($_.Length/1KB,1)}} |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 25
    }
}
Write-Section "RECENTLY_MODIFIED_FILES" ($recentFiles | Format-Table -AutoSize | Out-String)

# ── 12. INSTALLED SOFTWARE ────────────────────────────────────────────────────
Write-Log "Collecting installed software..."
$software = @(
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue
    Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue
    Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue
) | Where-Object { $_.DisplayName } |
    Select-Object DisplayName, Publisher, DisplayVersion, InstallDate |
    Sort-Object InstallDate -Descending |
    Format-Table -AutoSize | Out-String
Write-Section "INSTALLED_SOFTWARE" $software

# ── 13. FIREWALL STATUS ───────────────────────────────────────────────────────
Write-Log "Collecting firewall information..."
$firewallData = @"
--- Firewall Profiles ---
$((Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table | Out-String).Trim())

--- Inbound Allow Rules ---
$((Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' } |
    Select-Object DisplayName, LocalPort, RemoteAddress, Profile, Enabled | Format-Table -AutoSize | Out-String).Trim())
"@
Write-Section "FIREWALL_INFO" $firewallData

# ── 14. WINDOWS DEFENDER ──────────────────────────────────────────────────────
Write-Log "Collecting Windows Defender status..."
$defStatus  = Get-MpComputerStatus -EA SilentlyContinue
$defThreats = Get-MpThreatDetection -EA SilentlyContinue
$defData = @"
--- Defender Status ---
$(($defStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled,
    IoavProtectionEnabled, NISEnabled, OnAccessProtectionEnabled,
    AntivirusSignatureLastUpdated, QuickScanStartTime, FullScanStartTime | Format-List | Out-String).Trim())

--- Recent Threat Detections ---
$(if ($defThreats) { $defThreats | Select-Object -First 20 | Format-Table | Out-String } else { "No threats recorded" })
"@
Write-Section "DEFENDER_STATUS" $defData

# ── 15. LOADED DRIVERS ────────────────────────────────────────────────────────
Write-Log "Collecting loaded drivers..."
$drivers = (Get-WmiObject Win32_SystemDriver |
    Select-Object Name, DisplayName, State, PathName, ServiceType |
    Sort-Object State | Format-Table -AutoSize -Wrap | Out-String).Trim()
Write-Section "LOADED_DRIVERS" $drivers

# ── 16. SUSPICIOUS INDICATORS SUMMARY ────────────────────────────────────────
Write-Log "Running suspicious indicator checks..."
$suspProcs = Get-WmiObject Win32_Process | Where-Object {
    $_.ExecutablePath -match "\\temp\\|\\tmp\\|appdata\\local\\temp|\\windows\\temp|\\programdata\\" -or
    ($_.ExecutablePath -eq $null -and $_.Name -notin @('System','Idle','Registry','smss.exe','csrss.exe','wininit.exe','services.exe','lsass.exe','winlogon.exe'))
}
$suspConnections = Get-NetTCPConnection | Where-Object {
    $_.RemotePort -in @(4444,4445,1337,31337,8888,9090,9999,6667,6697,1234,5555,7777) -and
    $_.State -eq 'Established'
}
$suspData = @"
--- Processes from Suspicious Locations ---
$(if ($suspProcs) { $suspProcs | Select-Object ProcessId, Name, ExecutablePath, CommandLine | Format-Table -AutoSize | Out-String } else { "(none detected)" })

--- Connections to High-Risk Ports ---
$(if ($suspConnections) { $suspConnections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Format-Table | Out-String } else { "(none detected)" })
"@
Write-Section "SUSPICIOUS_INDICATORS" $suspData

# ── Finalize ──────────────────────────────────────────────────────────────────
$endTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content -Path $outputFile -Value "`r`n=== INVESTIGATION COMPLETE ===" -Encoding UTF8
Add-Content -Path $outputFile -Value "EndTime: $endTime" -Encoding UTF8

Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │  SnowTrace Investigation COMPLETE                           │" -ForegroundColor Green
Write-Host "  │  Report: $outputFile" -ForegroundColor Green
Write-Host "  │  Upload this file to the SnowTrace Dashboard for analysis   │" -ForegroundColor Green
Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
