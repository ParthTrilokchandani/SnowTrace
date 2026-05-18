#Requires -Version 3.0
<#
.SYNOPSIS
    SnowTrace - Windows Compromise Investigation Script
    By Agent P | Version 1.0
.DESCRIPTION
    Collects forensic artifacts for incident response and compromise assessment.
    Run as Administrator for complete results.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File snowtrace_windows.ps1
#>

$ErrorActionPreference = "SilentlyContinue"
$timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$hostname   = $env:COMPUTERNAME
$username   = $env:USERNAME
$outputFile = "snowtrace_windows_${hostname}_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

Write-Host "  SnowTrace | Windows Investigation | By Agent P" -ForegroundColor Cyan
Write-Host "  Output: $outputFile" -ForegroundColor Green

function Write-Section {
    param([string]$Name, [string]$Content)
    Add-Content -Path $outputFile -Value "`r`n[${Name}]`r`n${Content}`r`n[/${Name}]" -Encoding UTF8
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$os = Get-WmiObject -Class Win32_OperatingSystem

Set-Content -Path $outputFile -Value @"
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
"@ -Encoding UTF8

Write-Host "  [1/22] System Info..." -ForegroundColor DarkCyan
Write-Section "SYSTEM_INFO" (Get-WmiObject Win32_ComputerSystem | Select-Object Name, Domain, Manufacturer, Model | Format-List | Out-String)

Write-Host "  [2/22] Processes..." -ForegroundColor DarkCyan
$procs = Get-WmiObject Win32_Process | ForEach-Object {
    $sig = if ($_.ExecutablePath) { try { (Get-AuthenticodeSignature $_.ExecutablePath -EA SilentlyContinue).Status } catch {} }
    [PSCustomObject]@{ PID=$_.ProcessId; PPID=$_.ParentProcessId; Name=$_.Name; Path=$_.ExecutablePath; CmdLine=if($_.CommandLine){$_.CommandLine.Substring(0,[Math]::Min(100,$_.CommandLine.Length))}else{""}; User=$_.GetOwner().User; Signature=$sig }
} | Format-Table -AutoSize | Out-String
Write-Section "RUNNING_PROCESSES" $procs

Write-Host "  [3/22] Network..." -ForegroundColor DarkCyan
Write-Section "NETWORK_CONNECTIONS" @"
--- TCP Connections ---
$(Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Sort-Object State | Format-Table -AutoSize | Out-String)
--- UDP Endpoints ---
$(Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,@{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Format-Table -AutoSize | Out-String)
--- DNS Servers ---
$(Get-DnsClientServerAddress | Select-Object InterfaceAlias,ServerAddresses | Format-Table -AutoSize | Out-String)
--- Hosts File ---
$(Get-Content "$env:SystemRootSystem32driversetchosts" | Where-Object {$_ -notmatch "^#" -and $_.Trim() -ne ""})
"@

Write-Host "  [4/22] DNS Cache..." -ForegroundColor DarkCyan
Write-Section "DNS_CACHE" (Get-DnsClientCache | Select-Object Entry,RecordName,RecordType,Status,TimeToLive | Format-Table -AutoSize | Out-String)

Write-Host "  [5/22] Scheduled Tasks..." -ForegroundColor DarkCyan
Write-Section "SCHEDULED_TASKS" (Get-ScheduledTask | ForEach-Object { [PSCustomObject]@{Name=$_.TaskName;Path=$_.TaskPath;State=$_.State;Author=$_.Author;Actions=(($_.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join " | ")} } | Format-Table -AutoSize | Out-String)

Write-Host "  [6/22] Services..." -ForegroundColor DarkCyan
Write-Section "SERVICES" (Get-WmiObject Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | Sort-Object State,Name | Format-Table -AutoSize | Out-String)

Write-Host "  [7/22] Persistence..." -ForegroundColor DarkCyan
$runKeys = @("HKLM:SOFTWAREMicrosoftWindowsCurrentVersionRun","HKLM:SOFTWAREMicrosoftWindowsCurrentVersionRunOnce","HKLM:SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionRun","HKCU:SOFTWAREMicrosoftWindowsCurrentVersionRun","HKCU:SOFTWAREMicrosoftWindowsCurrentVersionRunOnce")
$regOut = foreach ($k in $runKeys) { "Key: $k"; if (Test-Path $k) { (Get-ItemProperty $k).PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object {"  $($_.Name) = $($_.Value)"} } }
$wmiF = Get-WMIObject -Namespace rootsubscription -Class __EventFilter -EA SilentlyContinue
$wmiC = Get-WMIObject -Namespace rootsubscription -Class __EventConsumer -EA SilentlyContinue
$ifeo = Get-ChildItem "HKLM:SOFTWAREMicrosoftWindows NTCurrentVersionImage File Execution Options" -EA SilentlyContinue | ForEach-Object { $d=(Get-ItemProperty $_.PSPath -Name Debugger -EA SilentlyContinue).Debugger; if($d){"  $($_.PSChildName) -> Debugger: $d"} }
Write-Section "PERSISTENCE" @"
--- Registry Run Keys ---
$($regOut -join "`r`n")
--- Winlogon ---
$(Get-ItemProperty "HKLM:SOFTWAREMicrosoftWindows NTCurrentVersionWinlogon" -EA SilentlyContinue | Select-Object Shell,Userinit | Format-List | Out-String)
--- AppInit_DLLs ---
$((Get-ItemProperty "HKLM:SOFTWAREMicrosoftWindows NTCurrentVersionWindows" -Name AppInit_DLLs -EA SilentlyContinue).AppInit_DLLs)
--- Image File Execution Options (Debuggers) ---
$(if ($ifeo) { $ifeo -join "`r`n" } else { "(none)" })
--- WMI Event Filters ---
$(if ($wmiF) { $wmiF | Select-Object Name,Query | Format-Table | Out-String } else { "(none)" })
--- WMI Event Consumers ---
$(if ($wmiC) { $wmiC | Select-Object Name,ScriptText,CommandLineTemplate | Format-Table | Out-String } else { "(none)" })
"@

Write-Host "  [8/22] Users..." -ForegroundColor DarkCyan
Write-Section "USER_ACCOUNTS" @"
--- Local Users ---
$(Get-LocalUser | Select-Object Name,Enabled,SID,LastLogon,PasswordLastSet | Format-Table -AutoSize | Out-String)
--- Administrators ---
$(Get-LocalGroupMember -Group "Administrators" -EA SilentlyContinue | Select-Object Name,SID,PrincipalSource | Format-Table | Out-String)
"@

Write-Host "  [9/22] Security Events..." -ForegroundColor DarkCyan
try {
    $evts = Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4624,4625,4648,4720,4726,4728,4732,4672);StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200 -EA Stop |
        Select-Object TimeCreated,Id,@{N='EventType';E={switch($_.Id){4624{'[OK] Successful Login'}4625{'[!!] FAILED Login'}4648{'[>>] Explicit Credentials'}4720{'[NEW] User Account Created'}4726{'[DEL] User Deleted'}4728{'[GRP] Added to Group'}4732{'[ADM] Added to Admins'}4672{'[PRIV] Special Privileges'}}}} |
        Format-Table -AutoSize | Out-String
    Write-Section "SECURITY_EVENTS" $evts
} catch { Write-Section "SECURITY_EVENTS" "Requires Administrator privileges.`r`nError: $_" }

Write-Host "  [10/22] PowerShell..." -ForegroundColor DarkCyan
$histFile = "$env:APPDATAMicrosoftWindowsPowerShellPSReadLineConsoleHost_history.txt"
Write-Section "POWERSHELL_INFO" @"
--- Execution Policy ---
$(Get-ExecutionPolicy -List | Format-Table | Out-String)
--- History (last 200 commands) ---
$(if (Test-Path $histFile) { Get-Content $histFile -Tail 200 | Out-String } else { "(not found)" })
"@

Write-Host "  [11/22] Recent Files..." -ForegroundColor DarkCyan
$rf = foreach ($p in @($env:TEMP,"$env:SystemRootTemp","$env:USERPROFILEDownloads",$env:APPDATA)) {
    if (Test-Path $p) { Get-ChildItem -Path $p -Recurse -File -EA SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select-Object FullName,LastWriteTime,@{N='KB';E={[math]::Round($_.Length/1KB,1)}} | Sort-Object LastWriteTime -Descending | Select-Object -First 20 }
}
Write-Section "RECENTLY_MODIFIED_FILES" ($rf | Format-Table -AutoSize | Out-String)

Write-Host "  [12/22] Software..." -ForegroundColor DarkCyan
Write-Section "INSTALLED_SOFTWARE" (@(Get-ItemProperty "HKLM:SoftwareMicrosoftWindowsCurrentVersionUninstall*" -EA SilentlyContinue; Get-ItemProperty "HKLM:SoftwareWow6432NodeMicrosoftWindowsCurrentVersionUninstall*" -EA SilentlyContinue) | Where-Object {$_.DisplayName} | Select-Object DisplayName,Publisher,DisplayVersion,InstallDate | Sort-Object InstallDate -Descending | Format-Table -AutoSize | Out-String)

Write-Host "  [13/22] Firewall..." -ForegroundColor DarkCyan
Write-Section "FIREWALL_INFO" @"
--- Profiles ---
$(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table | Out-String)
--- Inbound Allow Rules ---
$(Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'} | Select-Object DisplayName,LocalPort,RemoteAddress,Enabled | Format-Table -AutoSize | Out-String)
"@

Write-Host "  [14/22] Defender..." -ForegroundColor DarkCyan
Write-Section "DEFENDER_STATUS" @"
--- Status ---
$(Get-MpComputerStatus -EA SilentlyContinue | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,AntivirusSignatureLastUpdated | Format-List | Out-String)
--- Recent Detections ---
$(Get-MpThreatDetection -EA SilentlyContinue | Select-Object -First 10 | Format-Table | Out-String)
"@

Write-Host "  [15/22] Suspicious Checks..." -ForegroundColor DarkCyan
$sp = Get-WmiObject Win32_Process | Where-Object { $_.ExecutablePath -match "\temp\|\tmp\|appdata\local\temp|\windows\temp" }
$sc = Get-NetTCPConnection | Where-Object { $_.RemotePort -in @(4444,4445,1337,31337,8888,9090,6667,6697,1234,5555,7777) -and $_.State -eq 'Established' }
Write-Section "SUSPICIOUS_INDICATORS" @"
--- Processes from suspicious paths ---
$(if ($sp) { $sp | Select-Object ProcessId,Name,ExecutablePath | Format-Table | Out-String } else { "(none)" })
--- Connections to high-risk ports ---
$(if ($sc) { $sc | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Format-Table | Out-String } else { "(none)" })
"@

Write-Host "  [16/22] Prefetch files..." -ForegroundColor DarkCyan
Write-Section "PREFETCH_FILES" (Get-ChildItem "$env:SystemRootPrefetch*.pf" -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 50 | Select-Object Name,LastWriteTime | Format-Table -AutoSize | Out-String)

Write-Host "  [17/22] Shadow copies..." -ForegroundColor DarkCyan
Write-Section "SHADOW_COPIES" (vssadmin list shadows 2>&1 | Out-String)

Write-Host "  [18/22] RDP artifacts..." -ForegroundColor DarkCyan
$rdpE = (Get-ItemProperty "HKLM:SYSTEMCurrentControlSetControlTerminal Server" -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
Write-Section "RDP_ARTIFACTS" @"
--- RDP Status ---
$(if ($rdpE -eq 0) { "RDP ENABLED" } elseif ($rdpE -eq 1) { "RDP Disabled" } else { "Unknown" })
--- Client History ---
$((Get-ChildItem "HKCU:SOFTWAREMicrosoftTerminal Server ClientServers" -EA SilentlyContinue | ForEach-Object { [PSCustomObject]@{Server=$_.PSChildName;User=(Get-ItemProperty $_.PSPath -Name UsernameHint -EA SilentlyContinue).UsernameHint} } | Format-Table | Out-String).Trim())
--- Active Sessions ---
$((query session 2>&1 | Out-String).Trim())
"@

Write-Host "  [19/22] USB history..." -ForegroundColor DarkCyan
Write-Section "USB_HISTORY" (Get-ChildItem "HKLM:SYSTEMCurrentControlSetEnumUSBSTOR" -EA SilentlyContinue | ForEach-Object { $c=$_.PSChildName; Get-ChildItem $_.PSPath -EA SilentlyContinue | ForEach-Object { [PSCustomObject]@{Class=$c;InstanceID=$_.PSChildName;Name=(Get-ItemProperty $_.PSPath -Name FriendlyName -EA SilentlyContinue).FriendlyName} } } | Format-Table -AutoSize | Out-String)

Write-Host "  [20/22] Named pipes..." -ForegroundColor DarkCyan
Write-Section "NAMED_PIPES" (try { [System.IO.Directory]::GetFiles('\.pipe') | Sort-Object | Out-String } catch { "(requires elevated context)" })

Write-Host "  [21/22] Persistence (extended)..." -ForegroundColor DarkCyan
$ppl2 = (Get-ItemProperty "HKLM:SYSTEMCurrentControlSetControlLsa" -Name RunAsPPL -EA SilentlyContinue).RunAsPPL
$wmiF2 = Get-WMIObject -Namespace rootsubscription -Class __EventFilter -EA SilentlyContinue
$wmiC2 = Get-WMIObject -Namespace rootsubscription -Class __EventConsumer -EA SilentlyContinue
Write-Section "PERSISTENCE" @"
--- LSA Packages ---
$((Get-ItemProperty "HKLM:SYSTEMCurrentControlSetControlLsa" -EA SilentlyContinue | Select-Object SecurityPackages,AuthenticationPackages,NotificationPackages | Format-List | Out-String).Trim())
--- LSASS RunAsPPL ---
$(if ($ppl2 -eq 1) { "RunAsPPL = 1 (LSASS protected)" } else { "RunAsPPL = $ppl2 (LSASS NOT protected)" })
--- Boot Execute ---
$((Get-ItemProperty "HKLM:SYSTEMCurrentControlSetControlSession Manager" -Name BootExecute -EA SilentlyContinue).BootExecute -join ", ")
--- Network Provider Order ---
$((Get-ItemProperty "HKLM:SYSTEMCurrentControlSetControlNetworkProviderOrder" -EA SilentlyContinue).ProviderOrder)
--- WMI Filters ---
$(if ($wmiF2) { $wmiF2 | Select-Object Name,Query | Format-Table | Out-String } else { "(none)" })
--- WMI Consumers ---
$(if ($wmiC2) { $wmiC2 | Select-Object Name,ScriptText,CommandLineTemplate | Format-Table | Out-String } else { "(none)" })
"@

Write-Host "  [22/22] Browser artifacts..." -ForegroundColor DarkCyan
Write-Section "BROWSER_ARTIFACTS" @"
--- Downloads (last 30 days) ---
$((Get-ChildItem "$env:USERPROFILEDownloads" -Recurse -File -EA SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-30)} | Select-Object Name,LastWriteTime,@{N='KB';E={[math]::Round($_.Length/1KB,1)}} | Sort-Object LastWriteTime -Descending | Select-Object -First 30 | Format-Table -AutoSize | Out-String).Trim())
--- Chrome Extensions ---
$((Get-ChildItem "$env:LOCALAPPDATAGoogleChromeUser DataDefaultExtensions" -EA SilentlyContinue | Select-Object Name,LastWriteTime | Format-Table | Out-String).Trim())
--- Edge Extensions ---
$((Get-ChildItem "$env:LOCALAPPDATAMicrosoftEdgeUser DataDefaultExtensions" -EA SilentlyContinue | Select-Object Name,LastWriteTime | Format-Table | Out-String).Trim())
"@

Add-Content -Path $outputFile -Value "`r`n=== INVESTIGATION COMPLETE ===`r`nEndTime: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Encoding UTF8
Write-Host "`n  [DONE] Report: $outputFile" -ForegroundColor Green
Write-Host "  Upload to SnowTrace Dashboard for analysis." -ForegroundColor Cyan
