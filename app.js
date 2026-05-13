/* ═══════════════════════════════════════════════════════════════════
   SnowTrace — Cyber Triage Platform | app.js
   By Agent P
   ═══════════════════════════════════════════════════════════════════ */

'use strict';

// ════════════════════════════════════════════
//  NAVIGATION
// ════════════════════════════════════════════

function showTab(id, btn) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  if (btn) btn.classList.add('active');
}

function toggleRem(header) {
  const body  = header.nextElementSibling;
  const arrow = header.querySelector('.rem-arrow');
  body.classList.toggle('open');
  arrow.style.transform = body.classList.contains('open') ? 'rotate(90deg)' : '';
}

function copyCode(btn) {
  const txt = btn.parentElement.textContent.replace('copy', '').trim();
  navigator.clipboard.writeText(txt).then(() => {
    btn.textContent = 'copied!';
    setTimeout(() => { btn.textContent = 'copy'; }, 1500);
  });
}

// ════════════════════════════════════════════
//  DRAG & DROP / FILE UPLOAD
// ════════════════════════════════════════════

function handleDragOver(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.add('drag-over');
}

function handleDragLeave() {
  document.getElementById('drop-zone').classList.remove('drag-over');
}

function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) readFile(file);
}

function handleFileSelect(e) {
  if (e.target.files[0]) readFile(e.target.files[0]);
}

function readFile(file) {
  const reader = new FileReader();
  reader.onload = (e) => analyzeReport(e.target.result, file.name);
  reader.readAsText(file);
}

// ════════════════════════════════════════════
//  SECTION PARSER
// ════════════════════════════════════════════

function parseSections(text) {
  const sections = {};
  const re = /\[([A-Z_]+)\]\r?\n([\s\S]*?)\r?\n\[\/\1\]/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    sections[m[1]] = m[2];
  }

  // Parse top-level header fields (key: value lines before first section)
  const hdr = {};
  const lines = text.split(/\r?\n/).slice(0, 20);
  for (const l of lines) {
    const kv = l.match(/^([A-Za-z]+):\s*(.+)$/);
    if (kv) hdr[kv[1]] = kv[2].trim();
  }
  sections._header = hdr;
  return sections;
}

// ════════════════════════════════════════════
//  ANALYSIS ENGINE — ENTRY POINT
// ════════════════════════════════════════════

function analyzeReport(text, filename) {
  const sections = parseSections(text);
  const platform = (sections._header.Platform || '').toLowerCase();
  const findings = [];

  if (platform === 'windows') {
    analyzeWindows(sections, findings);
  } else if (platform === 'linux') {
    analyzeLinux(sections, findings);
  } else {
    // Heuristic detection
    if (text.includes('HKLM') || text.includes('PowerShell')) {
      analyzeWindows(sections, findings);
    } else {
      analyzeLinux(sections, findings);
    }
  }

  renderResults(sections._header, findings, filename, platform);
}

// ════════════════════════════════════════════
//  WINDOWS ANALYSIS
// ════════════════════════════════════════════

function analyzeWindows(s, F) {
  const proc    = s.RUNNING_PROCESSES    || '';
  const net     = s.NETWORK_CONNECTIONS  || '';
  const ps      = s.POWERSHELL_INFO      || '';
  const sched   = s.SCHEDULED_TASKS      || '';
  const pers    = s.PERSISTENCE          || '';
  const evts    = s.SECURITY_EVENTS      || '';
  const defs    = s.DEFENDER_STATUS      || '';
  const susp    = s.SUSPICIOUS_INDICATORS || '';
  const prefetch= s.PREFETCH_FILES       || '';
  const shadow  = s.SHADOW_COPIES        || '';
  const rdp     = s.RDP_ARTIFACTS        || '';
  const pipes   = s.NAMED_PIPES          || '';
  const browser = s.BROWSER_ARTIFACTS    || '';

  // ── Processes from suspicious locations ──
  const suspProcPaths = extractLines(proc, /\\temp\\|\\tmp\\|appdata\\local\\temp|\\windows\\temp|\\programdata\\/i);
  if (suspProcPaths.length) {
    F.push({
      sev: 'critical',
      title: 'Processes running from temporary/unusual directories',
      desc: 'Malware frequently executes from %TEMP%, AppData\\Local\\Temp, or ProgramData to avoid detection. These paths should never host executable processes.',
      evidence: suspProcPaths.slice(0, 10).join('\n'),
    });
  }

  const unsignedProcs = extractLines(proc, /Signature.*(?:NotSigned|UnknownError|HashMismatch)/i);
  if (unsignedProcs.length > 3) {
    F.push({
      sev: 'high',
      title: `${unsignedProcs.length} processes with invalid or missing digital signatures`,
      desc: 'Unsigned executables may indicate tampered binaries, dropped malware, or custom attacker tooling. Investigate each one.',
      evidence: unsignedProcs.slice(0, 8).join('\n'),
    });
  }

  // ── Network — high-risk ports ──
  const BAD_PORTS_WIN = [4444, 4445, 1337, 31337, 8888, 9090, 9999, 6667, 6697, 1234, 5555, 7777, 13338, 65535, 12345];
  const netLines = net.split('\n');
  const badConns = netLines.filter(l => BAD_PORTS_WIN.some(p => l.match(new RegExp(':' + p + '\\s'))));
  if (badConns.length) {
    F.push({
      sev: 'critical',
      title: 'Active connections to high-risk/known attacker ports',
      desc: 'Ports such as 4444 (Metasploit default), 31337 (elite hacker), 1337, 6667 (IRC C2) are strongly associated with malware and C2 frameworks.',
      evidence: badConns.join('\n'),
    });
  }

  const rdpLines = netLines.filter(l => l.match(/:3389\s/) && l.match(/Established/i));
  if (rdpLines.length) {
    F.push({
      sev: 'medium',
      title: 'Active RDP connections detected',
      desc: 'Remote Desktop connections may be legitimate administrative access or attacker lateral movement. Verify all active RDP sessions.',
      evidence: rdpLines.join('\n'),
    });
  }

  // ── PowerShell history — IOCs ──
  const psLines = ps.split('\n');
  const psIoc = psLines.filter(l =>
    /iex\b|invoke-expression|\-enc\s|\-encodedcommand|downloadstring|downloadfile|webclient|bitsadmin|certutil.*decode|\[convert\]::frombase64|net\.webclient|start-bitstransfer/i.test(l)
  );
  if (psIoc.length) {
    F.push({
      sev: 'critical',
      title: `PowerShell history contains download/execution cradles (${psIoc.length} lines)`,
      desc: 'Commands like IEX, Invoke-Expression, -EncodedCommand, DownloadString, and certutil decode are classic PowerShell-based attack techniques used for initial execution and lateral movement.',
      evidence: psIoc.slice(0, 15).join('\n'),
    });
  }

  const base64Lines = psLines.filter(l => /[A-Za-z0-9+/]{50,}={0,2}/.test(l) && !/^#/.test(l));
  if (base64Lines.length) {
    F.push({
      sev: 'high',
      title: 'Potential Base64-encoded content in PowerShell history',
      desc: 'Long base64 strings often represent obfuscated payloads, encoded scripts, or exfiltrated data. Each should be decoded and inspected.',
      evidence: base64Lines.slice(0, 5).join('\n'),
    });
  }

  // ── Scheduled tasks — suspicious actions ──
  const taskLines = sched.split('\n');
  const suspTasks = taskLines.filter(l =>
    /-enc\s|\-encodedcommand|base64|cmd.*\/c.*wscript|powershell.*hidden|mshta|regsvr32|rundll32/i.test(l)
  );
  if (suspTasks.length) {
    F.push({
      sev: 'critical',
      title: 'Scheduled tasks with obfuscated or suspicious actions',
      desc: 'Encoded commands, mshta, regsvr32, or rundll32 in task actions are common persistence techniques. Attackers abuse scheduled tasks to survive reboots.',
      evidence: suspTasks.slice(0, 8).join('\n'),
    });
  }

  // ── Persistence — WMI subscriptions ──
  if (/ScriptText|CommandLineTemplate/i.test(pers) && !/\(none\)/i.test(pers)) {
    F.push({
      sev: 'critical',
      title: 'WMI Event Subscription persistence detected',
      desc: 'WMI subscriptions are a stealthy persistence mechanism that survives reimaging of user profiles. Attackers use them to re-execute malware on system events.',
      evidence: extractBlock(pers, /WMI Event/),
    });
  }

  // ── Persistence — IFEO debugger hijack ──
  const ifeoPart = extractBlock(pers, /Image File Execution Options/);
  if (ifeoPart && /Debugger:/i.test(ifeoPart)) {
    F.push({
      sev: 'high',
      title: 'Image File Execution Options (IFEO) debugger hijack detected',
      desc: 'IFEO debugger entries redirect execution of a target binary to an attacker-controlled process. This is used to silently hijack applications.',
      evidence: ifeoPart.split('\n').filter(l => /Debugger/i.test(l)).join('\n'),
    });
  }

  // ── Security events — failed logins ──
  const failedLogins = (evts.match(/\[!!\] FAILED Login/g) || []).length;
  if (failedLogins > 10) {
    F.push({
      sev: 'high',
      title: `${failedLogins} failed login events in the last 7 days`,
      desc: 'A large number of failed logins may indicate a brute-force or password-spray attack. Correlate source IPs and check if any succeeded.',
      evidence: `Failed login events count: ${failedLogins}\n` + extractLines(evts, /FAILED Login/).slice(0, 5).join('\n'),
    });
  } else if (failedLogins > 0) {
    F.push({
      sev: 'medium',
      title: `${failedLogins} failed login events detected`,
      desc: 'Review source of failed authentication attempts.',
      evidence: `Failed login count: ${failedLogins}`,
    });
  }

  // ── Security events — new user accounts ──
  const newUsers = extractLines(evts, /\[NEW\] User Account Created/);
  if (newUsers.length) {
    F.push({
      sev: 'high',
      title: `${newUsers.length} user account(s) created recently`,
      desc: 'New local user account creation may indicate an attacker creating a backdoor account for persistent access.',
      evidence: newUsers.join('\n'),
    });
  }

  // ── Defender disabled ──
  if (/RealTimeProtectionEnabled\s*:\s*False/i.test(defs)) {
    F.push({
      sev: 'critical',
      title: 'Windows Defender Real-Time Protection is DISABLED',
      desc: 'Attackers commonly disable AV/EDR solutions as a first step after gaining access to prevent detection of subsequent activity.',
      evidence: 'RealTimeProtectionEnabled : False',
    });
  }
  if (/AMServiceEnabled\s*:\s*False/i.test(defs)) {
    F.push({
      sev: 'critical',
      title: 'Windows Defender Antimalware Service is DISABLED',
      desc: 'The core Defender service has been stopped. This is a serious indicator that AV tampering has occurred.',
      evidence: 'AMServiceEnabled : False',
    });
  }

  // ── Script-level suspicious indicators ──
  const suspLines = susp.split('\n').filter(l => l.trim() && !l.match(/^---/));
  if (suspLines.length > 5) {
    F.push({
      sev: 'high',
      title: 'Suspicious indicators detected by script checks',
      desc: 'The script identified processes running from non-standard paths or connections to high-risk ports during collection.',
      evidence: suspLines.slice(0, 15).join('\n'),
    });
  }

  // ── Security events — log cleared ──
  const logCleared = extractLines(evts, /CLR.*LOG CLEARED/i);
  if (logCleared.length) {
    F.push({
      sev: 'critical',
      title: `Security or System event log was cleared (${logCleared.length} event(s))`,
      desc: 'Event log clearing (Event IDs 1102/104) is a classic attacker anti-forensics action. Attackers clear logs after gaining access to hide their activity.',
      evidence: logCleared.join('\n'),
    });
  }

  // ── Persistence — LSASS unprotected ──
  if (/RunAsPPL = 0|LSASS NOT protected/i.test(pers)) {
    F.push({
      sev: 'medium',
      title: 'LSASS is not protected (RunAsPPL disabled)',
      desc: 'Without RunAsPPL, LSASS memory can be dumped to extract credential hashes and Kerberos tickets. Enable RunAsPPL via HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1.',
      evidence: extractLines(pers, /RunAsPPL/i).join('\n'),
    });
  }

  // ── Persistence — non-standard Boot Execute ──
  const bootExec = extractLines(pers, /Boot Execute/i);
  if (bootExec.some(l => !/autocheck autochk/.test(l))) {
    F.push({
      sev: 'high',
      title: 'Non-standard Boot Execute entry detected',
      desc: 'Boot Execute entries run before Windows fully initializes. The only legitimate value is "autocheck autochk *". Anything else is highly suspicious.',
      evidence: bootExec.join('\n'),
    });
  }

  // ── Persistence — non-standard LSA packages ──
  const lsaLines = extractLines(pers, /SecurityPackages|AuthenticationPackages/i);
  const suspLsa = lsaLines.filter(l => /pam_|mimilib|ssp\.dll/i.test(l));
  if (suspLsa.length) {
    F.push({
      sev: 'critical',
      title: 'Suspicious LSA Security/Authentication package detected',
      desc: 'Attackers inject malicious SSPs (e.g. mimilib.dll) into LSA to capture credentials on every login. Any unrecognized DLL here is a strong compromise indicator.',
      evidence: suspLsa.join('\n'),
    });
  }

  // ── Shadow copies deleted/missing ──
  if (shadow && /no items found|no shadow copies/i.test(shadow)) {
    F.push({
      sev: 'high',
      title: 'No Volume Shadow Copies found — possible ransomware activity',
      desc: 'Ransomware consistently deletes VSS shadow copies to prevent recovery. No shadow copies on a production system warrants investigation.',
      evidence: shadow.split('\n').slice(0, 5).join('\n'),
    });
  }

  // ── Named pipes — suspicious ──
  const suspPipes = extractLines(pipes, /meterpreter|msf|cobalt|cobaltstrike|beacon|empire|havoc|sliver|postex/i);
  if (suspPipes.length) {
    F.push({
      sev: 'critical',
      title: 'Named pipe associated with known C2 framework detected',
      desc: 'Metasploit, Cobalt Strike, Empire and similar frameworks use characteristic named pipe names. This is a strong active compromise indicator.',
      evidence: suspPipes.join('\n'),
    });
  }

  // ── RDP — unexpected connections ──
  const rdpConns = extractLines(rdp, /Server\s+:/i);
  if (rdpConns.length) {
    F.push({
      sev: 'medium',
      title: `${rdpConns.length} saved RDP connection(s) in client history`,
      desc: 'RDP connection history reveals systems this machine has remotely accessed. Unexpected destinations may indicate lateral movement by an attacker.',
      evidence: rdpConns.join('\n'),
    });
  }

  // ── Prefetch — execution from suspicious paths ──
  const suspPrefetch = extractLines(prefetch, /TEMP|TMP|APPDATA|DOWNLOADS|\\USERS\\PUBLIC/i);
  if (suspPrefetch.length) {
    F.push({
      sev: 'high',
      title: `Prefetch shows execution of files from suspicious directories`,
      desc: 'Prefetch records binary execution even if the file was deleted afterward. Entries from Temp, AppData, or Downloads paths warrant investigation.',
      evidence: suspPrefetch.slice(0, 10).join('\n'),
    });
  }

  // ── Browser — suspicious downloads ──
  const suspDownloads = extractLines(browser, /\.exe$|\.ps1$|\.bat$|\.vbs$|\.js$|\.hta$|\.cmd$|\.scr$|\.lnk$/i);
  if (suspDownloads.length) {
    F.push({
      sev: 'high',
      title: `${suspDownloads.length} potentially malicious file type(s) in Downloads folder`,
      desc: 'Executable and script files in the Downloads folder (.exe, .ps1, .bat, .vbs, .hta, .js) are common initial access artifacts. Verify each file is legitimate.',
      evidence: suspDownloads.slice(0, 10).join('\n'),
    });
  }

  F.push({
    sev: 'info',
    title: 'Investigation complete — all major categories scanned',
    desc: 'SnowTrace collected: processes, network, persistence (run keys, WMI, IFEO, LSA packages, boot execute), scheduled tasks, services, users, security events (incl. log clearing), PowerShell history, prefetch, shadow copies, RDP artifacts, USB history, named pipes, browser artifacts, installed software, firewall, and Defender status.',
    evidence: '',
  });
}

// ════════════════════════════════════════════
//  LINUX ANALYSIS
// ════════════════════════════════════════════

function analyzeLinux(s, F) {
  const proc      = s.RUNNING_PROCESSES    || '';
  const net       = s.NETWORK_CONNECTIONS  || '';
  const cron      = s.CRON_JOBS            || '';
  const ssh       = s.SSH_KEYS             || '';
  const hist      = s.BASH_HISTORY         || '';
  const auth      = s.AUTH_LOGS            || '';
  const suid      = s.SUID_SGID_FILES      || '';
  const ww        = s.WORLD_WRITABLE       || '';
  const hosts     = s.HOSTS_FILE           || '';
  const susp      = s.SUSPICIOUS_INDICATORS || '';
  const users     = s.USER_ACCOUNTS        || '';
  const mods      = s.KERNEL_MODULES       || '';
  const ldpre     = s.LD_PRELOAD           || '';
  const caps      = s.FILE_CAPABILITIES    || '';
  const pam       = s.PAM_CONFIG           || '';
  const profiles  = s.SHELL_PROFILES       || '';
  const immutable = s.IMMUTABLE_FILES      || '';
  const procmaps  = s.PROC_MAPS            || '';
  const miners    = s.CRYPTO_MINERS        || '';
  const pkgint    = s.PACKAGE_INTEGRITY    || '';

  // ── Processes from /tmp ──
  const tmpProcs = extractLines(proc + susp, /\/tmp\/|\/dev\/shm\/|\/var\/tmp\//);
  if (tmpProcs.length) {
    F.push({
      sev: 'critical',
      title: 'Processes running from /tmp, /dev/shm, or /var/tmp',
      desc: 'Legitimate system processes never run from world-writable temp directories. This is a strong indicator of malware or a live attacker presence.',
      evidence: tmpProcs.slice(0, 10).join('\n'),
    });
  }

  // ── Cron — download/reverse-shell patterns ──
  const suspCron = cron.split('\n').filter(l =>
    /wget|curl|bash\s*-i|nc\s|ncat|\/dev\/tcp|python.*-c|perl.*-e|base64\s*-d|mkfifo/i.test(l) && !l.match(/^#/)
  );
  if (suspCron.length) {
    F.push({
      sev: 'critical',
      title: 'Cron job with download or reverse-shell pattern',
      desc: 'wget, curl, nc, bash -i, /dev/tcp and similar patterns in crontab entries are a major red flag. Attackers use cron for persistence and beaconing.',
      evidence: suspCron.join('\n'),
    });
  }

  // ── SSH authorized keys ──
  const authKeyLines = ssh.split('\n').filter(l => l.match(/^(ssh-|ecdsa-|sk-)/));
  if (authKeyLines.length > 5) {
    F.push({
      sev: 'high',
      title: `${authKeyLines.length} SSH authorized keys found across accounts`,
      desc: 'A high number of authorized SSH keys is suspicious. Verify each key is known and authorized. Attackers add SSH keys for persistent, password-free access.',
      evidence: authKeyLines.join('\n'),
    });
  } else if (authKeyLines.length > 0) {
    F.push({
      sev: 'medium',
      title: `${authKeyLines.length} SSH authorized key(s) found — review each`,
      desc: 'Verify that all SSH authorized keys belong to known, authorized personnel.',
      evidence: authKeyLines.join('\n'),
    });
  }

  // ── Bash history — reverse shell / privilege escalation ──
  const suspHist = hist.split('\n').filter(l =>
    /\bnc\b|\bncat\b|\bnetcat\b|\/dev\/tcp\/|bash\s+-i|mkfifo|base64\s*-d|chmod\s+[+]s|chmod\s+4755|python.*import.*socket|perl.*socket|wget\s+http|curl\s+http|\.\/[a-z0-9]{4,8}$/i.test(l)
    && !l.match(/^#/)
  );
  if (suspHist.length) {
    F.push({
      sev: 'critical',
      title: `${suspHist.length} suspicious command(s) in bash/shell history`,
      desc: 'Commands indicating reverse shells (nc, /dev/tcp, bash -i), privilege escalation (chmod +s), or payload download (wget/curl) were found in shell history.',
      evidence: suspHist.slice(0, 15).join('\n'),
    });
  }

  // ── Auth logs — failed logins ──
  const failedAuth = extractLines(auth, /failed password|authentication failure|invalid user|illegal user|Connection closed by invalid user/i);
  if (failedAuth.length > 50) {
    F.push({
      sev: 'high',
      title: `${failedAuth.length} failed authentication events in auth logs`,
      desc: 'High volume of authentication failures indicates brute-force or credential stuffing. Correlate source IPs.',
      evidence: failedAuth.slice(0, 10).join('\n'),
    });
  } else if (failedAuth.length > 10) {
    F.push({
      sev: 'medium',
      title: `${failedAuth.length} failed login attempts detected`,
      desc: 'Multiple failed authentication events. Review the source IPs.',
      evidence: failedAuth.slice(0, 8).join('\n'),
    });
  }

  // ── Auth logs — root SSH login ──
  const rootAccepted = extractLines(auth, /Accepted.*root|root.*Accepted/i);
  if (rootAccepted.length) {
    F.push({
      sev: 'critical',
      title: 'Root login accepted via SSH',
      desc: 'Direct root SSH login is a severe finding. PermitRootLogin should be "no" in sshd_config. Verify this access was authorized.',
      evidence: rootAccepted.join('\n'),
    });
  }

  // ── SUID/SGID in non-standard locations ──
  const unusualSuid = suid.split('\n').filter(l =>
    l.trim() && !l.match(/^---/) &&
    !l.match(/\/usr\/(s?bin|lib|libexec)|^\/(s?bin)|\/snap\/|\/proc\/|\/sys\//)
  );
  if (unusualSuid.length) {
    F.push({
      sev: 'high',
      title: `${unusualSuid.length} SUID/SGID files in non-standard locations`,
      desc: 'SUID binaries in /tmp, /home, or other non-standard paths are a major privilege escalation indicator. Attackers plant SUID shells to maintain elevated access.',
      evidence: unusualSuid.slice(0, 10).join('\n'),
    });
  }

  // ── World-writable files in system directories ──
  const wwSys = extractLines(ww, /\/etc\/|\/bin\/|\/sbin\/|\/usr\/bin\/|\/usr\/sbin\//);
  if (wwSys.length) {
    F.push({
      sev: 'critical',
      title: 'World-writable files in system directories (/etc, /bin, /usr)',
      desc: 'System binaries or configuration files should never be world-writable. This allows any user to inject malicious code into system files.',
      evidence: wwSys.join('\n'),
    });
  }

  // ── /etc/hosts — custom entries ──
  const hostLines = hosts.split('\n').filter(l =>
    l.trim() &&
    !l.match(/^#/) &&
    !l.match(/^(127\.0\.0\.1|::1|fe80|ff0|localhost|ip6-|broadcasthost)/i) &&
    l.trim() !== ''
  );
  if (hostLines.length) {
    F.push({
      sev: 'medium',
      title: `${hostLines.length} custom entries in /etc/hosts`,
      desc: 'Unusual /etc/hosts entries can redirect traffic to attacker-controlled servers, intercept credentials, or block security updates.',
      evidence: hostLines.join('\n'),
    });
  }

  // ── Users with interactive shells ──
  const shellUsers = extractLines(users, /\/(bash|sh|zsh|fish|dash)$/);
  if (shellUsers.length > 5) {
    F.push({
      sev: 'medium',
      title: `${shellUsers.length} accounts with interactive shell access`,
      desc: 'Review all accounts with login shells. Service accounts should use /sbin/nologin or /bin/false.',
      evidence: shellUsers.join('\n'),
    });
  }

  // ── Kernel modules ──
  const modLines = mods.split('\n').filter(l => l.trim() && !l.match(/^Module/));
  if (modLines.length > 0) {
    F.push({
      sev: 'low',
      title: `${modLines.length} kernel modules loaded — review for rootkits`,
      desc: 'Compare loaded modules against expected baseline. Unknown modules may indicate LKM rootkits. Use rkhunter or chkrootkit for automated detection.',
      evidence: modLines.slice(0, 5).join('\n') + (modLines.length > 5 ? '\n...' : ''),
    });
  }

  // ── Network — high-risk ports ──
  const BAD_PORTS_LIN = [4444, 4445, 1337, 31337, 8888, 9090, 9999, 6667, 6697, 1234, 5555, 7777];
  const badConns = net.split('\n').filter(l => BAD_PORTS_LIN.some(p => l.includes(':' + p)));
  if (badConns.length) {
    F.push({
      sev: 'critical',
      title: 'Connections to high-risk ports detected',
      desc: 'Ports 4444 (Metasploit), 31337, 1337, 6667 (IRC C2) are associated with attacker tooling.',
      evidence: badConns.join('\n'),
    });
  }

  // ── Suspicious indicator section ──
  const suspCmds = susp.split('\n').filter(l =>
    /nc |ncat|\/dev\/tcp|bash -i|mkfifo|base64 -d|wget|curl/i.test(l)
  );
  if (suspCmds.length) {
    F.push({
      sev: 'high',
      title: 'Suspicious commands flagged during collection',
      desc: 'The script detected suspicious commands during the investigation phase.',
      evidence: suspCmds.slice(0, 10).join('\n'),
    });
  }

  // ── ld.so.preload ──
  if (/\[WARNING\] File exists/i.test(ldpre)) {
    F.push({
      sev: 'critical',
      title: '/etc/ld.so.preload exists — classic rootkit persistence mechanism',
      desc: '/etc/ld.so.preload forces a shared library to be loaded into every process. Attackers use it to intercept system calls, hide files/processes, and capture credentials. This file should not exist on a clean system.',
      evidence: ldpre.split('\n').slice(0, 10).join('\n'),
    });
  }

  // ── Dangerous file capabilities ──
  const dangerCaps = extractLines(caps, /cap_setuid|cap_setgid|cap_sys_admin|cap_net_raw|cap_dac_override/i)
    .filter(l => !l.match(/^---/) && l.trim());
  if (dangerCaps.length) {
    F.push({
      sev: 'high',
      title: `${dangerCaps.length} file(s) with dangerous capabilities set`,
      desc: 'Capabilities like cap_setuid, cap_sys_admin, or cap_dac_override on binaries (especially interpreters like python/perl) allow privilege escalation without a SUID bit — often missed by standard audits.',
      evidence: dangerCaps.join('\n'),
    });
  }

  // ── Unusual PAM modules ──
  const unusualPam = extractLines(pam, /\.so/).filter(l =>
    !l.match(/^#/) && l.trim() &&
    !/pam_(unix|env|limits|systemd|deny|permit|keyinit|loginuid|nologin|securetty|tally2|faillock|motd|mail|lastlog|selinux|namespace|cap|xauth|pwquality|cracklib|sss|ldap|winbind|access|localuser|group|exec|script|time|listfile)/i.test(l)
  );
  if (unusualPam.length) {
    F.push({
      sev: 'high',
      title: 'Non-standard PAM module(s) detected',
      desc: 'Attackers plant malicious PAM modules (e.g. pam_backdoor.so) that accept a hardcoded password for any account. Any unrecognized PAM module must be investigated.',
      evidence: unusualPam.slice(0, 10).join('\n'),
    });
  }

  // ── Shell profile tampering ──
  const suspProfile = extractLines(profiles, /wget|curl|\/dev\/tcp|bash\s+-i|mkfifo|base64|LD_PRELOAD|exec\s+[^-]/i)
    .filter(l => !l.match(/^#/) && l.trim());
  if (suspProfile.length) {
    F.push({
      sev: 'critical',
      title: 'Shell profile file contains suspicious command(s)',
      desc: 'Attacker-injected commands in .bashrc, .profile, /etc/profile etc. execute every time a user opens a shell. This is used for reverse shell callbacks, credential capture, or LD_PRELOAD injection.',
      evidence: suspProfile.slice(0, 10).join('\n'),
    });
  }

  // ── Immutable files in sensitive dirs ──
  const immutableHits = extractLines(immutable, /IMMUTABLE:/i);
  if (immutableHits.length) {
    F.push({
      sev: 'high',
      title: `${immutableHits.length} immutable file(s) detected (chattr +i)`,
      desc: 'Attackers set the immutable bit on their files and backdoors to prevent deletion even by root. Immutable files in /etc, /bin, or home directories are highly suspicious.',
      evidence: immutableHits.join('\n'),
    });
  }

  // ── Libraries from /tmp loaded in processes ──
  const mapHits = extractLines(procmaps, /\/(tmp|dev\/shm|var\/tmp)\//i)
    .filter(l => !l.match(/^===/));
  if (mapHits.length) {
    F.push({
      sev: 'critical',
      title: 'Shared library from temp directory loaded in live process',
      desc: 'A running process has mapped a library from /tmp, /dev/shm, or /var/tmp. This is a strong indicator of process injection or a running malware implant.',
      evidence: mapHits.slice(0, 10).join('\n'),
    });
  }

  // ── Deleted memory mappings ──
  const deletedMaps = extractLines(procmaps, /\(deleted\)/i)
    .filter(l => !l.match(/^PID/) === false);
  if (deletedMaps.length > 5) {
    F.push({
      sev: 'medium',
      title: `Processes with deleted memory-mapped files detected`,
      desc: 'Processes mapping files that have been deleted from disk may indicate malware that executes from memory after removing its on-disk binary.',
      evidence: deletedMaps.slice(0, 8).join('\n'),
    });
  }

  // ── Crypto miners ──
  const minerProcs = extractLines(miners, /xmrig|minerd|xmr-stak|cpuminer|kswapd0|cryptonight|stratum/i)
    .filter(l => !l.match(/^---/) && l.trim());
  const minerConns = extractLines(miners, /:3333|:4444|:5555|:14444|:45700/);
  if (minerProcs.length || minerConns.length) {
    F.push({
      sev: 'critical',
      title: 'Crypto miner indicators detected',
      desc: 'Known miner process names or connections to mining pool ports (3333, 4444, 14444) were found. Cryptomining malware typically runs as a persistent service and can indicate deeper system compromise.',
      evidence: [...minerProcs, ...minerConns].slice(0, 10).join('\n'),
    });
  }

  // ── Package integrity failures ──
  const pkgFail = extractLines(pkgint, /MODIFIED|^S\.|^M\.|^5\./i)
    .filter(l => l.trim() && !l.match(/^---/));
  if (pkgFail.length) {
    F.push({
      sev: 'critical',
      title: `${pkgFail.length} system package file(s) have been tampered with`,
      desc: 'Package integrity verification found modified system files. Attackers replace system binaries (ls, ps, netstat, sshd) with trojaned versions to maintain access and hide activity.',
      evidence: pkgFail.slice(0, 15).join('\n'),
    });
  }

  F.push({
    sev: 'info',
    title: 'Investigation complete — all major categories scanned',
    desc: 'SnowTrace collected: processes, network, cron, systemd, users, SSH keys, auth logs, shell history, SUID/SGID, world-writable, kernel modules, ld.so.preload, file capabilities, PAM config, shell profiles, immutable files, process memory maps, XDG autostart, containers, package integrity, and crypto miner indicators.',
    evidence: '',
  });
}

// ════════════════════════════════════════════
//  HELPERS
// ════════════════════════════════════════════

function extractLines(text, regex) {
  return text.split('\n').filter(l => regex.test(l));
}

function extractBlock(text, startRegex) {
  const lines = text.split('\n');
  let capturing = false;
  const out = [];
  for (const l of lines) {
    if (startRegex.test(l)) capturing = true;
    if (capturing) {
      out.push(l);
      if (out.length > 20) break;
    }
  }
  return out.join('\n');
}

// ════════════════════════════════════════════
//  RENDER RESULTS
// ════════════════════════════════════════════

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };

function renderResults(hdr, findings, filename, platform) {
  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => counts[f.sev]++);

  let html = `
  <div class="report-header">
    <div style="color:var(--green);font-size:13px;letter-spacing:1px">📋 REPORT: ${escHtml(filename)}</div>
    <div class="report-meta">
      <div class="meta-chip">Platform: <span>${escHtml(platform.toUpperCase() || hdr.Platform || 'Unknown')}</span></div>
      <div class="meta-chip">Host: <span>${escHtml(hdr.Hostname || 'Unknown')}</span></div>
      <div class="meta-chip">User: <span>${escHtml(hdr.User || 'Unknown')}</span></div>
      <div class="meta-chip">Date: <span>${escHtml(hdr.Date || 'Unknown')}</span></div>
      <div class="meta-chip">OS: <span>${escHtml(hdr.OS || 'Unknown')}</span></div>
      <div class="meta-chip">Admin/Root: <span>${escHtml(hdr.IsAdmin || hdr.IsRoot || 'Unknown')}</span></div>
    </div>
  </div>

  <div class="findings-summary">
    ${counts.critical ? `<div class="sev-badge sev-critical">🔴 ${counts.critical} CRITICAL</div>` : ''}
    ${counts.high     ? `<div class="sev-badge sev-high">🟠 ${counts.high} HIGH</div>`         : ''}
    ${counts.medium   ? `<div class="sev-badge sev-medium">🟡 ${counts.medium} MEDIUM</div>`   : ''}
    ${counts.low      ? `<div class="sev-badge sev-low">🔵 ${counts.low} LOW</div>`             : ''}
    ${counts.info     ? `<div class="sev-badge sev-info">ℹ ${counts.info} INFO</div>`           : ''}
  </div>`;

  if (counts.critical === 0 && counts.high === 0) {
    html += `<div class="no-findings">
      <div class="no-findings-icon">✅</div>
      <div style="color:var(--green);font-size:14px">No critical or high severity findings</div>
      <div style="color:var(--text2);margin-top:8px;font-size:12px">Review medium and low findings below. Consider this a good baseline.</div>
    </div>`;
  }

  findings.forEach(f => {
    html += `
    <div class="finding finding-${f.sev}">
      <div class="finding-header" onclick="toggleFinding(this)">
        <div class="finding-sev">${SEV_LABEL[f.sev]}</div>
        <div class="finding-title">${escHtml(f.title)}</div>
        <div class="finding-arrow">▶</div>
      </div>
      <div class="finding-body">
        <div style="margin-bottom:8px;line-height:1.7">${escHtml(f.desc)}</div>
        ${f.evidence
          ? `<div style="font-size:11px;color:var(--text2);margin-bottom:4px;text-transform:uppercase;letter-spacing:1px">Evidence:</div>
             <div class="finding-evidence">${escHtml(f.evidence)}</div>`
          : ''}
        ${f.sev !== 'info'
          ? `<div style="margin-top:10px">
               <button class="btn btn-red"
                 onclick="showTab('remediation',document.querySelectorAll('.nav-btn')[4]);event.stopPropagation()">
                 → View Remediation Steps
               </button>
             </div>`
          : ''}
      </div>
    </div>`;
  });

  document.getElementById('analysis-output').innerHTML = html;

  // Auto-expand critical findings
  document.querySelectorAll('.finding-critical .finding-header').forEach(h => {
    h.nextElementSibling.classList.add('open');
    h.querySelector('.finding-arrow').style.transform = 'rotate(90deg)';
  });
}

function toggleFinding(header) {
  const body  = header.nextElementSibling;
  const arrow = header.querySelector('.finding-arrow');
  body.classList.toggle('open');
  arrow.style.transform = body.classList.contains('open') ? 'rotate(90deg)' : '';
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\n/g, '<br>');
}

// ════════════════════════════════════════════
//  SCRIPT DOWNLOAD
// ════════════════════════════════════════════

const WIN_SCRIPT = `#Requires -Version 3.0
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
$outputFile = "snowtrace_windows_\${hostname}_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

Write-Host "  SnowTrace | Windows Investigation | By Agent P" -ForegroundColor Cyan
Write-Host "  Output: $outputFile" -ForegroundColor Green

function Write-Section {
    param([string]$Name, [string]$Content)
    Add-Content -Path $outputFile -Value "\`r\`n[\${Name}]\`r\`n\${Content}\`r\`n[/\${Name}]" -Encoding UTF8
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

Write-Host "  [1/15] System Info..." -ForegroundColor DarkCyan
Write-Section "SYSTEM_INFO" (Get-WmiObject Win32_ComputerSystem | Select-Object Name, Domain, Manufacturer, Model | Format-List | Out-String)

Write-Host "  [2/15] Processes..." -ForegroundColor DarkCyan
$procs = Get-WmiObject Win32_Process | ForEach-Object {
    $sig = if ($_.ExecutablePath) { try { (Get-AuthenticodeSignature $_.ExecutablePath -EA SilentlyContinue).Status } catch {} }
    [PSCustomObject]@{ PID=$_.ProcessId; PPID=$_.ParentProcessId; Name=$_.Name; Path=$_.ExecutablePath; CmdLine=if($_.CommandLine){$_.CommandLine.Substring(0,[Math]::Min(100,$_.CommandLine.Length))}else{""}; User=$_.GetOwner().User; Signature=$sig }
} | Format-Table -AutoSize | Out-String
Write-Section "RUNNING_PROCESSES" $procs

Write-Host "  [3/15] Network..." -ForegroundColor DarkCyan
Write-Section "NETWORK_CONNECTIONS" @"
--- TCP Connections ---
$(Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Sort-Object State | Format-Table -AutoSize | Out-String)
--- UDP Endpoints ---
$(Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,@{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Format-Table -AutoSize | Out-String)
--- DNS Servers ---
$(Get-DnsClientServerAddress | Select-Object InterfaceAlias,ServerAddresses | Format-Table -AutoSize | Out-String)
--- Hosts File ---
$(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object {$_ -notmatch "^#" -and $_.Trim() -ne ""})
"@

Write-Host "  [4/15] DNS Cache..." -ForegroundColor DarkCyan
Write-Section "DNS_CACHE" (Get-DnsClientCache | Select-Object Entry,RecordName,RecordType,Status,TimeToLive | Format-Table -AutoSize | Out-String)

Write-Host "  [5/15] Scheduled Tasks..." -ForegroundColor DarkCyan
Write-Section "SCHEDULED_TASKS" (Get-ScheduledTask | ForEach-Object { [PSCustomObject]@{Name=$_.TaskName;Path=$_.TaskPath;State=$_.State;Author=$_.Author;Actions=(($_.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join " | ")} } | Format-Table -AutoSize | Out-String)

Write-Host "  [6/15] Services..." -ForegroundColor DarkCyan
Write-Section "SERVICES" (Get-WmiObject Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | Sort-Object State,Name | Format-Table -AutoSize | Out-String)

Write-Host "  [7/15] Persistence..." -ForegroundColor DarkCyan
$runKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
$regOut = foreach ($k in $runKeys) { "Key: $k"; if (Test-Path $k) { (Get-ItemProperty $k).PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object {"  $($_.Name) = $($_.Value)"} } }
$wmiF = Get-WMIObject -Namespace root\subscription -Class __EventFilter -EA SilentlyContinue
$wmiC = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -EA SilentlyContinue
$ifeo = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -EA SilentlyContinue | ForEach-Object { $d=(Get-ItemProperty $_.PSPath -Name Debugger -EA SilentlyContinue).Debugger; if($d){"  $($_.PSChildName) -> Debugger: $d"} }
Write-Section "PERSISTENCE" @"
--- Registry Run Keys ---
$($regOut -join "\`r\`n")
--- Winlogon ---
$(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -EA SilentlyContinue | Select-Object Shell,Userinit | Format-List | Out-String)
--- AppInit_DLLs ---
$((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -EA SilentlyContinue).AppInit_DLLs)
--- Image File Execution Options (Debuggers) ---
$(if ($ifeo) { $ifeo -join "\`r\`n" } else { "(none)" })
--- WMI Event Filters ---
$(if ($wmiF) { $wmiF | Select-Object Name,Query | Format-Table | Out-String } else { "(none)" })
--- WMI Event Consumers ---
$(if ($wmiC) { $wmiC | Select-Object Name,ScriptText,CommandLineTemplate | Format-Table | Out-String } else { "(none)" })
"@

Write-Host "  [8/15] Users..." -ForegroundColor DarkCyan
Write-Section "USER_ACCOUNTS" @"
--- Local Users ---
$(Get-LocalUser | Select-Object Name,Enabled,SID,LastLogon,PasswordLastSet | Format-Table -AutoSize | Out-String)
--- Administrators ---
$(Get-LocalGroupMember -Group "Administrators" -EA SilentlyContinue | Select-Object Name,SID,PrincipalSource | Format-Table | Out-String)
"@

Write-Host "  [9/15] Security Events..." -ForegroundColor DarkCyan
try {
    $evts = Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4624,4625,4648,4720,4726,4728,4732,4672);StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200 -EA Stop |
        Select-Object TimeCreated,Id,@{N='EventType';E={switch($_.Id){4624{'[OK] Successful Login'}4625{'[!!] FAILED Login'}4648{'[>>] Explicit Credentials'}4720{'[NEW] User Account Created'}4726{'[DEL] User Deleted'}4728{'[GRP] Added to Group'}4732{'[ADM] Added to Admins'}4672{'[PRIV] Special Privileges'}}}} |
        Format-Table -AutoSize | Out-String
    Write-Section "SECURITY_EVENTS" $evts
} catch { Write-Section "SECURITY_EVENTS" "Requires Administrator privileges.\`r\`nError: $_" }

Write-Host "  [10/15] PowerShell..." -ForegroundColor DarkCyan
$histFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
Write-Section "POWERSHELL_INFO" @"
--- Execution Policy ---
$(Get-ExecutionPolicy -List | Format-Table | Out-String)
--- History (last 200 commands) ---
$(if (Test-Path $histFile) { Get-Content $histFile -Tail 200 | Out-String } else { "(not found)" })
"@

Write-Host "  [11/15] Recent Files..." -ForegroundColor DarkCyan
$rf = foreach ($p in @($env:TEMP,"$env:SystemRoot\Temp","$env:USERPROFILE\Downloads",$env:APPDATA)) {
    if (Test-Path $p) { Get-ChildItem -Path $p -Recurse -File -EA SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select-Object FullName,LastWriteTime,@{N='KB';E={[math]::Round($_.Length/1KB,1)}} | Sort-Object LastWriteTime -Descending | Select-Object -First 20 }
}
Write-Section "RECENTLY_MODIFIED_FILES" ($rf | Format-Table -AutoSize | Out-String)

Write-Host "  [12/15] Software..." -ForegroundColor DarkCyan
Write-Section "INSTALLED_SOFTWARE" (@(Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue; Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue) | Where-Object {$_.DisplayName} | Select-Object DisplayName,Publisher,DisplayVersion,InstallDate | Sort-Object InstallDate -Descending | Format-Table -AutoSize | Out-String)

Write-Host "  [13/15] Firewall..." -ForegroundColor DarkCyan
Write-Section "FIREWALL_INFO" @"
--- Profiles ---
$(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table | Out-String)
--- Inbound Allow Rules ---
$(Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'} | Select-Object DisplayName,LocalPort,RemoteAddress,Enabled | Format-Table -AutoSize | Out-String)
"@

Write-Host "  [14/15] Defender..." -ForegroundColor DarkCyan
Write-Section "DEFENDER_STATUS" @"
--- Status ---
$(Get-MpComputerStatus -EA SilentlyContinue | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,AntivirusSignatureLastUpdated | Format-List | Out-String)
--- Recent Detections ---
$(Get-MpThreatDetection -EA SilentlyContinue | Select-Object -First 10 | Format-Table | Out-String)
"@

Write-Host "  [15/22] Suspicious Checks..." -ForegroundColor DarkCyan
$sp = Get-WmiObject Win32_Process | Where-Object { $_.ExecutablePath -match "\\temp\\|\\tmp\\|appdata\\local\\temp|\\windows\\temp" }
$sc = Get-NetTCPConnection | Where-Object { $_.RemotePort -in @(4444,4445,1337,31337,8888,9090,6667,6697,1234,5555,7777) -and $_.State -eq 'Established' }
Write-Section "SUSPICIOUS_INDICATORS" @"
--- Processes from suspicious paths ---
$(if ($sp) { $sp | Select-Object ProcessId,Name,ExecutablePath | Format-Table | Out-String } else { "(none)" })
--- Connections to high-risk ports ---
$(if ($sc) { $sc | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Format-Table | Out-String } else { "(none)" })
"@

Write-Host "  [16/22] Prefetch files..." -ForegroundColor DarkCyan
Write-Section "PREFETCH_FILES" (Get-ChildItem "$env:SystemRoot\Prefetch\*.pf" -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 50 | Select-Object Name,LastWriteTime | Format-Table -AutoSize | Out-String)

Write-Host "  [17/22] Shadow copies..." -ForegroundColor DarkCyan
Write-Section "SHADOW_COPIES" (vssadmin list shadows 2>&1 | Out-String)

Write-Host "  [18/22] RDP artifacts..." -ForegroundColor DarkCyan
$rdpE = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
Write-Section "RDP_ARTIFACTS" @"
--- RDP Status ---
$(if ($rdpE -eq 0) { "RDP ENABLED" } elseif ($rdpE -eq 1) { "RDP Disabled" } else { "Unknown" })
--- Client History ---
$((Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers" -EA SilentlyContinue | ForEach-Object { [PSCustomObject]@{Server=$_.PSChildName;User=(Get-ItemProperty $_.PSPath -Name UsernameHint -EA SilentlyContinue).UsernameHint} } | Format-Table | Out-String).Trim())
--- Active Sessions ---
$((query session 2>&1 | Out-String).Trim())
"@

Write-Host "  [19/22] USB history..." -ForegroundColor DarkCyan
Write-Section "USB_HISTORY" (Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -EA SilentlyContinue | ForEach-Object { $c=$_.PSChildName; Get-ChildItem $_.PSPath -EA SilentlyContinue | ForEach-Object { [PSCustomObject]@{Class=$c;InstanceID=$_.PSChildName;Name=(Get-ItemProperty $_.PSPath -Name FriendlyName -EA SilentlyContinue).FriendlyName} } } | Format-Table -AutoSize | Out-String)

Write-Host "  [20/22] Named pipes..." -ForegroundColor DarkCyan
Write-Section "NAMED_PIPES" (try { [System.IO.Directory]::GetFiles('\\.\pipe\') | Sort-Object | Out-String } catch { "(requires elevated context)" })

Write-Host "  [21/22] Persistence (extended)..." -ForegroundColor DarkCyan
$ppl2 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -EA SilentlyContinue).RunAsPPL
$wmiF2 = Get-WMIObject -Namespace root\subscription -Class __EventFilter -EA SilentlyContinue
$wmiC2 = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -EA SilentlyContinue
Write-Section "PERSISTENCE" @"
--- LSA Packages ---
$((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue | Select-Object SecurityPackages,AuthenticationPackages,NotificationPackages | Format-List | Out-String).Trim())
--- LSASS RunAsPPL ---
$(if ($ppl2 -eq 1) { "RunAsPPL = 1 (LSASS protected)" } else { "RunAsPPL = $ppl2 (LSASS NOT protected)" })
--- Boot Execute ---
$((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name BootExecute -EA SilentlyContinue).BootExecute -join ", ")
--- Network Provider Order ---
$((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" -EA SilentlyContinue).ProviderOrder)
--- WMI Filters ---
$(if ($wmiF2) { $wmiF2 | Select-Object Name,Query | Format-Table | Out-String } else { "(none)" })
--- WMI Consumers ---
$(if ($wmiC2) { $wmiC2 | Select-Object Name,ScriptText,CommandLineTemplate | Format-Table | Out-String } else { "(none)" })
"@

Write-Host "  [22/22] Browser artifacts..." -ForegroundColor DarkCyan
Write-Section "BROWSER_ARTIFACTS" @"
--- Downloads (last 30 days) ---
$((Get-ChildItem "$env:USERPROFILE\Downloads" -Recurse -File -EA SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-30)} | Select-Object Name,LastWriteTime,@{N='KB';E={[math]::Round($_.Length/1KB,1)}} | Sort-Object LastWriteTime -Descending | Select-Object -First 30 | Format-Table -AutoSize | Out-String).Trim())
--- Chrome Extensions ---
$((Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" -EA SilentlyContinue | Select-Object Name,LastWriteTime | Format-Table | Out-String).Trim())
--- Edge Extensions ---
$((Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" -EA SilentlyContinue | Select-Object Name,LastWriteTime | Format-Table | Out-String).Trim())
"@

Add-Content -Path $outputFile -Value "\`r\`n=== INVESTIGATION COMPLETE ===\`r\`nEndTime: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Encoding UTF8
Write-Host "\`n  [DONE] Report: $outputFile" -ForegroundColor Green
Write-Host "  Upload to SnowTrace Dashboard for analysis." -ForegroundColor Cyan
`;

const LIN_SCRIPT = `#!/usr/bin/env bash
# =============================================================================
#  SnowTrace - Linux Compromise Investigation Script
#  By Agent P | Version 1.0
#  Usage: sudo bash snowtrace_linux.sh
# =============================================================================
set -o pipefail
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
USERNAME_VAL=$(whoami 2>/dev/null || echo "unknown")
OUTPUT_FILE="snowtrace_linux_\${HOSTNAME_VAL}_$(date '+%Y%m%d_%H%M%S').txt"
DISTRO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)

C_CYAN="\\033[0;36m"; C_GREEN="\\033[0;32m"; C_YELLOW="\\033[0;33m"; C_RESET="\\033[0m"
log()  { echo -e "\${C_GREEN}  [>] \$1\${C_RESET}"; }
warn() { echo -e "\${C_YELLOW}  [!] \$1\${C_RESET}"; }

echo -e "\${C_CYAN}  SnowTrace | Linux Investigation | By Agent P\${C_RESET}"
[ \$EUID -ne 0 ] && warn "Not root - some checks will be incomplete. Re-run with sudo."
echo ""

ws() { local n="\$1"; shift; printf '\\n[%s]\\n%s\\n[/%s]\\n' "\$n" "\$*" "\$n" >> "\$OUTPUT_FILE"; }

cat > "\$OUTPUT_FILE" << HEOF
=== SNOWTRACE INVESTIGATION REPORT ===
Tool: SnowTrace by Agent P
Version: 1.0
Platform: Linux
Date: \$TIMESTAMP
Hostname: \$HOSTNAME_VAL
User: \$USERNAME_VAL
IsRoot: \$([ \$EUID -eq 0 ] && echo "Yes" || echo "No")
OS: \$DISTRO
Kernel: \$(uname -r)
Arch: \$(uname -m)
Uptime: \$(uptime -p 2>/dev/null || uptime)
HEOF

log "[1/17] System info..."
ws "SYSTEM_INFO" "\$(uname -a)
\$(cat /etc/os-release 2>/dev/null)
\$(free -h 2>/dev/null)
\$(df -h 2>/dev/null)
\$(uptime)"

log "[2/17] Running processes..."
ws "RUNNING_PROCESSES" "\$(ps aux --sort=-%cpu 2>/dev/null | head -60)
--- Process Tree ---
\$(pstree -p 2>/dev/null | head -60 || ps -ejH 2>/dev/null | head -40)
--- Procs from /tmp /dev/shm ---
\$(ls -la /proc/*/exe 2>/dev/null | grep -E 'tmp|shm' || echo '(none)')"

log "[3/17] Network connections..."
ws "NETWORK_CONNECTIONS" "--- Listening Ports ---
\$(ss -tlunp 2>/dev/null || netstat -tlunp 2>/dev/null)
--- Established Connections ---
\$(ss -tnp 2>/dev/null | grep ESTAB || netstat -tnp 2>/dev/null | grep ESTABLISHED)
--- All TCP/UDP ---
\$(ss -tunap 2>/dev/null | head -60)
--- Interfaces ---
\$(ip addr 2>/dev/null || ifconfig 2>/dev/null)
--- ARP ---
\$(arp -n 2>/dev/null || ip neigh 2>/dev/null)"

log "[4/17] Hosts & DNS..."
ws "HOSTS_FILE" "--- /etc/hosts ---
\$(grep -v '^#' /etc/hosts 2>/dev/null | grep -v '^\$')
--- /etc/resolv.conf ---
\$(cat /etc/resolv.conf 2>/dev/null)"

log "[5/17] Cron jobs..."
CRON_OUT="--- /etc/crontab ---
\$(cat /etc/crontab 2>/dev/null)
--- /etc/cron.d/ ---"
for f in /etc/cron.d/*; do [ -f "\$f" ] && CRON_OUT+="\$(printf '=== %s ===\\n' "\$f"; cat "\$f" 2>/dev/null)"; done
CRON_OUT+="
--- User crontabs ---"
while IFS=: read -r u _; do ct=\$(crontab -u "\$u" -l 2>/dev/null); [ -n "\$ct" ] && CRON_OUT+="\$(printf '--- %s ---\\n%s\\n' "\$u" "\$ct")"; done < /etc/passwd
ws "CRON_JOBS" "\$CRON_OUT"

log "[6/17] Services & startup..."
ws "STARTUP_SERVICES" "\$(systemctl list-units --type=service --state=running 2>/dev/null | head -50 || service --status-all 2>/dev/null | head -40)
--- Enabled at boot ---
\$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -40)
--- /etc/rc.local ---
\$(cat /etc/rc.local 2>/dev/null)
--- profile.d ---
\$(ls -la /etc/profile.d/ 2>/dev/null)"

log "[7/17] Users & sudoers..."
ws "USER_ACCOUNTS" "--- passwd ---
\$(cat /etc/passwd)
--- group ---
\$(cat /etc/group 2>/dev/null)
--- sudoers ---
\$(cat /etc/sudoers 2>/dev/null)
--- Users with shell ---
\$(grep -E '/bin/(bash|sh|zsh|fish|dash)$' /etc/passwd 2>/dev/null)
--- Empty passwords ---
\$(awk -F: '\$2 == \"\" {print \$1}' /etc/shadow 2>/dev/null || echo '(requires root)')"

log "[8/17] SSH keys..."
SSH_OUT="--- sshd_config ---
\$(cat /etc/ssh/sshd_config 2>/dev/null)
--- authorized_keys ---"
for h in /root /home/*; do k="\${h}/.ssh/authorized_keys"; [ -f "\$k" ] && SSH_OUT+="\$(printf '=== %s ===\\n' "\$k"; cat "\$k" 2>/dev/null)"; done
ws "SSH_KEYS" "\$SSH_OUT"

log "[9/17] Recently modified files..."
ws "RECENTLY_MODIFIED_FILES" "--- Modified <7d in key dirs ---
\$(find /etc /bin /sbin /usr/bin /usr/sbin /tmp /var/tmp /dev/shm -maxdepth 3 -type f -mtime -7 2>/dev/null | xargs ls -la 2>/dev/null | head -60)
--- /tmp ---
\$(ls -laR /tmp/ 2>/dev/null | head -40)
--- /dev/shm ---
\$(ls -laR /dev/shm/ 2>/dev/null | head -20)
--- Hidden files in home ---
\$(find /home /root -maxdepth 3 -name '.*' -type f 2>/dev/null | head -30)"

log "[10/17] SUID/SGID files..."
ws "SUID_SGID_FILES" "--- All SUID ---
\$(find / -perm -4000 -type f 2>/dev/null | grep -v -E '^(/proc|/sys)' | sort)
--- All SGID ---
\$(find / -perm -2000 -type f 2>/dev/null | grep -v -E '^(/proc|/sys)' | sort)
--- SUID outside standard ---
\$(find / -perm -4000 -type f 2>/dev/null | grep -v -E '^(/usr/(s?bin|lib)|/(s?bin)|/proc|/sys|/snap)' | sort)"

log "[11/17] World-writable files..."
ws "WORLD_WRITABLE" "--- System dirs ---
\$(find /etc /bin /sbin /usr/bin /usr/sbin -perm -002 -type f 2>/dev/null | sort)
--- World-writable dirs ---
\$(find / -perm -002 -type d 2>/dev/null | grep -v -E '^(/proc|/sys|/run|/tmp|/var/tmp|/dev)' | sort | head -20)"

log "[12/17] Auth logs..."
ws "AUTH_LOGS" "--- Recent auth log ---
\$(tail -300 /var/log/auth.log 2>/dev/null || tail -300 /var/log/secure 2>/dev/null || echo '(not found)')
--- Failed logins ---
\$(grep -iE 'failed|failure|invalid user' /var/log/auth.log /var/log/secure 2>/dev/null | tail -80)
--- Last logins ---
\$(last -w -n 40 2>/dev/null)
--- Now ---
\$(who 2>/dev/null; w 2>/dev/null)"

log "[13/17] Shell history..."
HIST_OUT="--- Root ---
\$(cat /root/.bash_history 2>/dev/null | tail -150 || echo '(not accessible)')
--- Users ---"
for h in /home/*; do
  u=\$(basename "\$h")
  for hf in .bash_history .zsh_history; do
    [ -f "\${h}/\${hf}" ] && HIST_OUT+="\$(printf '=== %s (%s) ===\\n' "\$u" "\$hf"; tail -100 "\${h}/\${hf}" 2>/dev/null)"
  done
done
ws "BASH_HISTORY" "\$HIST_OUT"

log "[14/17] Kernel modules..."
ws "KERNEL_MODULES" "\$(lsmod 2>/dev/null)"

log "[15/17] Packages..."
if command -v apt-get &>/dev/null; then
  ws "RECENTLY_INSTALLED" "\$(grep -E 'install|upgrade' /var/log/dpkg.log 2>/dev/null | tail -60)"
elif command -v rpm &>/dev/null; then
  ws "RECENTLY_INSTALLED" "\$(rpm -qa --queryformat '%{INSTALLTIME:date} %{NAME}\\n' 2>/dev/null | sort -r | head -50)"
fi

log "[16/17] Firewall rules..."
ws "FIREWALL_RULES" "--- iptables ---
\$(iptables -L -n -v 2>/dev/null || echo '(not available)')
--- UFW ---
\$(ufw status verbose 2>/dev/null || echo '(not installed)')"

log "[17/17] Suspicious indicators..."
ws "SUSPICIOUS_INDICATORS" "--- Procs from /tmp /dev/shm ---
\$(for pid in /proc/[0-9]*/exe; do t=\$(readlink "\$pid" 2>/dev/null); echo "\$t" | grep -qE '^/(tmp|dev/shm|var/tmp)' && printf 'PID %s -> %s\\n' "\$(echo \$pid | grep -o '[0-9]*')" "\$t"; done)
--- Suspicious history commands ---
\$(cat /root/.bash_history /home/*/.bash_history 2>/dev/null | grep -E '(nc |ncat|netcat|/dev/tcp/|bash -i|mkfifo|base64 -d|chmod [+]s|wget http|curl http)' | sort -u | head -30)
--- Cron with download/shell patterns ---
\$(cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -E '(wget|curl|nc |bash -i|/dev/tcp)' || echo '(none)')
--- World-writable in /etc /bin ---
\$(find /etc /bin /sbin /usr/bin /usr/sbin -perm -002 -type f 2>/dev/null | head -10 || echo '(none)')
--- SUID in unusual locations ---
\$(find / -perm -4000 -type f 2>/dev/null | grep -v -E '^(/usr/(s?bin|lib)|/(s?bin)|/proc|/sys|/snap)' | head -10 || echo '(none)')"

log "[18/27] ld.so.preload check..."
ws "LD_PRELOAD" "\$([ -f /etc/ld.so.preload ] && printf '[WARNING] File exists:\\n' && cat /etc/ld.so.preload || echo '(not present - normal)')
--- LD_PRELOAD in process environments ---
\$(for pid in /proc/[0-9]*/environ; do e=\$(cat "\$pid" 2>/dev/null | tr '\\0' '\\n'); echo "\$e" | grep -q LD_PRELOAD && printf 'PID %s (%s): %s\\n' "\$(echo \$pid|grep -o '[0-9]*')" "\$(cat \$(dirname \$pid)/comm 2>/dev/null)" "\$(echo "\$e"|grep LD_PRELOAD)"; done)"

log "[19/27] File capabilities..."
ws "FILE_CAPABILITIES" "--- All files with capabilities ---
\$(getcap -r / 2>/dev/null || echo '(getcap not available)')"

log "[20/27] PAM configuration..."
ws "PAM_CONFIG" "--- /etc/pam.d/ listing ---
\$(ls -la /etc/pam.d/ 2>/dev/null)
--- sshd ---
\$(cat /etc/pam.d/sshd 2>/dev/null)
--- Non-standard PAM modules ---
\$(grep -rh 'pam_' /etc/pam.d/ 2>/dev/null | grep -v '^#' | grep -vE 'pam_(unix|env|limits|systemd|deny|permit|keyinit|loginuid|nologin|securetty|tally2|faillock|motd|mail|lastlog|selinux|namespace|cap|xauth|pwquality|cracklib|sss|ldap|winbind|access|localuser|group|exec|script|time|listfile)' | sort -u)"

log "[21/27] Shell profiles..."
ws "SHELL_PROFILES" "\$(for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment; do [ -f \"\$f\" ] && printf '=== %s ===\\n' \"\$f\" && cat \"\$f\" 2>/dev/null; done)
--- User profiles ---
\$(for h in /root /home/*; do for f in .bashrc .bash_profile .profile .zshrc; do fp=\"\${h}/\${f}\"; [ -f \"\$fp\" ] && printf '=== %s ===\\n' \"\$fp\" && cat \"\$fp\" 2>/dev/null; done; done)
--- Suspicious patterns ---
\$(grep -rhnE '(wget|curl|nc |bash -i|/dev/tcp|base64|LD_PRELOAD|eval [^(]|exec [^-])' /etc/profile /etc/bash.bashrc /etc/bashrc /home/*/.bashrc /home/*/.bash_profile /root/.bashrc /root/.bash_profile 2>/dev/null | grep -v '^#' | sort -u)"

log "[22/27] Immutable files..."
ws "IMMUTABLE_FILES" "\$(for d in /etc /bin /sbin /usr/bin /usr/sbin /tmp /root; do [ -d \"\$d\" ] && lsattr \"\$d\" 2>/dev/null | awk '/^....i/{print \"IMMUTABLE: \" \$0}'; done)"

log "[23/27] Process memory maps..."
ws "PROC_MAPS" "--- Libraries from /tmp /dev/shm /var/tmp ---
\$(for m in /proc/[0-9]*/maps; do pid=\$(echo \$m|grep -o '[0-9]*'); comm=\$(cat /proc/\${pid}/comm 2>/dev/null); grep -qE '/(tmp|dev/shm|var/tmp)/' \"\$m\" 2>/dev/null && printf '=== PID %s (%s) ===\\n' \"\$pid\" \"\$comm\" && grep -E '/(tmp|dev/shm|var/tmp)/' \"\$m\" 2>/dev/null; done)
--- Deleted memory mappings ---
\$(for m in /proc/[0-9]*/maps; do pid=\$(echo \$m|grep -o '[0-9]*'); comm=\$(cat /proc/\${pid}/comm 2>/dev/null); grep -q '(deleted)' \"\$m\" 2>/dev/null && printf 'PID %s (%s) has deleted mappings\\n' \"\$pid\" \"\$comm\"; done | head -30)"

log "[24/27] XDG autostart..."
ws "XDG_AUTOSTART" "--- System (/etc/xdg/autostart/) ---
\$(ls -la /etc/xdg/autostart/ 2>/dev/null; for f in /etc/xdg/autostart/*.desktop; do [ -f \"\$f\" ] && printf '=== %s ===\\n' \"\$f\" && cat \"\$f\" 2>/dev/null; done)
--- User (~/.config/autostart/) ---
\$(for h in /root /home/*; do d=\"\${h}/.config/autostart\"; [ -d \"\$d\" ] && ls -la \"\$d\" 2>/dev/null && for f in \"\$d\"/*.desktop; do [ -f \"\$f\" ] && cat \"\$f\" 2>/dev/null; done; done)"

log "[25/27] Containers..."
ws "CONTAINER_ARTIFACTS" "\$([ -f /.dockerenv ] && echo 'RUNNING INSIDE DOCKER CONTAINER' || echo '(not a docker container)')
\$(cat /proc/1/cgroup 2>/dev/null | head -5)
--- Docker ---
\$(command -v docker &>/dev/null && docker ps -a 2>/dev/null || echo '(docker not installed)')"

log "[26/27] Package integrity..."
ws "PACKAGE_INTEGRITY" "\$(if command -v rpm &>/dev/null; then rpm -Va 2>/dev/null | grep -v '^.........' | head -50 || echo '(no tampering)'; elif command -v debsums &>/dev/null; then debsums -s 2>/dev/null | head -50 || echo '(no tampering)'; elif command -v dpkg &>/dev/null; then for p in bash coreutils openssh-server sudo login passwd; do r=\$(dpkg -V \"\$p\" 2>/dev/null); [ -n \"\$r\" ] && echo \"MODIFIED \$p: \$r\" || echo \"OK: \$p\"; done; else echo '(no integrity tool found)'; fi)"

log "[27/27] Crypto miner indicators..."
ws "CRYPTO_MINERS" "--- Miner process names ---
\$(ps aux 2>/dev/null | grep -iE '(xmrig|minerd|xmr-stak|cpuminer|kswapd0|cryptonight|stratum)' | grep -v grep || echo '(none)')
--- Mining pool connections (3333,4444,5555,7777,14444,45700) ---
\$(ss -tnp 2>/dev/null | awk '\$5 ~ /:3333\$|:4444\$|:5555\$|:7777\$|:14444\$|:45700\$/' || echo '(none)')
--- Top CPU consumers ---
\$(ps aux --sort=-%cpu 2>/dev/null | head -12)"

printf '\\n=== INVESTIGATION COMPLETE ===\\nEndTime: %s\\nOutputFile: %s\\n' "\$(date '+%Y-%m-%d %H:%M:%S')" "\$OUTPUT_FILE" >> "\$OUTPUT_FILE"
echo -e "\${C_GREEN}  [DONE] Report: \$OUTPUT_FILE\${C_RESET}"
echo -e "\${C_CYAN}  Upload to SnowTrace Dashboard for analysis.\${C_RESET}"
`;

function downloadScript(platform) {
  const isWin   = platform === 'windows';
  const content  = isWin ? WIN_SCRIPT : LIN_SCRIPT;
  const filename = isWin ? 'snowtrace_windows.ps1' : 'snowtrace_linux.sh';
  const type     = isWin ? 'text/plain' : 'text/x-sh';

  const blob = new Blob([content], { type });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
