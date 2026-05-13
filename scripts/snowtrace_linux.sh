#!/usr/bin/env bash
# =============================================================================
#  SnowTrace - Linux Compromise Investigation Script
#  By Agent P | Version 1.0
#
#  USAGE:
#    sudo bash snowtrace_linux.sh
#
#  For complete results, run as root or with sudo.
# =============================================================================

set -o pipefail

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
USERNAME_VAL=$(whoami 2>/dev/null || echo "unknown")
OUTPUT_FILE="snowtrace_linux_${HOSTNAME_VAL}_$(date '+%Y%m%d_%H%M%S').txt"

# ── Colors ────────────────────────────────────────────────────────────────────
C_CYAN="\033[0;36m"
C_GREEN="\033[0;32m"
C_YELLOW="\033[0;33m"
C_RED="\033[0;31m"
C_RESET="\033[0m"

log()  { echo -e "${C_GREEN}  [>] $1${C_RESET}"; }
warn() { echo -e "${C_YELLOW}  [!] $1${C_RESET}"; }
err()  { echo -e "${C_RED}  [X] $1${C_RESET}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${C_CYAN}  ███████╗███╗   ██╗ ██████╗ ██╗    ██╗████████╗██████╗  █████╗  ██████╗███████╗${C_RESET}"
echo -e "${C_CYAN}  ██╔════╝████╗  ██║██╔═══██╗██║    ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝${C_RESET}"
echo -e "${C_CYAN}  ███████╗██╔██╗ ██║██║   ██║██║ █╗ ██║   ██║   ██████╔╝███████║██║     █████╗  ${C_RESET}"
echo -e "${C_CYAN}  ╚════██║██║╚██╗██║██║   ██║██║███╗██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ${C_RESET}"
echo -e "${C_CYAN}  ███████║██║ ╚████║╚██████╔╝╚███╔███╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗${C_RESET}"
echo -e "${C_CYAN}  ╚══════╝╚═╝  ╚═══╝ ╚═════╝  ╚══╝╚══╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝${C_RESET}"
echo -e "${C_CYAN}  Linux Compromise Investigation | By Agent P${C_RESET}"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root - some checks will be limited. Re-run with sudo for full results."
fi

# ── Section writer ────────────────────────────────────────────────────────────
write_section() {
    local name="$1"
    shift
    local content="$*"
    printf '\n[%s]\n%s\n[/%s]\n' "$name" "$content" "$name" >> "$OUTPUT_FILE"
}

write_section_cmd() {
    local name="$1"
    shift
    local content
    content=$("$@" 2>/dev/null)
    printf '\n[%s]\n%s\n[/%s]\n' "$name" "$content" "$name" >> "$OUTPUT_FILE"
}

# ── Report Header ─────────────────────────────────────────────────────────────
DISTRO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "Unknown")
KERNEL=$(uname -r)

cat > "$OUTPUT_FILE" << EOF
=== SNOWTRACE INVESTIGATION REPORT ===
Tool: SnowTrace by Agent P
Version: 1.0
Platform: Linux
Date: $TIMESTAMP
Hostname: $HOSTNAME_VAL
User: $USERNAME_VAL
IsRoot: $([ $EUID -eq 0 ] && echo "Yes" || echo "No")
OS: $DISTRO
Kernel: $KERNEL
Arch: $(uname -m)
Uptime: $(uptime -p 2>/dev/null || uptime)
EOF

log "Output file: $OUTPUT_FILE"
echo ""

# ── 1. SYSTEM INFORMATION ─────────────────────────────────────────────────────
log "Collecting system information..."
SYS_INFO=$(cat << 'SEOF'
--- uname ---
SEOF
echo "$(uname -a)"
printf '\n--- OS Release ---\n'
cat /etc/os-release 2>/dev/null
printf '\n--- CPU Info ---\n'
grep -E "model name|cpu cores" /proc/cpuinfo 2>/dev/null | sort -u
printf '\n--- Memory ---\n'
free -h 2>/dev/null
printf '\n--- Disk Usage ---\n'
df -h 2>/dev/null
printf '\n--- Uptime/Load ---\n'
uptime
)
write_section "SYSTEM_INFO" "$SYS_INFO"

# ── 2. RUNNING PROCESSES ──────────────────────────────────────────────────────
log "Collecting running processes..."
PROC_DATA=$(
printf '--- All Processes (by CPU) ---\n'
ps aux --sort=-%cpu 2>/dev/null | head -60
printf '\n--- Process Tree ---\n'
pstree -p 2>/dev/null | head -80 || ps -ejH 2>/dev/null | head -60
printf '\n--- Processes from /tmp, /dev/shm, /var/tmp ---\n'
ls -la /proc/*/exe 2>/dev/null | grep -E "tmp|shm" || echo "(none)"
)
write_section "RUNNING_PROCESSES" "$PROC_DATA"

# ── 3. NETWORK CONNECTIONS ────────────────────────────────────────────────────
log "Collecting network connections..."
NET_DATA=$(
printf '--- Listening Ports ---\n'
ss -tlunp 2>/dev/null || netstat -tlunp 2>/dev/null
printf '\n--- Established Connections ---\n'
ss -tnp 2>/dev/null | grep ESTAB || netstat -tnp 2>/dev/null | grep ESTABLISHED
printf '\n--- All TCP/UDP ---\n'
ss -tunap 2>/dev/null | head -80 || netstat -tunap 2>/dev/null | head -80
printf '\n--- Network Interfaces ---\n'
ip addr 2>/dev/null || ifconfig 2>/dev/null
printf '\n--- Routing Table ---\n'
ip route 2>/dev/null || route -n 2>/dev/null
printf '\n--- ARP Cache ---\n'
arp -n 2>/dev/null || ip neigh 2>/dev/null
)
write_section "NETWORK_CONNECTIONS" "$NET_DATA"

# ── 4. DNS / HOSTS ────────────────────────────────────────────────────────────
log "Collecting DNS and hosts file..."
DNS_DATA=$(
printf '--- /etc/hosts ---\n'
grep -v '^#' /etc/hosts 2>/dev/null | grep -v '^$'
printf '\n--- /etc/resolv.conf ---\n'
cat /etc/resolv.conf 2>/dev/null
printf '\n--- /etc/nsswitch.conf ---\n'
cat /etc/nsswitch.conf 2>/dev/null
)
write_section "HOSTS_FILE" "$DNS_DATA"

# ── 5. CRON JOBS ──────────────────────────────────────────────────────────────
log "Collecting cron jobs..."
CRON_DATA=$(
printf '--- System /etc/crontab ---\n'
cat /etc/crontab 2>/dev/null

printf '\n--- /etc/cron.d/ ---\n'
for f in /etc/cron.d/*; do
    [ -f "$f" ] && printf "=== %s ===\n" "$f" && cat "$f" 2>/dev/null
done

printf '\n--- Cron Directories ---\n'
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    printf "=== %s ===\n" "$dir"
    ls -la "$dir" 2>/dev/null
done

printf '\n--- User Crontabs ---\n'
while IFS=: read -r user _; do
    ctab=$(crontab -u "$user" -l 2>/dev/null)
    [ -n "$ctab" ] && printf '--- %s ---\n%s\n' "$user" "$ctab"
done < /etc/passwd

printf '\n--- Anacron ---\n'
cat /etc/anacrontab 2>/dev/null
)
write_section "CRON_JOBS" "$CRON_DATA"

# ── 6. SYSTEMD SERVICES / STARTUP ─────────────────────────────────────────────
log "Collecting startup services..."
SVC_DATA=$(
printf '--- Running Services ---\n'
systemctl list-units --type=service --state=running 2>/dev/null | head -60 || service --status-all 2>/dev/null | head -60

printf '\n--- Enabled Services (Boot) ---\n'
systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -60

printf '\n--- Systemd Timers ---\n'
systemctl list-timers --all 2>/dev/null | head -30

printf '\n--- /etc/rc.local ---\n'
cat /etc/rc.local 2>/dev/null

printf '\n--- /etc/profile.d/ ---\n'
ls -la /etc/profile.d/ 2>/dev/null
for f in /etc/profile.d/*.sh; do
    [ -f "$f" ] && printf '=== %s ===\n' "$f" && cat "$f" 2>/dev/null
done

printf '\n--- /etc/init.d/ ---\n'
ls -la /etc/init.d/ 2>/dev/null
)
write_section "STARTUP_SERVICES" "$SVC_DATA"

# ── 7. USER ACCOUNTS ──────────────────────────────────────────────────────────
log "Collecting user account information..."
USER_DATA=$(
printf '--- /etc/passwd (non-system) ---\n'
awk -F: '$3 >= 1000 || $3 == 0 {print}' /etc/passwd 2>/dev/null

printf '\n--- All passwd entries ---\n'
cat /etc/passwd 2>/dev/null

printf '\n--- /etc/group ---\n'
cat /etc/group 2>/dev/null

printf '\n--- Sudoers ---\n'
cat /etc/sudoers 2>/dev/null
ls -la /etc/sudoers.d/ 2>/dev/null
for f in /etc/sudoers.d/*; do
    [ -f "$f" ] && printf '=== %s ===\n' "$f" && cat "$f" 2>/dev/null
done

printf '\n--- Users with login shell ---\n'
grep -E '/bin/(bash|sh|zsh|fish|dash)$' /etc/passwd 2>/dev/null

printf '\n--- Users with empty password ---\n'
awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null || echo "(requires root)"

printf '\n--- Recently created accounts (last 30 days) ---\n'
find /home -maxdepth 1 -type d -newer /tmp -mtime -30 2>/dev/null
)
write_section "USER_ACCOUNTS" "$USER_DATA"

# ── 8. SSH KEYS & CONFIG ──────────────────────────────────────────────────────
log "Collecting SSH configuration and keys..."
SSH_DATA=$(
printf '--- SSH Server Config ---\n'
cat /etc/ssh/sshd_config 2>/dev/null

printf '\n--- SSH Host Keys ---\n'
ls -la /etc/ssh/ssh_host_* 2>/dev/null

printf '\n--- Authorized Keys ---\n'
for home in /root /home/*; do
    keyfile="${home}/.ssh/authorized_keys"
    [ -f "$keyfile" ] && printf '=== %s ===\n' "$keyfile" && cat "$keyfile" 2>/dev/null
done

printf '\n--- Known Hosts ---\n'
for home in /root /home/*; do
    kh="${home}/.ssh/known_hosts"
    [ -f "$kh" ] && printf '=== %s ===\n' "$kh" && cat "$kh" 2>/dev/null | head -30
done

printf '\n--- ~/.ssh permissions ---\n'
for home in /root /home/*; do
    [ -d "${home}/.ssh" ] && ls -la "${home}/.ssh/" 2>/dev/null
done
)
write_section "SSH_KEYS" "$SSH_DATA"

# ── 9. RECENTLY MODIFIED FILES ────────────────────────────────────────────────
log "Collecting recently modified files (last 7 days)..."
RECENT_DATA=$(
printf '--- Files modified in last 7 days (key dirs) ---\n'
find /etc /bin /sbin /usr/bin /usr/sbin /tmp /var/tmp /dev/shm \
    -maxdepth 3 -type f -newer /tmp -mtime -7 2>/dev/null |
    xargs ls -la 2>/dev/null | head -80

printf '\n--- Files in /tmp ---\n'
ls -laR /tmp/ 2>/dev/null | head -50

printf '\n--- Files in /var/tmp ---\n'
ls -laR /var/tmp/ 2>/dev/null | head -30

printf '\n--- Files in /dev/shm ---\n'
ls -laR /dev/shm/ 2>/dev/null | head -20

printf '\n--- Hidden files in home directories ---\n'
find /home /root -maxdepth 3 -name ".*" -type f 2>/dev/null | head -40
)
write_section "RECENTLY_MODIFIED_FILES" "$RECENT_DATA"

# ── 10. SUID / SGID FILES ─────────────────────────────────────────────────────
log "Collecting SUID/SGID files..."
SUID_DATA=$(
printf '--- SUID Files ---\n'
find / -perm -4000 -type f 2>/dev/null | grep -v -E '^(/proc|/sys)' | sort

printf '\n--- SGID Files ---\n'
find / -perm -2000 -type f 2>/dev/null | grep -v -E '^(/proc|/sys)' | sort

printf '\n--- SUID outside standard paths ---\n'
find / -perm -4000 -type f 2>/dev/null | grep -v -E '^(/usr/(s?bin|lib)|/(s?bin)|/proc|/sys)' | sort
)
write_section "SUID_SGID_FILES" "$SUID_DATA"

# ── 11. WORLD-WRITABLE FILES ──────────────────────────────────────────────────
log "Collecting world-writable files..."
WW_DATA=$(
printf '--- World-Writable Files in System Dirs ---\n'
find /etc /bin /sbin /usr/bin /usr/sbin /lib /lib64 \
    -perm -002 -type f 2>/dev/null | sort

printf '\n--- World-Writable Directories ---\n'
find / -perm -002 -type d 2>/dev/null | grep -v -E '^(/proc|/sys|/run|/tmp|/var/tmp|/dev)' | sort | head -30
)
write_section "WORLD_WRITABLE" "$WW_DATA"

# ── 12. AUTHENTICATION LOGS ───────────────────────────────────────────────────
log "Collecting authentication logs..."
AUTH_DATA=$(
printf '--- Recent Auth Log (last 300 lines) ---\n'
if [ -f /var/log/auth.log ]; then
    tail -300 /var/log/auth.log 2>/dev/null
elif [ -f /var/log/secure ]; then
    tail -300 /var/log/secure 2>/dev/null
else
    echo "(no auth log found - may require journalctl)"
fi

printf '\n--- Recent Failed Logins ---\n'
if [ -f /var/log/auth.log ]; then
    grep -i "failed\|failure\|invalid user\|illegal user" /var/log/auth.log 2>/dev/null | tail -100
elif [ -f /var/log/secure ]; then
    grep -i "failed\|failure\|invalid user" /var/log/secure 2>/dev/null | tail -100
fi

printf '\n--- Last Logins ---\n'
last -w -n 50 2>/dev/null

printf '\n--- Failed Login Attempts (lastb) ---\n'
lastb -n 30 2>/dev/null || echo "(requires root)"

printf '\n--- Who is logged in now ---\n'
who 2>/dev/null
w 2>/dev/null
)
write_section "AUTH_LOGS" "$AUTH_DATA"

# ── 13. BASH HISTORY ──────────────────────────────────────────────────────────
log "Collecting bash/shell history..."
HIST_DATA=$(
printf '--- Root bash history ---\n'
cat /root/.bash_history 2>/dev/null | tail -200 || echo "(not accessible)"

printf '\n--- User histories ---\n'
for home in /home/*; do
    user=$(basename "$home")
    for histfile in ".bash_history" ".zsh_history" ".sh_history"; do
        if [ -f "${home}/${histfile}" ]; then
            printf '=== %s (%s) ===\n' "$user" "$histfile"
            tail -150 "${home}/${histfile}" 2>/dev/null
        fi
    done
done
)
write_section "BASH_HISTORY" "$HIST_DATA"

# ── 14. KERNEL MODULES ────────────────────────────────────────────────────────
log "Collecting kernel modules..."
MOD_DATA=$(
printf '--- Loaded Modules ---\n'
lsmod 2>/dev/null

printf '\n--- Unsigned/Unknown Modules ---\n'
for mod in $(lsmod 2>/dev/null | awk 'NR>1 {print $1}'); do
    info=$(modinfo "$mod" 2>/dev/null | grep -E "^(filename|signer|sig_key):")
    echo "=== $mod ==="
    echo "$info"
done | head -100
)
write_section "KERNEL_MODULES" "$MOD_DATA"

# ── 15. RECENTLY INSTALLED PACKAGES ───────────────────────────────────────────
log "Collecting package installation history..."
PKG_DATA=$(
if command -v apt-get &>/dev/null; then
    printf '--- APT Package History (last 7 days) ---\n'
    grep -E "install|upgrade" /var/log/dpkg.log 2>/dev/null | tail -80
    printf '\n--- Manually Installed Packages ---\n'
    apt-mark showmanual 2>/dev/null | head -50
elif command -v rpm &>/dev/null; then
    printf '--- RPM Install History ---\n'
    rpm -qa --queryformat '%{INSTALLTIME:date} %{NAME}-%{VERSION}\n' 2>/dev/null | sort -r | head -60
elif command -v pacman &>/dev/null; then
    printf '--- Pacman Install History ---\n'
    grep "installed\|upgraded" /var/log/pacman.log 2>/dev/null | tail -60
fi
)
write_section "RECENTLY_INSTALLED" "$PKG_DATA"

# ── 16. SUSPICIOUS INDICATORS SUMMARY ────────────────────────────────────────
log "Running suspicious indicator checks..."
SUSP_DATA=$(
printf '--- Processes running from /tmp, /dev/shm, /var/tmp ---\n'
for pid in /proc/[0-9]*/exe; do
    target=$(readlink "$pid" 2>/dev/null)
    if echo "$target" | grep -qE '^/(tmp|dev/shm|var/tmp)'; then
        printf 'PID %s -> %s\n' "$(echo $pid | grep -o '[0-9]*')" "$target"
    fi
done

printf '\n--- Suspicious commands in bash history ---\n'
cat /root/.bash_history /home/*/.bash_history 2>/dev/null |
    grep -E "(nc |ncat |netcat |/dev/tcp/|base64 -d|bash -i|mkfifo|python.*import socket|perl.*socket|wget.*(http|ftp)|curl.*(http|ftp)|chmod \+s|chmod 4755|scp -[^-])" 2>/dev/null |
    sort -u | head -40

printf '\n--- Cron entries with download/reverse shell patterns ---\n'
cat /etc/crontab /etc/cron.d/* 2>/dev/null
for u in $(cut -f1 -d: /etc/passwd); do crontab -u "$u" -l 2>/dev/null; done |
    grep -E "(wget|curl|nc |bash -i|/dev/tcp)" 2>/dev/null || echo "(none)"

printf '\n--- World-writable files in sensitive dirs ---\n'
find /etc /bin /sbin /usr/bin /usr/sbin -perm -002 -type f 2>/dev/null | head -20 || echo "(none)"

printf '\n--- SUID files in unusual locations ---\n'
find / -perm -4000 -type f 2>/dev/null |
    grep -v -E '^(/usr/(s?bin|lib|libexec)|/(s?bin)|/proc|/sys|/snap)' | head -20 || echo "(none)"

printf '\n--- Listening on unusual ports (>1024, not common web) ---\n'
ss -tlnp 2>/dev/null | awk '$4 !~ /:22$|:80$|:443$|:25$|:53$|:110$|:143$/' | grep -v "State" | head -20

printf '\n--- Rootkit indicators ---\n'
if command -v rkhunter &>/dev/null; then
    rkhunter --check --sk --nocolors 2>/dev/null | tail -30
elif command -v chkrootkit &>/dev/null; then
    chkrootkit 2>/dev/null | grep -v "not infected" | head -30
else
    echo "(rkhunter/chkrootkit not installed)"
fi
)
write_section "SUSPICIOUS_INDICATORS" "$SUSP_DATA"

# ── 17. IPTABLES / FIREWALL ───────────────────────────────────────────────────
log "Collecting firewall rules..."
FW_DATA=$(
printf '--- iptables ---\n'
iptables -L -n -v 2>/dev/null || echo "(not available)"

printf '\n--- ip6tables ---\n'
ip6tables -L -n -v 2>/dev/null || echo "(not available)"

printf '\n--- nftables ---\n'
nft list ruleset 2>/dev/null || echo "(not available)"

printf '\n--- UFW Status ---\n'
ufw status verbose 2>/dev/null || echo "(ufw not installed)"

printf '\n--- firewalld ---\n'
firewall-cmd --list-all 2>/dev/null || echo "(firewalld not installed)"
)
write_section "FIREWALL_RULES" "$FW_DATA"

# ── 18. LD_PRELOAD / ld.so.preload ───────────────────────────────────────────
log "Checking ld.so.preload and LD_PRELOAD..."
LDPRELOAD_DATA=$(
printf '--- /etc/ld.so.preload ---\n'
if [ -f /etc/ld.so.preload ]; then
    printf '[WARNING] File exists - contents:\n'
    cat /etc/ld.so.preload 2>/dev/null
else
    echo "(not present - normal)"
fi

printf '\n--- LD_PRELOAD in live process environments ---\n'
for pid in /proc/[0-9]*/environ; do
    env_data=$(cat "$pid" 2>/dev/null | tr '\0' '\n')
    if echo "$env_data" | grep -q "LD_PRELOAD"; then
        proc_name=$(cat "$(dirname $pid)/comm" 2>/dev/null)
        pid_num=$(echo "$pid" | grep -o '[0-9]*')
        printf 'PID %s (%s): %s\n' "$pid_num" "$proc_name" "$(echo "$env_data" | grep LD_PRELOAD)"
    fi
done

printf '\n--- /etc/ld.so.conf.d/ ---\n'
ls -la /etc/ld.so.conf.d/ 2>/dev/null
cat /etc/ld.so.conf 2>/dev/null
)
write_section "LD_PRELOAD" "$LDPRELOAD_DATA"

# ── 19. FILE CAPABILITIES ─────────────────────────────────────────────────────
log "Checking file capabilities..."
CAP_DATA=$(
printf '--- All files with capabilities set ---\n'
getcap -r / 2>/dev/null || echo "(getcap not available)"

printf '\n--- Capabilities on common interpreter targets ---\n'
for f in /usr/bin/python3 /usr/bin/python2 /usr/bin/perl /usr/bin/ruby /usr/bin/vim \
          /usr/bin/nmap /usr/bin/tcpdump /usr/bin/node /usr/bin/php; do
    [ -f "$f" ] && cap=$(getcap "$f" 2>/dev/null) && [ -n "$cap" ] && echo "$cap"
done
)
write_section "FILE_CAPABILITIES" "$CAP_DATA"

# ── 20. PAM CONFIGURATION ─────────────────────────────────────────────────────
log "Checking PAM configuration..."
PAM_DATA=$(
printf '--- /etc/pam.d/ listing ---\n'
ls -la /etc/pam.d/ 2>/dev/null

for svc in sshd sudo su login passwd; do
    f="/etc/pam.d/${svc}"
    [ -f "$f" ] && printf '\n--- %s ---\n' "$f" && cat "$f" 2>/dev/null
done

printf '\n--- Non-standard PAM modules in use ---\n'
grep -rh "pam_" /etc/pam.d/ 2>/dev/null | grep -v "^#" | \
    grep -vE "pam_(unix|env|limits|systemd|deny|permit|keyinit|loginuid|nologin|securetty|tally2|faillock|motd|mail|lastlog|selinux|namespace|cap|xauth|pwquality|cracklib|sss|ldap|winbind|access|localuser|group|exec|script|time|listfile)" | \
    sort -u
)
write_section "PAM_CONFIG" "$PAM_DATA"

# ── 21. SHELL PROFILES ────────────────────────────────────────────────────────
log "Checking shell profile files for tampering..."
PROFILE_DATA=$(
for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment; do
    [ -f "$f" ] && printf '=== %s ===\n' "$f" && cat "$f" 2>/dev/null
done

printf '\n--- User shell profiles ---\n'
for home in /root /home/*; do
    for f in .bashrc .bash_profile .profile .zshrc .bash_logout; do
        fp="${home}/${f}"
        [ -f "$fp" ] && printf '=== %s ===\n' "$fp" && cat "$fp" 2>/dev/null
    done
done

printf '\n--- Suspicious patterns in profiles (download/exec) ---\n'
grep -rhnE "(wget|curl|nc |bash -i|/dev/tcp|base64|LD_PRELOAD|eval [^(]|exec [^-])" \
    /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment \
    /root/.bashrc /root/.bash_profile /root/.profile \
    /home/*/.bashrc /home/*/.bash_profile /home/*/.profile 2>/dev/null | \
    grep -v "^#" | sort -u
)
write_section "SHELL_PROFILES" "$PROFILE_DATA"

# ── 22. IMMUTABLE FILES ───────────────────────────────────────────────────────
log "Checking for immutable files (chattr +i)..."
IMMUTABLE_DATA=$(
for dir in /etc /bin /sbin /usr/bin /usr/sbin /tmp /var/www /root; do
    [ -d "$dir" ] && lsattr "$dir" 2>/dev/null | awk '/^....i/{print "IMMUTABLE: " $0}'
done

printf '\n--- Immutable files in home dirs ---\n'
for home in /root /home/*; do
    [ -d "$home" ] && lsattr "$home" 2>/dev/null | awk '/^....i/{print "IMMUTABLE: " $0}'
done
)
if echo "$IMMUTABLE_DATA" | grep -q "IMMUTABLE"; then
    write_section "IMMUTABLE_FILES" "$IMMUTABLE_DATA"
else
    write_section "IMMUTABLE_FILES" "(no immutable files found in checked directories)"
fi

# ── 23. MEMORY-MAPPED LIBRARIES ───────────────────────────────────────────────
log "Scanning process memory maps for libraries from suspicious paths..."
MAPS_DATA=$(
printf '--- Libraries loaded from /tmp /dev/shm /var/tmp ---\n'
for maps_file in /proc/[0-9]*/maps; do
    pid=$(echo "$maps_file" | grep -o '[0-9]*')
    comm=$(cat "/proc/${pid}/comm" 2>/dev/null)
    if grep -qE "/(tmp|dev/shm|var/tmp)/" "$maps_file" 2>/dev/null; then
        printf '=== PID %s (%s) ===\n' "$pid" "$comm"
        grep -E "/(tmp|dev/shm|var/tmp)/" "$maps_file" 2>/dev/null
    fi
done

printf '\n--- Processes with deleted mapped executables ---\n'
for maps_file in /proc/[0-9]*/maps; do
    pid=$(echo "$maps_file" | grep -o '[0-9]*')
    comm=$(cat "/proc/${pid}/comm" 2>/dev/null)
    if grep -q "(deleted)" "$maps_file" 2>/dev/null; then
        printf 'PID %s (%s):\n' "$pid" "$comm"
        grep "(deleted)" "$maps_file" 2>/dev/null | head -2
    fi
done | head -60
)
write_section "PROC_MAPS" "$MAPS_DATA"

# ── 24. XDG AUTOSTART ─────────────────────────────────────────────────────────
log "Checking XDG autostart entries..."
XDG_DATA=$(
printf '--- System autostart (/etc/xdg/autostart/) ---\n'
ls -la /etc/xdg/autostart/ 2>/dev/null || echo "(not found)"
for f in /etc/xdg/autostart/*.desktop; do
    [ -f "$f" ] && printf '=== %s ===\n' "$f" && cat "$f" 2>/dev/null
done

printf '\n--- User autostart (~/.config/autostart/) ---\n'
for home in /root /home/*; do
    adir="${home}/.config/autostart"
    if [ -d "$adir" ]; then
        printf '=== %s ===\n' "$adir"
        ls -la "$adir" 2>/dev/null
        for f in "$adir"/*.desktop; do
            [ -f "$f" ] && cat "$f" 2>/dev/null
        done
    fi
done
)
write_section "XDG_AUTOSTART" "$XDG_DATA"

# ── 25. CONTAINER ARTIFACTS ───────────────────────────────────────────────────
log "Checking container/Docker artifacts..."
CONTAINER_DATA=$(
printf '--- Running inside container check ---\n'
[ -f /.dockerenv ] && echo "RUNNING INSIDE DOCKER CONTAINER" || echo "(not a docker container)"
cat /proc/1/cgroup 2>/dev/null | head -5

if command -v docker &>/dev/null; then
    printf '\n--- Docker containers ---\n'
    docker ps -a 2>/dev/null
    printf '\n--- Docker images ---\n'
    docker images 2>/dev/null
    printf '\n--- Docker networks ---\n'
    docker network ls 2>/dev/null
else
    printf '\n(docker not installed)\n'
fi

printf '\n--- Namespace listing (PID 1) ---\n'
ls -la /proc/1/ns/ 2>/dev/null
)
write_section "CONTAINER_ARTIFACTS" "$CONTAINER_DATA"

# ── 26. PACKAGE INTEGRITY ─────────────────────────────────────────────────────
log "Checking package integrity..."
PKG_INTEGRITY_DATA=$(
if command -v rpm &>/dev/null; then
    printf '--- RPM verification (modified files) ---\n'
    rpm -Va 2>/dev/null | grep -v "^........." | head -50 || echo "(no tampering detected)"
elif command -v debsums &>/dev/null; then
    printf '--- debsums verification ---\n'
    debsums -s 2>/dev/null | head -50 || echo "(no tampering detected)"
elif command -v dpkg &>/dev/null; then
    printf '--- dpkg verify (key packages) ---\n'
    for pkg in bash coreutils openssh-server sudo login passwd; do
        result=$(dpkg -V "$pkg" 2>/dev/null)
        if [ -n "$result" ]; then echo "MODIFIED $pkg: $result"; else echo "OK: $pkg"; fi
    done
else
    echo "(no package integrity tool found)"
fi
)
write_section "PACKAGE_INTEGRITY" "$PKG_INTEGRITY_DATA"

# ── 27. CRYPTO MINER INDICATORS ───────────────────────────────────────────────
log "Checking for crypto miner indicators..."
MINER_DATA=$(
printf '--- Known miner process names ---\n'
ps aux 2>/dev/null | grep -iE "(xmrig|minerd|xmr-stak|cpuminer|kswapd0|ksoftirqd[0-9]|kthreadd[0-9]+|cryptonight|stratum)" | grep -v grep || echo "(none found)"

printf '\n--- Connections to mining pool ports (3333,4444,5555,7777,14444,45700) ---\n'
ss -tnp 2>/dev/null | awk '$5 ~ /:3333$|:4444$|:5555$|:7777$|:14444$|:45700$/' || \
netstat -tnp 2>/dev/null | awk '$4 ~ /:3333$|:4444$|:5555$|:7777$|:14444$|:45700$/'
echo "(checked)"

printf '\n--- Top 10 CPU-consuming processes ---\n'
ps aux --sort=-%cpu 2>/dev/null | head -12

printf '\n--- Miner config files in common drop dirs ---\n'
find /tmp /var/tmp /dev/shm /root /home -maxdepth 4 \
    \( -name "xmrig*" -o -name "minerd*" -o -name "cpuminer*" -o -name "*.conf" \) \
    -newer /tmp -mtime -30 -type f 2>/dev/null | \
    xargs grep -l "pool\|stratum\|wallet\|worker" 2>/dev/null | head -10 || echo "(none found)"
)
write_section "CRYPTO_MINERS" "$MINER_DATA"

# ── Finalize ──────────────────────────────────────────────────────────────────
END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
printf '\n=== INVESTIGATION COMPLETE ===\nEndTime: %s\nOutputFile: %s\n' "$END_TIME" "$OUTPUT_FILE" >> "$OUTPUT_FILE"

echo ""
echo -e "${C_GREEN}  ┌────────────────────────────────────────────────────────────────┐${C_RESET}"
echo -e "${C_GREEN}  │  SnowTrace Investigation COMPLETE                              │${C_RESET}"
echo -e "${C_GREEN}  │  Report: ${OUTPUT_FILE}${C_RESET}"
echo -e "${C_GREEN}  │  Upload this file to the SnowTrace Dashboard for analysis      │${C_RESET}"
echo -e "${C_GREEN}  └────────────────────────────────────────────────────────────────┘${C_RESET}"
echo ""
