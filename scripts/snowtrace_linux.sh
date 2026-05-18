#!/usr/bin/env bash
# =============================================================================
#  SnowTrace - Linux Compromise Investigation Script
#  By Agent P | Version 1.0
#  Usage: sudo bash snowtrace_linux.sh
# =============================================================================
set -o pipefail
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
USERNAME_VAL=$(whoami 2>/dev/null || echo "unknown")
OUTPUT_FILE="snowtrace_linux_${HOSTNAME_VAL}_$(date '+%Y%m%d_%H%M%S').txt"
DISTRO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)

C_CYAN="\033[0;36m"; C_GREEN="\033[0;32m"; C_YELLOW="\033[0;33m"; C_RESET="\033[0m"
log()  { echo -e "${C_GREEN}  [>] $1${C_RESET}"; }
warn() { echo -e "${C_YELLOW}  [!] $1${C_RESET}"; }

echo -e "${C_CYAN}  SnowTrace | Linux Investigation | By Agent P${C_RESET}"
[ $EUID -ne 0 ] && warn "Not root - some checks will be incomplete. Re-run with sudo."
echo ""

ws() { local n="$1"; shift; printf '\n[%s]\n%s\n[/%s]\n' "$n" "$*" "$n" >> "$OUTPUT_FILE"; }

cat > "$OUTPUT_FILE" << HEOF
=== SNOWTRACE INVESTIGATION REPORT ===
Tool: SnowTrace by Agent P
Version: 1.0
Platform: Linux
Date: $TIMESTAMP
Hostname: $HOSTNAME_VAL
User: $USERNAME_VAL
IsRoot: $([ $EUID -eq 0 ] && echo "Yes" || echo "No")
OS: $DISTRO
Kernel: $(uname -r)
Arch: $(uname -m)
Uptime: $(uptime -p 2>/dev/null || uptime)
HEOF

log "[1/27] System info..."
ws "SYSTEM_INFO" "$(uname -a)
$(cat /etc/os-release 2>/dev/null)
$(free -h 2>/dev/null)
$(df -h 2>/dev/null)
$(uptime)"

log "[2/27] Running processes..."
ws "RUNNING_PROCESSES" "$(ps aux --sort=-%cpu 2>/dev/null | head -60)
--- Process Tree ---
$(pstree -p 2>/dev/null | head -60 || ps -ejH 2>/dev/null | head -40)
--- Procs from /tmp /dev/shm ---
$(ls -la /proc/*/exe 2>/dev/null | grep -E 'tmp|shm' || echo '(none)')"

log "[3/27] Network connections..."
ws "NETWORK_CONNECTIONS" "--- Listening Ports ---
$(ss -tlunp 2>/dev/null || netstat -tlunp 2>/dev/null)
--- Established Connections ---
$(ss -tnp 2>/dev/null | grep ESTAB || netstat -tnp 2>/dev/null | grep ESTABLISHED)
--- All TCP/UDP ---
$(ss -tunap 2>/dev/null | head -60)
--- Interfaces ---
$(ip addr 2>/dev/null || ifconfig 2>/dev/null)
--- ARP ---
$(arp -n 2>/dev/null || ip neigh 2>/dev/null)"

log "[4/27] Hosts & DNS..."
ws "HOSTS_FILE" "--- /etc/hosts ---
$(grep -v '^#' /etc/hosts 2>/dev/null | grep -v '^$')
--- /etc/resolv.conf ---
$(cat /etc/resolv.conf 2>/dev/null)"

log "[5/27] Cron jobs..."
CRON_OUT="--- /etc/crontab ---
$(cat /etc/crontab 2>/dev/null)
--- /etc/cron.d/ ---"
for f in /etc/cron.d/*; do [ -f "$f" ] && CRON_OUT+="$(printf '=== %s ===\n' "$f"; cat "$f" 2>/dev/null)"; done
CRON_OUT+="
--- User crontabs ---"
while IFS=: read -r u _; do ct=$(crontab -u "$u" -l 2>/dev/null); [ -n "$ct" ] && CRON_OUT+="$(printf '--- %s ---\n%s\n' "$u" "$ct")"; done < /etc/passwd
ws "CRON_JOBS" "$CRON_OUT"

log "[6/27] Services & startup..."
ws "STARTUP_SERVICES" "$(systemctl list-units --type=service --state=running 2>/dev/null | head -50 || service --status-all 2>/dev/null | head -40)
--- Enabled at boot ---
$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -40)
--- /etc/rc.local ---
$(cat /etc/rc.local 2>/dev/null)
--- profile.d ---
$(ls -la /etc/profile.d/ 2>/dev/null)"

log "[7/27] Users & sudoers..."
ws "USER_ACCOUNTS" "--- passwd ---
$(cat /etc/passwd)
--- group ---
$(cat /etc/group 2>/dev/null)
--- sudoers ---
$(cat /etc/sudoers 2>/dev/null)
--- Users with shell ---
$(grep -E '/bin/(bash|sh|zsh|fish|dash)$' /etc/passwd 2>/dev/null)
--- Empty passwords ---
$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null || echo '(requires root)')"

log "[8/27] SSH keys..."
SSH_OUT="--- sshd_config ---
$(cat /etc/ssh/sshd_config 2>/dev/null)
--- authorized_keys ---"
for h in /root /home/*; do k="${h}/.ssh/authorized_keys"; [ -f "$k" ] && SSH_OUT+="$(printf '=== %s ===\n' "$k"; cat "$k" 2>/dev/null)"; done
ws "SSH_KEYS" "$SSH_OUT"

log "[9/27] Recently modified files..."
ws "RECENTLY_MODIFIED_FILES" "--- Modified <7d in key dirs ---
$(find /etc /bin /sbin /usr/bin /usr/sbin /tmp /var/tmp /dev/shm -maxdepth 3 -type f -mtime -7 2>/dev/null | xargs ls -la 2>/dev/null | head -60)
--- /tmp ---
$(ls -laR /tmp/ 2>/dev/null | head -40)
--- /dev/shm ---
$(ls -laR /dev/shm/ 2>/dev/null | head -20)
--- Hidden files in home ---
$(find /home /root -maxdepth 3 -name '.*' -type f 2>/dev/null | head -30)"

log "[10/27] SUID/SGID files..."
ws "SUID_SGID_FILES" "--- All SUID ---
$(find / -perm -4000 -type f 2>/dev/null | grep -v -E '^(/proc|/sys)' | sort)
--- All SGID ---
$(find / -perm -2000 -type f 2>/dev/null | grep -v -E '^(/proc|/sys)' | sort)
--- SUID outside standard ---
$(find / -perm -4000 -type f 2>/dev/null | grep -v -E '^(/usr/(s?bin|lib)|/(s?bin)|/proc|/sys|/snap)' | sort)"

log "[11/27] World-writable files..."
ws "WORLD_WRITABLE" "--- System dirs ---
$(find /etc /bin /sbin /usr/bin /usr/sbin -perm -002 -type f 2>/dev/null | sort)
--- World-writable dirs ---
$(find / -perm -002 -type d 2>/dev/null | grep -v -E '^(/proc|/sys|/run|/tmp|/var/tmp|/dev)' | sort | head -20)"

log "[12/27] Auth logs..."
ws "AUTH_LOGS" "--- Recent auth log ---
$(tail -300 /var/log/auth.log 2>/dev/null || tail -300 /var/log/secure 2>/dev/null || echo '(not found)')
--- Failed logins ---
$(grep -iE 'failed|failure|invalid user' /var/log/auth.log /var/log/secure 2>/dev/null | tail -80)
--- Last logins ---
$(last -w -n 40 2>/dev/null)
--- Now ---
$(who 2>/dev/null; w 2>/dev/null)"

log "[13/27] Shell history..."
HIST_OUT="--- Root ---
$(cat /root/.bash_history 2>/dev/null | tail -150 || echo '(not accessible)')
--- Users ---"
for h in /home/*; do
  u=$(basename "$h")
  for hf in .bash_history .zsh_history; do
    [ -f "${h}/${hf}" ] && HIST_OUT+="$(printf '=== %s (%s) ===\n' "$u" "$hf"; tail -100 "${h}/${hf}" 2>/dev/null)"
  done
done
ws "BASH_HISTORY" "$HIST_OUT"

log "[14/27] Kernel modules..."
ws "KERNEL_MODULES" "$(lsmod 2>/dev/null)"

log "[15/27] Packages..."
if command -v apt-get &>/dev/null; then
  ws "RECENTLY_INSTALLED" "$(grep -E 'install|upgrade' /var/log/dpkg.log 2>/dev/null | tail -60)"
elif command -v rpm &>/dev/null; then
  ws "RECENTLY_INSTALLED" "$(rpm -qa --queryformat '%{INSTALLTIME:date} %{NAME}\n' 2>/dev/null | sort -r | head -50)"
fi

log "[16/27] Firewall rules..."
ws "FIREWALL_RULES" "--- iptables ---
$(iptables -L -n -v 2>/dev/null || echo '(not available)')
--- UFW ---
$(ufw status verbose 2>/dev/null || echo '(not installed)')"

log "[17/27] Suspicious indicators..."
ws "SUSPICIOUS_INDICATORS" "--- Procs from /tmp /dev/shm ---
$(for pid in /proc/[0-9]*/exe; do t=$(readlink "$pid" 2>/dev/null); echo "$t" | grep -qE '^/(tmp|dev/shm|var/tmp)' && printf 'PID %s -> %s\n' "$(echo $pid | grep -o '[0-9]*')" "$t"; done)
--- Suspicious history commands ---
$(cat /root/.bash_history /home/*/.bash_history 2>/dev/null | grep -E '(nc |ncat|netcat|/dev/tcp/|bash -i|mkfifo|base64 -d|chmod [+]s|wget http|curl http)' | sort -u | head -30)
--- Cron with download/shell patterns ---
$(cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -E '(wget|curl|nc |bash -i|/dev/tcp)' || echo '(none)')
--- World-writable in /etc /bin ---
$(find /etc /bin /sbin /usr/bin /usr/sbin -perm -002 -type f 2>/dev/null | head -10 || echo '(none)')
--- SUID in unusual locations ---
$(find / -perm -4000 -type f 2>/dev/null | grep -v -E '^(/usr/(s?bin|lib)|/(s?bin)|/proc|/sys|/snap)' | head -10 || echo '(none)')"

log "[18/27] ld.so.preload check..."
ws "LD_PRELOAD" "$([ -f /etc/ld.so.preload ] && printf '[WARNING] File exists:\n' && cat /etc/ld.so.preload || echo '(not present - normal)')
--- LD_PRELOAD in process environments ---
$(for pid in /proc/[0-9]*/environ; do e=$(cat "$pid" 2>/dev/null | tr '\0' '\n'); echo "$e" | grep -q LD_PRELOAD && printf 'PID %s (%s): %s\n' "$(echo $pid|grep -o '[0-9]*')" "$(cat $(dirname $pid)/comm 2>/dev/null)" "$(echo "$e"|grep LD_PRELOAD)"; done)"

log "[19/27] File capabilities..."
ws "FILE_CAPABILITIES" "--- All files with capabilities ---
$(getcap -r / 2>/dev/null || echo '(getcap not available)')"

log "[20/27] PAM configuration..."
ws "PAM_CONFIG" "--- /etc/pam.d/ listing ---
$(ls -la /etc/pam.d/ 2>/dev/null)
--- sshd ---
$(cat /etc/pam.d/sshd 2>/dev/null)
--- Non-standard PAM modules ---
$(grep -rh 'pam_' /etc/pam.d/ 2>/dev/null | grep -v '^#' | grep -vE 'pam_(unix|env|limits|systemd|deny|permit|keyinit|loginuid|nologin|securetty|tally2|faillock|motd|mail|lastlog|selinux|namespace|cap|xauth|pwquality|cracklib|sss|ldap|winbind|access|localuser|group|exec|script|time|listfile)' | sort -u)"

log "[21/27] Shell profiles..."
ws "SHELL_PROFILES" "$(for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment; do [ -f "$f" ] && printf '=== %s ===\n' "$f" && cat "$f" 2>/dev/null; done)
--- User profiles ---
$(for h in /root /home/*; do for f in .bashrc .bash_profile .profile .zshrc; do fp="${h}/${f}"; [ -f "$fp" ] && printf '=== %s ===\n' "$fp" && cat "$fp" 2>/dev/null; done; done)
--- Suspicious patterns ---
$(grep -rhnE '(wget|curl|nc |bash -i|/dev/tcp|base64|LD_PRELOAD|eval [^(]|exec [^-])' /etc/profile /etc/bash.bashrc /etc/bashrc /home/*/.bashrc /home/*/.bash_profile /root/.bashrc /root/.bash_profile 2>/dev/null | grep -v '^#' | sort -u)"

log "[22/27] Immutable files..."
ws "IMMUTABLE_FILES" "$(for d in /etc /bin /sbin /usr/bin /usr/sbin /tmp /root; do [ -d "$d" ] && lsattr "$d" 2>/dev/null | awk '/^....i/{print "IMMUTABLE: " $0}'; done)"

log "[23/27] Process memory maps..."
ws "PROC_MAPS" "--- Libraries from /tmp /dev/shm /var/tmp ---
$(for m in /proc/[0-9]*/maps; do pid=$(echo $m|grep -o '[0-9]*'); comm=$(cat /proc/${pid}/comm 2>/dev/null); grep -qE '/(tmp|dev/shm|var/tmp)/' "$m" 2>/dev/null && printf '=== PID %s (%s) ===\n' "$pid" "$comm" && grep -E '/(tmp|dev/shm|var/tmp)/' "$m" 2>/dev/null; done)
--- Deleted memory mappings ---
$(for m in /proc/[0-9]*/maps; do pid=$(echo $m|grep -o '[0-9]*'); comm=$(cat /proc/${pid}/comm 2>/dev/null); grep -q '(deleted)' "$m" 2>/dev/null && printf 'PID %s (%s) has deleted mappings\n' "$pid" "$comm"; done | head -30)"

log "[24/27] XDG autostart..."
ws "XDG_AUTOSTART" "--- System (/etc/xdg/autostart/) ---
$(ls -la /etc/xdg/autostart/ 2>/dev/null; for f in /etc/xdg/autostart/*.desktop; do [ -f "$f" ] && printf '=== %s ===\n' "$f" && cat "$f" 2>/dev/null; done)
--- User (~/.config/autostart/) ---
$(for h in /root /home/*; do d="${h}/.config/autostart"; [ -d "$d" ] && ls -la "$d" 2>/dev/null && for f in "$d"/*.desktop; do [ -f "$f" ] && cat "$f" 2>/dev/null; done; done)"

log "[25/27] Containers..."
ws "CONTAINER_ARTIFACTS" "$([ -f /.dockerenv ] && echo 'RUNNING INSIDE DOCKER CONTAINER' || echo '(not a docker container)')
$(cat /proc/1/cgroup 2>/dev/null | head -5)
--- Docker ---
$(command -v docker &>/dev/null && docker ps -a 2>/dev/null || echo '(docker not installed)')"

log "[26/27] Package integrity..."
ws "PACKAGE_INTEGRITY" "$(if command -v rpm &>/dev/null; then rpm -Va 2>/dev/null | grep -v '^.........' | head -50 || echo '(no tampering)'; elif command -v debsums &>/dev/null; then debsums -s 2>/dev/null | head -50 || echo '(no tampering)'; elif command -v dpkg &>/dev/null; then for p in bash coreutils openssh-server sudo login passwd; do r=$(dpkg -V "$p" 2>/dev/null); [ -n "$r" ] && echo "MODIFIED $p: $r" || echo "OK: $p"; done; else echo '(no integrity tool found)'; fi)"

log "[27/27] Crypto miner indicators..."
ws "CRYPTO_MINERS" "--- Miner process names ---
$(ps aux 2>/dev/null | grep -iE '(xmrig|minerd|xmr-stak|cpuminer|kswapd0|cryptonight|stratum)' | grep -v grep || echo '(none)')
--- Mining pool connections (3333,4444,5555,7777,14444,45700) ---
$(ss -tnp 2>/dev/null | awk '$5 ~ /:3333$|:4444$|:5555$|:7777$|:14444$|:45700$/' || echo '(none)')
--- Top CPU consumers ---
$(ps aux --sort=-%cpu 2>/dev/null | head -12)"

printf '\n=== INVESTIGATION COMPLETE ===\nEndTime: %s\nOutputFile: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$OUTPUT_FILE" >> "$OUTPUT_FILE"
echo -e "${C_GREEN}  [DONE] Report: $OUTPUT_FILE${C_RESET}"
echo -e "${C_CYAN}  Upload to SnowTrace Dashboard for analysis.${C_RESET}"
