
    
  
#!/usr/bin/env bash

set -Eeuo pipefail

if (( EUID != 0 )); then
    echo "Error: this script must be run as root." >&2
    exit 1
fi

for command_name in ufw ss iptables awk sort flock; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Error: required command '$command_name' was not found." >&2
        exit 1
    fi
done

# Prevent overlapping runs from editing UFW at the same time.
exec 9>/run/gretun-ufw.lock
flock -w 60 9 || { echo "Error: another firewall update is running." >&2; exit 1; }

# Remove the ping service and files created by older releases.
if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now ping_service.service >/dev/null 2>&1 || true
fi

if [[ -f /etc/systemd/system/ping_service.service ]]; then
    rm -f /etc/systemd/system/ping_service.service
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi
fi

rm -f /root/ping_files/ping_iran.sh /root/ping_files/ping_kharej.sh
rmdir /root/ping_files 2>/dev/null || true

# Read once so repeated runs do not send already saved rules back to UFW.
saved_rules="$(ufw show added)" || exit 1
rule_exists() {
    local expected="ufw $*" line
    while IFS= read -r line; do
        [[ $line == "$expected" || $line == "$expected comment "* ]] && return 0
    done <<< "$saved_rules"
    return 1
}
ensure_rule() {
    local arg
    local -a without_comment=()
    for arg in "$@"; do
        [[ $arg == comment ]] && break
        without_comment+=("$arg")
    done
    rule_exists "${without_comment[@]}" && return 0
    ufw "$@" >/dev/null
    saved_rules+=$'\n'"ufw ${without_comment[*]}"
}

# TCP/22 must precede any older DENY. Preserve the same SSH allow on reruns.
first_rule="$(awk '/^ufw / {print; exit}' <<< "$saved_rules")"
if [[ $first_rule != 'ufw allow 22/tcp' && $first_rule != 'ufw allow 22/tcp comment '* ]]; then
    if rule_exists allow 22/tcp; then ufw delete allow 22/tcp >/dev/null; fi
    ufw insert 1 allow 22/tcp >/dev/null
    saved_rules=$'ufw allow 22/tcp\n'"$saved_rules"
fi

declare -A tcp_ports=()
declare -A ssh_ports=()

add_tcp_port() {
    local port=$1

    [[ $port =~ ^[0-9]+$ ]] || return 0
    (( port >= 1 && port <= 65535 )) || return 0
    [[ $port == 222 ]] && return 0

    tcp_ports["$port"]=1
}

add_ssh_port() {
    local port=$1

    [[ $port =~ ^[0-9]+$ ]] || return 0
    (( port >= 1 && port <= 65535 )) || return 0
    [[ $port == 222 ]] && return 0

    ssh_ports["$port"]=1
    add_tcp_port "$port"
}

listening_tcp_ports() {
    ss -H -lnt | awk '{address=$4; sub(/^.*:/, "", address); if (address ~ /^[0-9]+$/) print address}'
}

while IFS= read -r port; do
    add_tcp_port "$port"
done < <(listening_tcp_ports)

