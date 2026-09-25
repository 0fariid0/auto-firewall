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

# SSH lockout protection. The exact rule that fixed the previous release is
# applied before any deny rule or firewall activation.
add_ssh_port 22

if command -v sshd >/dev/null 2>&1; then
    while IFS= read -r port; do
        add_ssh_port "$port"
    done < <(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' || true)
fi

if [[ -n ${SSH_CONNECTION:-} ]]; then
    current_ssh_port=''
    read -r _ _ _ current_ssh_port <<< "$SSH_CONNECTION" || true
    add_ssh_port "$current_ssh_port"
fi

while IFS= read -r port; do
    add_ssh_port "$port"
done < <(ss -H -lntp 2>/dev/null | awk '/sshd/ {address=$4; sub(/^.*:/, "", address); if (address ~ /^[0-9]+$/) print address}' || true)

# Optional manual ports, separated by commas or spaces.
if [[ -n ${AUTO_FIREWALL_TCP_PORTS:-} ]]; then
    for port in ${AUTO_FIREWALL_TCP_PORTS//,/ }; do
        add_tcp_port "$port"
    done
fi

echo "Opening TCP ports: $(printf '%s\n' "${!tcp_ports[@]}" | sort -n | paste -sd, -)"
for port in $(printf '%s\n' "${!tcp_ports[@]}" | sort -n); do
    if [[ $port != 22 ]]; then
        ensure_rule allow "$port/tcp" comment 'auto-firewall'
    fi
done

# Recreate the tunnel permissions after a UFW reset. GRE uses protocol 47;
# forwarded traffic also needs an explicit UFW route rule per interface.
for config_dir in /etc/gre-tunnels /etc/greplus-tunnels /etc/wgtun-tunnels; do
    [[ -d $config_dir ]] || continue
    for config in "$config_dir"/tunnel-*.conf; do
        [[ -f $config ]] || continue
        filename=${config##*/}
        [[ $filename =~ ^tunnel-([0-9]{1,3})\.conf$ ]] || continue
        id=${BASH_REMATCH[1]}
        case $config_dir in
            /etc/gre-tunnels) ifc="gre$id" ;;
            /etc/greplus-tunnels) ifc="greplus$id" ;;
            *) ifc="wgtun$id" ;;
        esac
        if [[ $config_dir == /etc/wgtun-tunnels ]]; then
            wg_port=$(awk -F= '$1=="LOCAL_WG_PORT" {gsub(/^[\047\"]|[\047\"]$/, "", $2); print $2; exit}' "$config")
            if [[ $wg_port =~ ^[0-9]+$ ]] && (( wg_port >= 1 && wg_port <= 65535 )); then
                ensure_rule allow "$wg_port/udp"
            fi
        else
            local_ip=$(awk -F= '$1=="LOCAL_PUBLIC_IP" {gsub(/^[\047\"]|[\047\"]$/, "", $2); print $2; exit}' "$config")
            remote_ip=$(awk -F= '$1=="REMOTE_PUBLIC_IP" {gsub(/^[\047\"]|[\047\"]$/, "", $2); print $2; exit}' "$config")
            if [[ $local_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && $remote_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                ensure_rule allow proto gre from "$remote_ip" to "$local_ip"
            fi
        fi
        ensure_rule allow in on "$ifc"
        ensure_rule route allow in on "$ifc"
        ensure_rule route allow out on "$ifc"
    done
done

blocked_destinations=(
    23.235.40.0/24
    43.249.75.0/24
    94.46.144.0/24
    103.66.28.0/24
    103.66.30.0/24
    103.228.104.0/24
    103.244.50.0/24
    103.245.223.0/24
    151.139.2.0/24
    151.139.4.0/24
    151.139.7.0/24
    151.139.104.0/24
    151.139.0.0/16
    157.52.82.125
    192.16.2.7
    217.22.29.98
    25.20.151.169
    192.0.0.0/24
    25.0.0.0/8
    25.208.254.0/32
    200.0.0.0/8
    102.0.0.0/8
    198.18.0.0/15
    198.51.100.0/24
    203.0.113.0/24
    224.0.0.0/3
    255.255.255.0/32
    0.0.0.0/8
    192.88.99.0/24
)

forward_source_blocks=(
    200.0.0.0/8
    102.0.0.0/8
    198.18.0.0/15
    198.51.100.0/24
    203.0.113.0/24
    224.0.0.0/3
    255.255.255.255/32
    192.0.0.0/24
    192.0.2.0/24
    0.0.0.0/8
    192.88.99.0/24
)

# Remove obsolete private-range blocks from earlier versions so GRE's 10.x
# inner addresses are not denied after UFW is enabled.
for subnet in 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 127.0.0.0/8 127.0.53.53 192.168.0.0/16 172.16.0.0/12; do
    if rule_exists deny out to "$subnet"; then ufw delete deny out to "$subnet" >/dev/null; fi
    if rule_exists route deny from "$subnet"; then ufw route delete deny from "$subnet" >/dev/null; fi
done
if rule_exists allow 222/tcp; then ufw delete allow 222/tcp >/dev/null; fi

for destination in "${blocked_destinations[@]}"; do
    ensure_rule deny out to "$destination" comment 'auto-firewall'
done

# UFW route rules are persistent. The previous direct iptables rules were
# duplicated on every run and 'iptables-save' did not actually save them.
for source in "${forward_source_blocks[@]}"; do
    ensure_rule route deny from "$source" comment 'auto-firewall'
done

# Remove exact legacy rules that older releases appended directly to FORWARD.
# The replacement rules above remain managed and persisted by UFW.
legacy_direct_source_blocks=(
    "${forward_source_blocks[@]}"
    10.0.0.0/8
    100.64.0.0/10
    169.254.0.0/16
    127.0.0.0/8
    127.0.53.53
    192.168.0.0/16
    172.16.0.0/12
    198.18.140.0/24
    102.230.9.0/24
    102.233.71.0/24
)

for source in "${legacy_direct_source_blocks[@]}"; do
    while iptables -C FORWARD -s "$source" -j DROP >/dev/null 2>&1; do
        iptables -D FORWARD -s "$source" -j DROP
    done
done

if ufw status | grep -q '^Status: inactive'; then
    ufw --force enable
fi

echo
echo "Firewall applied. SSH is allowed on TCP port(s): $(printf '%s\n' "${!ssh_ports[@]}" | sort -n | paste -sd, -)"
ufw status verbose
