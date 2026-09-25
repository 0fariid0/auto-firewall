#!/usr/bin/env bash

set -Eeuo pipefail

if (( EUID != 0 )); then
    echo "Error: this script must be run as root." >&2
    exit 1
fi

for command_name in ufw ss iptables awk sort; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Error: required command '$command_name' was not found." >&2
        exit 1
    fi
done

# Only one invocation may edit UFW at a time. GRE-TUN uses the same lock.
if command -v flock >/dev/null 2>&1; then
    exec 9>/run/gretun-ufw.lock
    flock -w 60 9 || { echo 'UFW is busy; retry later.' >&2; exit 1; }
fi

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

# This exact rule fixed SSH access in the previous release. Apply it first,
# before port discovery, deny rules, or enabling UFW.
ufw allow 22/tcp

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

listening_udp_ports() {
    ss -H -lnu | awk '{address=$4; sub(/^.*:/, "", address); if (address ~ /^[0-9]+$/) print address}'
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
        ufw allow "$port/tcp" comment 'auto-firewall'
    fi
done

# UDP listeners (including public WireGuard endpoints) must survive UFW enable.
while IFS= read -r port; do
    [[ $port =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || continue
    ufw allow "$port/udp" comment 'auto-firewall'
done < <(listening_udp_ports | sort -nu)

# GRE is IP protocol 47, not a TCP/UDP port. Read only the public endpoint
# addresses written by GRE-TUN; do not execute tunnel configuration files.
for config_dir in /etc/gre-tunnels /etc/greplus-tunnels; do
    [[ -d $config_dir ]] || continue
    for config in "$config_dir"/*.conf; do
        [[ -f $config ]] || continue
        local_ip=$(awk -F= '$1=="LOCAL_PUBLIC_IP" {gsub(/^[\047\"]|[\047\"]$/, "", $2); print $2; exit}' "$config")
        remote_ip=$(awk -F= '$1=="REMOTE_PUBLIC_IP" {gsub(/^[\047\"]|[\047\"]$/, "", $2); print $2; exit}' "$config")
        if [[ $local_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && $remote_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ufw allow proto gre from "$remote_ip" to "$local_ip" comment 'auto-firewall'
        fi
    done
done

# Interface rules take care of both locally delivered and routed VPN traffic.
# Include saved tunnels even if their interfaces have not appeared yet.
for config_dir in /etc/gre-tunnels /etc/greplus-tunnels /etc/wgtun-tunnels; do
    [[ -d $config_dir ]] || continue
    for config in "$config_dir"/*.conf; do
        [[ -f $config ]] || continue
        name=${config##*/}; id=${name//[^0-9]/}
        [[ $id =~ ^[0-9]{1,3}$ ]] || continue
        case $config_dir in
            /etc/gre-tunnels) ifc="gre$id" ;;
            /etc/greplus-tunnels) ifc="greplus$id" ;;
            *) ifc="wgtun$id" ;;
        esac
        ufw allow in on "$ifc" comment 'auto-firewall'
        ufw route allow in on "$ifc" comment 'auto-firewall'
        ufw route allow out on "$ifc" comment 'auto-firewall'
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

# Older releases denied these private ranges, including GRE/GREPLUS's 10.x
# inner addresses. Remove those exact stale rules before applying new rules.
for subnet in 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 127.0.0.0/8 127.0.53.53 192.168.0.0/16 172.16.0.0/12; do
    ufw delete deny out to "$subnet" >/dev/null 2>&1 || true
    ufw route delete deny from "$subnet" >/dev/null 2>&1 || true
done
ufw delete allow 222/tcp >/dev/null 2>&1 || true

for destination in "${blocked_destinations[@]}"; do
    ufw deny out to "$destination" comment 'auto-firewall'
done

# UFW route rules are persistent. The previous direct iptables rules were
# duplicated on every run and 'iptables-save' did not actually save them.
for source in "${forward_source_blocks[@]}"; do
    ufw route deny from "$source" comment 'auto-firewall'
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

ufw --force enable

echo
echo "Firewall applied. SSH is allowed on TCP port(s): $(printf '%s\n' "${!ssh_ports[@]}" | sort -n | paste -sd, -)"
ufw status verbose
