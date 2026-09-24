#!/usr/bin/env bash

set -Eeuo pipefail

if (( EUID != 0 )); then
    echo "Error: this script must be run as root." >&2
    exit 1
fi

for command_name in ufw ss iptables ip6tables iptables-save ip6tables-save awk sort paste date; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Error: required command '$command_name' was not found." >&2
        exit 1
    fi
done

# These are the private ranges used by GRE, WireGuard and GREPLUS.
# Extra ranges can be supplied with:
# AUTO_FIREWALL_TUNNEL_RANGES="10.40.0.0/16 10.50.0.0/16"
tunnel_ranges=(
    10.10.0.0/16
    10.20.0.0/16
    10.30.0.0/16
)

if [[ -n ${AUTO_FIREWALL_TUNNEL_RANGES:-} ]]; then
    for network in ${AUTO_FIREWALL_TUNNEL_RANGES//,/ }; do
        tunnel_ranges+=("$network")
    done
fi

# Back up the current firewall state before changing anything.
backup_dir="/root/auto-firewall-backups"
backup_stamp=$(date +%Y%m%d-%H%M%S)
mkdir -p "$backup_dir"
ufw status numbered > "$backup_dir/ufw-$backup_stamp.txt" 2>&1 || true
iptables-save > "$backup_dir/iptables-$backup_stamp.rules"
ip6tables-save > "$backup_dir/ip6tables-$backup_stamp.rules"
chmod 600 "$backup_dir"/* 2>/dev/null || true

# Remove the obsolete ping service from older releases.
if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now ping_service.service >/dev/null 2>&1 || true
fi

if [[ -f /etc/systemd/system/ping_service.service ]]; then
    rm -f /etc/systemd/system/ping_service.service
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload
fi

rm -f /root/ping_files/ping_iran.sh /root/ping_files/ping_kharej.sh
rmdir /root/ping_files 2>/dev/null || true

# Delete only rules created by this script on an earlier run. Rules belonging
# to Xray, Docker, GRE, WireGuard and other applications are left untouched.
mapfile -t managed_rule_numbers < <(
    ufw status numbered 2>/dev/null |
    awk '/auto-firewall/ {line=$0; sub(/^\[[[:space:]]*/, "", line); split(line, fields, "]"); print fields[1]}' |
    sort -rn
)

for rule_number in "${managed_rule_numbers[@]}"; do
    [[ $rule_number =~ ^[0-9]+$ ]] || continue
    ufw --force delete "$rule_number" >/dev/null
done

declare -A tcp_ports=()
declare -A udp_ports=()
declare -A ssh_ports=()

add_port() {
    local protocol=$1
    local port=$2

    [[ $port =~ ^[0-9]+$ ]] || return 0
    (( port >= 1 && port <= 65535 )) || return 0

    if [[ $protocol == tcp ]]; then
        tcp_ports["$port"]=1
    else
        udp_ports["$port"]=1
    fi
}

add_ssh_port() {
    local port=$1
    [[ $port =~ ^[0-9]+$ ]] || return 0
    (( port >= 1 && port <= 65535 )) || return 0
    ssh_ports["$port"]=1
    add_port tcp "$port"
}

# List only sockets reachable from outside. Services bound to loopback or a
# private tunnel address must not become public just because they are listening.
list_public_listening_ports() {
    local protocol=$1
    local ss_option

    [[ $protocol == tcp ]] && ss_option=-lnt || ss_option=-lnu

    ss -H "$ss_option" | awk '
        {
            endpoint=$4
            address=endpoint
            port=endpoint
            sub(/:[^:]*$/, "", address)
            sub(/^.*:/, "", port)
            gsub(/^\[/, "", address)
            gsub(/\]$/, "", address)

            if (address ~ /^127\./ || address == "::1") next
            if (address ~ /^10\./ || address ~ /^192\.168\./) next
            if (address ~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./) next
            if (port ~ /^[0-9]+$/) print port
        }
    '
}

# Always keep SSH, HTTP and HTTPS accessible. Telegram webhook traffic reaches
# Apache through HTTPS on port 443.
add_ssh_port 22
add_port tcp 80
add_port tcp 443

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
    add_port tcp "$port"
done < <(list_public_listening_ports tcp)

while IFS= read -r port; do
    add_port udp "$port"
done < <(list_public_listening_ports udp)

# Optional manually supplied ports, separated by commas or spaces.
if [[ -n ${AUTO_FIREWALL_TCP_PORTS:-} ]]; then
    for port in ${AUTO_FIREWALL_TCP_PORTS//,/ }; do
        add_port tcp "$port"
    done
fi

if [[ -n ${AUTO_FIREWALL_UDP_PORTS:-} ]]; then
    for port in ${AUTO_FIREWALL_UDP_PORTS//,/ }; do
        add_port udp "$port"
    done
fi

# Use conservative defaults. Routed traffic is denied unless it belongs to a
# declared tunnel range below.
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed

for port in $(printf '%s\n' "${!ssh_ports[@]}" | sort -n); do
    ufw allow "$port/tcp" comment 'auto-firewall SSH'
done

for port in $(printf '%s\n' "${!tcp_ports[@]}" | sort -n); do
    [[ -n ${ssh_ports[$port]+x} ]] && continue
    ufw allow "$port/tcp" comment 'auto-firewall TCP'
done

for port in $(printf '%s\n' "${!udp_ports[@]}" | sort -n); do
    ufw allow "$port/udp" comment 'auto-firewall UDP'
done

# Permit GRE itself. If peers are known, pass them in AUTO_FIREWALL_GRE_PEERS
# to limit GRE to those public IPs; otherwise GRE is allowed from any peer.
if [[ -n ${AUTO_FIREWALL_GRE_PEERS:-} ]]; then
    for peer in ${AUTO_FIREWALL_GRE_PEERS//,/ }; do
        ufw allow from "$peer" proto gre comment 'auto-firewall GRE peer'
    done
else
    ufw allow proto gre comment 'auto-firewall GRE'
fi

# Preserve the three tunnel families in both host-output and routed traffic.
for network in "${tunnel_ranges[@]}"; do
    ufw allow out to "$network" comment 'auto-firewall tunnel output'
    ufw route allow from "$network" comment 'auto-firewall tunnel source'
    ufw route allow to "$network" comment 'auto-firewall tunnel destination'
done

# Real SMTP port blocking. This prevents common spam abuse; unlike blocking the
# IP range 25.0.0.0/8, these rules actually target mail submission ports.
for smtp_port in 25 465 587; do
    ufw deny out "$smtp_port/tcp" comment 'auto-firewall SMTP abuse'
done

# Safe IPv4 special-use destinations. Private ranges are intentionally absent
# because this server uses them for GRE/WireGuard/GREPLUS.
blocked_destinations=(
    0.0.0.0/8
    192.0.0.0/24
    192.0.2.0/24
    198.18.0.0/15
    198.51.100.0/24
    203.0.113.0/24
    224.0.0.0/4
    240.0.0.0/4
    255.255.255.255/32
)

for destination in "${blocked_destinations[@]}"; do
    ufw deny out to "$destination" comment 'auto-firewall special-use'
done

# Remove exact direct FORWARD drops created by legacy versions. Do not flush
# iptables: Docker, Xray and tunnel managers may own unrelated rules.
legacy_direct_source_blocks=(
    200.0.0.0/8
    102.0.0.0/8
    10.0.0.0/8
    100.64.0.0/10
    169.254.0.0/16
    198.18.0.0/15
    198.51.100.0/24
    203.0.113.0/24
    224.0.0.0/4
    240.0.0.0/4
    255.255.255.255/32
    192.0.0.0/24
    192.0.2.0/24
    127.0.0.0/8
    127.0.53.53/32
    192.168.0.0/16
    0.0.0.0/8
    172.16.0.0/12
    224.0.0.0/3
    192.88.99.0/24
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
echo "Firewall applied successfully."
echo "SSH TCP ports: $(printf '%s\n' "${!ssh_ports[@]}" | sort -n | paste -sd, -)"
echo "Public TCP ports: $(printf '%s\n' "${!tcp_ports[@]}" | sort -n | paste -sd, -)"
echo "Public UDP ports: $(printf '%s\n' "${!udp_ports[@]}" | sort -n | paste -sd, -)"
echo "Tunnel ranges: $(printf '%s\n' "${tunnel_ranges[@]}" | paste -sd, -)"
echo "Backup: $backup_dir"
echo
ufw status verbose
