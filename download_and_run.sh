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

# Only one invocation may edit UFW at a time. GRE-TUN uses the same lock.
exec 9>/run/gretun-ufw.lock
flock -w 60 9 || { echo 'UFW is busy; retry later.' >&2; exit 1; }

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

# Inspect saved rules once. Repeated UFW calls become very slow on hosts that
# already have many rules, even when UFW reports "Skipping adding existing".
saved_rules="$(ufw show added)" || { echo 'Cannot inspect saved UFW rules; leaving firewall untouched.' >&2; exit 1; }
changed_rules=0
declare -A rules_cache=()
first_saved_rule=''
while IFS= read -r line; do
    [[ $line == ufw\ * ]] || continue
    [[ -n $first_saved_rule ]] || first_saved_rule=$line
    rules_cache["${line%% comment *}"]=1
done <<< "$saved_rules"

rule_exists() {
    [[ -v rules_cache["ufw $*"] ]]
}

ensure_rule() {
    rule_exists "$@" && return 0
    ufw "$@" >/dev/null || return 1
    rules_cache["ufw $*"]=1
    ((changed_rules+=1))
}

# A plain allow appended after an old DENY rule may not protect SSH. Make a
# wide TCP/22 allow the first IPv4 user rule, including when UFW is inactive.
if [[ $first_saved_rule != 'ufw allow 22/tcp' && $first_saved_rule != 'ufw allow 22/tcp comment '* ]]; then
    # UFW can skip an insert of a rule already present later in the list.
    if rule_exists allow 22/tcp; then
        ufw delete allow 22/tcp >/dev/null || exit 1
        unset 'rules_cache[ufw allow 22/tcp]'
    fi
    ufw insert 1 allow 22/tcp >/dev/null || { echo 'Could not place SSH rule first; UFW was not enabled.' >&2; exit 1; }
    first_saved_rule="$(ufw show added | awk '/^ufw / {print; exit}')"
    [[ $first_saved_rule == 'ufw allow 22/tcp' || $first_saved_rule == 'ufw allow 22/tcp comment '* ]] || {
        echo 'SSH rule is not first; refusing to enable UFW.' >&2; exit 1;
    }
    rules_cache['ufw allow 22/tcp']=1
    ((changed_rules+=1))
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
        ensure_rule allow "$port/tcp"
    fi
done

# UDP listeners (including public WireGuard endpoints) must survive UFW enable.
while IFS= read -r port; do
    [[ $port =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || continue
    ensure_rule allow "$port/udp"
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
            ensure_rule allow proto gre from "$remote_ip" to "$local_ip"
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

# Older releases denied these private ranges, including GRE/GREPLUS's 10.x
# inner addresses. Remove those exact stale rules before applying new rules.
for subnet in 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 127.0.0.0/8 127.0.53.53 192.168.0.0/16 172.16.0.0/12; do
    if rule_exists deny out to "$subnet"; then
        ufw delete deny out to "$subnet" >/dev/null || exit 1
        changed_rules=$((changed_rules + 1))
        unset "rules_cache[ufw deny out to $subnet]"
    fi
    if rule_exists route deny from "$subnet"; then
        ufw route delete deny from "$subnet" >/dev/null || exit 1
        changed_rules=$((changed_rules + 1))
        unset "rules_cache[ufw route deny from $subnet]"
    fi
done
if rule_exists allow 222/tcp; then
    ufw delete allow 222/tcp >/dev/null || exit 1
    changed_rules=$((changed_rules + 1))
    unset 'rules_cache[ufw allow 222/tcp]'
fi

for destination in "${blocked_destinations[@]}"; do
    ensure_rule deny out to "$destination"
done

# UFW route rules are persistent. The previous direct iptables rules were
# duplicated on every run and 'iptables-save' did not actually save them.
for source in "${forward_source_blocks[@]}"; do
    ensure_rule route deny from "$source"
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
    removed=0
    while (( removed < 20 )) && iptables -C FORWARD -s "$source" -j DROP >/dev/null 2>&1; do
        iptables -D FORWARD -s "$source" -j DROP
        ((removed+=1))
    done
done

current_status="$(ufw status)" || exit 1
if [[ $current_status == *'Status: inactive'* ]]; then
    ufw --force enable >/dev/null
fi

current_status="$(ufw status)" || exit 1
[[ $current_status == *'Status: active'* ]] || { echo 'UFW did not become active.' >&2; exit 1; }
echo "Firewall ready. New rules: $changed_rules. SSH TCP port(s): $(printf '%s\n' "${!ssh_ports[@]}" | sort -n | paste -sd, -)"
