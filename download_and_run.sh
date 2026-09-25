
    
  
#!/usr/bin/env bash
# Auto Firewall: preserve SSH, discover live ports, and keep GRE/WireGuard usable.
set -Eeuo pipefail

(( EUID == 0 )) || { echo 'Run as root.' >&2; exit 1; }
for tool in ufw ss awk sort flock; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing: $tool" >&2; exit 1; }
done

# No concurrent copies of this script may modify UFW.
exec 9>/run/gretun-ufw.lock
flock -w 60 9 || { echo 'UFW is busy; retry later.' >&2; exit 1; }

# Remove the obsolete ping service from the earlier release.
if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now ping_service.service >/dev/null 2>&1 || true
fi
if [[ -f /etc/systemd/system/ping_service.service ]]; then
    rm -f /etc/systemd/system/ping_service.service
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
rm -f /root/ping_files/ping_iran.sh /root/ping_files/ping_kharej.sh
rmdir /root/ping_files 2>/dev/null || true

# A damaged UFW tuple must be repaired before changing the stored rules.
ufw_errors=$(mktemp)
trap 'rm -f "$ufw_errors"' EXIT
if ! saved_rules=$(ufw show added 2>"$ufw_errors"); then
    cat "$ufw_errors" >&2
    echo 'Cannot inspect UFW rules; no firewall changes were made.' >&2
    exit 1
fi
if [[ -s $ufw_errors ]]; then
    cat "$ufw_errors" >&2
    echo 'UFW reported a malformed saved rule; no firewall changes were made.' >&2
    exit 1
fi

declare -A known_rules=() tcp_ports=() udp_ports=()
first_rule=''
while IFS= read -r line; do
    [[ $line == ufw\ * ]] || continue
    [[ -n $first_rule ]] || first_rule=$line
    known_rules["${line%% comment *}"]=1
done <<< "$saved_rules"
changed=0
rule_exists() { [[ -v known_rules["ufw $*"] ]]; }
ensure_rule() {
    rule_exists "$@" && return 0
    ufw "$@" >/dev/null
    known_rules["ufw $*"]=1
    ((changed+=1))
}

# A late SSH allow can sit behind an earlier DENY. Guarantee TCP/22 is first.
if [[ $first_rule != 'ufw allow 22/tcp' && $first_rule != 'ufw allow 22/tcp comment '* ]]; then
    if rule_exists allow 22/tcp; then
        ufw delete allow 22/tcp >/dev/null
        unset 'known_rules[ufw allow 22/tcp]'
    fi
    ufw insert 1 allow 22/tcp >/dev/null
    first_rule=$(ufw show added | awk '/^ufw / {print; exit}')
    [[ $first_rule == 'ufw allow 22/tcp' || $first_rule == 'ufw allow 22/tcp comment '* ]] || {
        echo 'TCP/22 was not placed first; refusing to enable UFW.' >&2; exit 1;
    }
    known_rules['ufw allow 22/tcp']=1
    ((changed+=1))
fi

add_port() {
    local proto=$1 port=$2
    [[ $port =~ ^[0-9]+$ ]] || return 0
    (( port >= 1 && port <= 65535 )) || return 0
    [[ $port == 222 ]] && return 0
    if [[ $proto == tcp && $port != 22 ]]; then tcp_ports["$port"]=1; fi
    if [[ $proto == udp ]]; then udp_ports["$port"]=1; fi
}

while IFS= read -r port; do add_port tcp "$port"; done < <(ss -H -lnt | awk '{a=$4; sub(/^.*:/,"",a); print a}')
while IFS= read -r port; do add_port udp "$port"; done < <(ss -H -lnu | awk '{a=$4; sub(/^.*:/,"",a); print a}')
if [[ -n ${AUTO_FIREWALL_TCP_PORTS:-} ]]; then
    for port in ${AUTO_FIREWALL_TCP_PORTS//,/ }; do add_port tcp "$port"; done
fi
if [[ -n ${AUTO_FIREWALL_UDP_PORTS:-} ]]; then
    for port in ${AUTO_FIREWALL_UDP_PORTS//,/ }; do add_port udp "$port"; done
fi

# UFW accepts comma-separated ports (at most 15 per rule). This replaces
# one Python process per listener with one process per group of listeners.
allow_port_groups() {
    local proto=$1 group='' count=0 port
    shift
    for port in "$@"; do
        if (( count == 15 )); then
            ensure_rule allow proto "$proto" from any to any port "$group"
            group='' count=0

