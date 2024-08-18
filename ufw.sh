#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

ports=$(ss -tuln | grep LISTEN | awk '{print $5}' | awk -F':' '{print $NF}' | sort -n | uniq)

for port in $ports; do
    sudo ufw allow "$port"/tcp
done

sudo ufw deny out from any to 200.0.0.0/8
sudo ufw deny out from any to 102.0.0.0/8
sudo ufw deny out from any to 10.0.0.0/8
sudo ufw deny out from any to 100.64.0.0/10
sudo ufw deny out from any to 169.254.0.0/16
sudo ufw deny out from any to 198.18.0.0/15
sudo ufw deny out from any to 198.51.100.0/24
sudo ufw deny out from any to 203.0.113.0/24
sudo ufw deny out from any to 224.0.0.0/4
sudo ufw deny out from any to 240.0.0.0/4
sudo ufw deny out from any to 255.255.255.255/32
sudo ufw deny out from any to 192.0.0.0/24
sudo ufw deny out from any to 192.0.2.0/24
sudo ufw deny out from any to 127.0.0.0/8
sudo ufw deny out from any to 127.0.53.53
sudo ufw deny out from any to 192.168.0.0/16
sudo ufw deny out from any to 0.0.0.0/8
sudo ufw deny out from any to 172.16.0.0/12
sudo ufw deny out from any to 224.0.0.0/3
sudo ufw deny out from any to 192.88.99.0/24
sudo ufw deny out from any to 198.18.140.0/24
sudo ufw deny out from any to 102.230.9.0/24
sudo ufw deny out from any to 102.233.71.0/24
sudo ufw allow 222/tcp

echo "y" | sudo ufw enable

sudo iptables -A FORWARD -s 200.0.0.0/8 -j DROP
sudo iptables -A FORWARD -s 102.0.0.0/8 -j DROP
sudo iptables -A FORWARD -s 10.0.0.0/8 -j DROP
sudo iptables -A FORWARD -s 100.64.0.0/10 -j DROP
sudo iptables -A FORWARD -s 169.254.0.0/16 -j DROP
sudo iptables -A FORWARD -s 198.18.0.0/15 -j DROP
sudo iptables -A FORWARD -s 198.51.100.0/24 -j DROP
sudo iptables -A FORWARD -s 203.0.113.0/24 -j DROP
sudo iptables -A FORWARD -s 224.0.0.0/4 -j DROP
sudo iptables -A FORWARD -s 240.0.0.0/4 -j DROP
sudo iptables -A FORWARD -s 255.255.255.255/32 -j DROP
sudo iptables -A FORWARD -s 192.0.0.0/24 -j DROP
sudo iptables -A FORWARD -s 192.0.2.0/24 -j DROP
sudo iptables -A FORWARD -s 127.0.0.0/8 -j DROP
sudo iptables -A FORWARD -s 127.0.53.53 -j DROP
sudo iptables -A FORWARD -s 192.168.0.0/16 -j DROP
sudo iptables -A FORWARD -s 0.0.0.0/8 -j DROP
sudo iptables -A FORWARD -s 172.16.0.0/12 -j DROP
sudo iptables -A FORWARD -s 224.0.0.0/3 -j DROP
sudo iptables -A FORWARD -s 192.88.99.0/24 -j DROP
sudo iptables -A FORWARD -s 169.254.0.0/16 -j DROP
sudo iptables -A FORWARD -s 198.18.140.0/24 -j DROP
sudo iptables -A FORWARD -s 102.230.9.0/24 -j DROP
sudo iptables -A FORWARD -s 102.233.71.0/24 -j DROP

sudo iptables-save

sudo ufw status verbose
