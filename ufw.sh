#!/bin/bash

# چک کردن اینکه اسکریپت با دسترسی روت اجرا می‌شود
if [[ $EUID -ne 0 ]]; then
   echo "این اسکریپت باید با دسترسی روت اجرا شود." 
   exit 1
fi

# استخراج پورت‌های TCP که در حال LISTEN هستند
ports=$(ss -tuln | grep LISTEN | awk '{print $5}' | awk -F':' '{print $NF}' | sort -n | uniq)

# باز کردن پورت‌ها در ufw
for port in $ports; do
    echo "باز کردن پورت $port در ufw..."
    sudo ufw allow "$port"/tcp
done

# اضافه کردن قوانین اضافی به ufw
echo "اضافه کردن قوانین اضافی به ufw..."
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

# فعال کردن ufw
echo "فعال کردن ufw..."
sudo ufw enable

# اضافه کردن قوانین به iptables
echo "اضافه کردن قوانین به iptables..."
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

# ذخیره کردن تنظیمات iptables
sudo iptables-save

# نمایش وضعیت ufw
sudo ufw status verbose

echo "پورت‌ها و قوانین فایروال با موفقیت اعمال شدند."
