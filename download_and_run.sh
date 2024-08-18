#!/bin/bash

# آدرس فایل اسکریپت در GitHub
GITHUB_REPO_URL="https://raw.githubusercontent.com/0fariid0/auto-firewall/main/ufw.sh"

# دانلود اسکریپت از GitHub
curl -O $GITHUB_REPO_URL

# جدا کردن نام فایل از URL
FILENAME=$(basename $GITHUB_REPO_URL)

# دادن دسترسی اجرایی به اسکریپت
chmod +x $FILENAME

# اجرای اسکریپت
sudo ./$FILENAME
