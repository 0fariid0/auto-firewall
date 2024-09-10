#!/bin/bash

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

# Remove old ufw.sh if it exists
if [ -f "ufw.sh" ]; then
    rm ufw.sh
fi

# Download the latest ufw.sh script from GitHub
GITHUB_REPO_URL="https://raw.githubusercontent.com/0fariid0/auto-firewall/main/ufw.sh"
curl -O $GITHUB_REPO_URL
FILENAME=$(basename $GITHUB_REPO_URL)
chmod +x $FILENAME

# Run the ufw.sh script
sudo ./$FILENAME
