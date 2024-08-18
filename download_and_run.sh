#!/bin/bash

GITHUB_REPO_URL="https://raw.githubusercontent.com/0fariid0/auto-firewall/main/ufw.sh"

curl -O $GITHUB_REPO_URL

FILENAME=$(basename $GITHUB_REPO_URL)

chmod +x $FILENAME

sudo ./$FILENAME
