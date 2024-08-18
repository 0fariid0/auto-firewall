#!/bin/bash

GITHUB_REPO_URL="https://raw.githubusercontent.com/0fariid0/auto-firewall/main/ufw.sh"
FILENAME=$(basename $GITHUB_REPO_URL)

if [ -f "$FILENAME" ]; then
    rm "$FILENAME"
fi

curl -O $GITHUB_REPO_URL

chmod +x $FILENAME

sudo ./$FILENAME
