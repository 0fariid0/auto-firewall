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

# Ask the user for server location
read -p "Select server location (1 for IRAN, 2 for kharej): " location

if [ "$location" == "1" ]; then
    filename="ping_iran.sh"
    cat <<EOL > $filename
#!/bin/bash

while true
do
    ping6 2002:fb8:221::2 &
    ping6 2002:fb8:222::2 &
    ping6 2002:fb8:223::2 &
    ping6 2002:fb8:224::2 &
    ping6 2002:fb8:225::2 &
    ping6 2002:fb8:226::2 &
    ping6 2002:fb8:227::2 &
    ping6 2002:fb8:228::2 &
    ping6 2002:fb8:229::2 &
    ping6 2002:fb8:121::2 &
    ping6 2002:fb8:122::2 &
    ping6 2002:fb8:123::2 &
    ping6 2002:fb8:124::2 &
    ping6 2002:fb8:125::2 &
    ping6 2002:fb8:126::2 &
    ping6 2002:fb8:127::2 &
    ping6 2002:fb8:128::2 &
    ping6 2002:fb8:129::2 &
    wait
done
EOL
elif [ "$location" == "2" ]; then
    filename="ping_kharej.sh"
    cat <<EOL > $filename
#!/bin/bash

while true
do
    ping6 2002:fb8:221::1 &
    ping6 2002:fb8:222::1 &
    ping6 2002:fb8:223::1 &
    ping6 2002:fb8:224::1 &
    ping6 2002:fb8:225::1 &
    ping6 2002:fb8:226::1 &
    ping6 2002:fb8:227::1 &
    ping6 2002:fb8:228::1 &
    ping6 2002:fb8:229::1 &
    ping6 2002:fb8:121::1 &
    ping6 2002:fb8:122::1 &
    ping6 2002:fb8:123::1 &
    ping6 2002:fb8:124::1 &
    ping6 2002:fb8:125::1 &
    ping6 2002:fb8:126::1 &
    ping6 2002:fb8:127::1 &
    ping6 2002:fb8:128::1 &
    ping6 2002:fb8:129::1 &
    wait
done
EOL
else
    echo "Invalid selection"
    exit 1
fi

# Make the ping script executable and move it to a directory
chmod +x $filename
directory="ping_files"
if [ ! -d "$directory" ]; then
    mkdir "$directory"
fi

mv $filename $directory/
chmod -R 755 $directory

# Create the systemd service file
service_name="ping_service.service"
cat <<EOL > /etc/systemd/system/$service_name
[Unit]
Description=Ping Service
After=network.target

[Service]
ExecStart=/bin/bash /root/$directory/$filename
Restart=always

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd, enable and start the service
systemctl daemon-reload
systemctl enable $service_name
systemctl start $service_name

# Display UFW status at the end
sudo ufw status verbose

echo "Ping script created and service $service_name is now running."
