#!/bin/bash

# This script installs docker and docker-compose on AlmaLinux 8. Should work on RHEL/CentOS/Rocky Linux 8 also.

# Install packages
sudo dnf install curl wget -y


# Install docker
echo "installing docker"

sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

sudo dnf install docker-ce docker-ce-cli containerd.io -y

sudo systemctl start docker.service
sudo systemctl enable docker.service


# Download latest docker-compose verions
echo "installing docker-compose"

curl -s https://api.github.com/repos/docker/compose/releases/latest | grep browser_download_url  | grep docker-compose-linux-aarch64 | cut -d '"' -f 4 | wget -qi -

chmod 755 docker-compose-linux-aarch64

sudo mv docker-compose-linux-aarch64 /usr/local/bin/docker-compose

sudo mkdir -p /usr/local/lib/docker/cli-plugins

sudo cp /usr/local/bin/docker-compose /usr/local/lib/docker/cli-plugins


# Add user to docker group
echo "adding user to docker group"
sudo usermod -aG docker $USER

# ****************      REBOOT SECTION     *******************
echo
echo "^^^ Do you want to reboot (yes/no) ^^^"
read REPLY
if [ "$REPLY" == "yes" ]; then
        echo
        echo "*** WARNING: You have selected to reboot  ***"
        sleep 2
        sudo shutdown -r +1 Rebooting in 1 minute
        sleep 30
elif [ "$REPLY" == "no"  ]; then
        echo
        echo "--- will not reboot ---"
        sleep 2
else
        echo
        echo "invalid answer, type yes or no";
fi
sleep 2
echo
