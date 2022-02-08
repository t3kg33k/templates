#!/bin/bash
# This script disables ssh root login 
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sudo systemctl restart sshd
sleep 2
clear
sudo grep -i "permitrootlogin" /etc/ssh/sshd_config
