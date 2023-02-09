#!/bin/bash
#
# Script to stop or start tailscale
clear
echo " Current status of Tailscale"
sudo tailscale status
sleep 3
echo
echo

echo "^^^ What would you like to do? start or stop Tailscale? "
read RESPONSE
if [ "$RESPONSE" == "start" ]; then
    echo
    echo " Starting Tailscale..."
    sudo tailscale up
    sudo tailscale status
else [ "$RESPONSE" == "stop" ]; 
    echo
    echo " Stopping Tailscale..."
    sudo tailscale down
    echo
    sudo tailscale status
fi
echo
exit
