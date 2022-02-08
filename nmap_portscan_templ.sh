#!/bin/bash
# nmap IP port scan

clear
echo
echo "@@@ This script will scan an IP address for open ports @@@"
echo
sleep 4
clear
echo
read -p "Enter the IP address to scan: " ipaddress
echo
sudo nmap -T4 -A -v $ipaddress
echo
