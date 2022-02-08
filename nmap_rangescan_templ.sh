#!/bin/bash
# nmap network scan

clear
echo
echo "@@@ This script will scan a network range @@@"
echo
sleep 4
clear
echo
read -p "Enter the range to scan with CIDR (i.e. 192.168.0.1/24): " netrange
echo
sudo nmap -sn $netrange
echo
