#!/bin/bash
# Script to backup libvirtd virtual machines
#
# 1. ----------------------------------
# -- Backup server1
# Shutdown the virtual machine
virsh shutdown server1
# Pause for 30 seconds on the script while shutdown
sleep 30s
# Backup the config xml to external storage
virsh dumpxml server1 > /mnt/usb/server1_backup.xml
# Copy the virtual disk to external storage
cp /home/images/server1.qcow2 /mnt/usb/
# Start the virtual machine
virsh start server1
# Change to the external storage
cd /mnt/usb
# Compress the virtual drive and config
tar cvzf server1_backup_$(date +%Y%m%d_%H%M%S).tar.gz server1.qcow2 server1_backup.xml
# Remove the files that were compressed to save space
rm -f /mnt/usb/server1.qcow2 /mnt/usb/server1_backup.xml
#
# 2. ----------------------------------
# -- Backup server2
# Shutdown the virtual machine
virsh shutdown server2
# Pause for 30 seconds on the script while shutdown
sleep 30s
# Backup the config xml to external storage
virsh dumpxml server2 > /mnt/usb/server2_backup.xml
# Copy the virtual disk to external storage
cp /home/images/server2.qcow2 /mnt/usb/
# Start the virtual machine
virsh start server2
# Change to the external storage
cd /mnt/usb
# Compress the virtual drive and config
tar cvzf server2_backup_$(date +%Y%m%d_%H%M%S).tar.gz server2.qcow2 server2_backup.xml
# Remove the files that were compressed to save space
rm -f /mnt/usb/server2.qcow2 /mnt/usb/server2_backup.xml
#

