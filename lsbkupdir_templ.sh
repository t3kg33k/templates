#!/bin/bash
# This script creates a log of disk space usage on a specific directory or mount. Best for directories with just files
# The directory where the log will be created will need to be changed of your choice
#
# removes the existing backup log to be recreated
rm -rf $HOME/logs/bkuplog.txt
echo "----------------------" >> $HOME/logs/bkuplog.txt
echo "*** this is the space available ***" >> $HOME/logs/bkuplog.txt
echo "----------------------" >> $HOME/logs/bkuplog.txt
#
# disk space usage on the directory
#
df -h /mnt/nas_backup | awk '{print $4}' >> $HOME/logs/bkuplog.txt
echo >> $HOME/logs/bkuplog.txt
echo "----------------------" >> $HOME/logs/bkuplog.txt
echo "*** this is a listing of the directory sorted by size ***" >> $HOME/logs/bkuplog.txt
echo "----------------------" >> $HOME/logs/bkuplog.txt
#
# list the directory sorted by size with just the size and file column
#
ls -lhS /mnt/nas_backup | awk '{print $5,$9}' >> $HOME/logs/bkuplog.txt
echo >> $HOME/logs/bkuplog.txt
echo "---------------------" >> $HOME/logs/bkuplog.txt
echo "*** this is a standard listing of the directory ***" >> $HOME/logs/bkuplog.txt
echo "---------------------" >> $HOME/logs/bkuplog.txt
#
# list the directory with just the size and file column
#
ls -lh /mnt/nas_backup | awk '{print $5,$9}' >> $HOME/logs/bkuplog.txt
