#!/bin/bash
#
# This script checks to see if a destination volume is mounted first before completing a backup
MNTSHARE=$(mount | grep backup | awk '{print $3}')

if [ "$MNTSHARE" == /backup ]; then
                rsync -av --log-file=/root/backup_log/dir_backup_log_$(date +%Y%m%d).log /dir/ /backup/dir/


elif
        [ "$MNTSHARE" != /backup ]; then

                echo "directory doesn't exit" > nobackupdirectory

fi

# Delete log files older than 15 days
find /root/backup_log/*.log -mtime +15 -exec rm {} \;
