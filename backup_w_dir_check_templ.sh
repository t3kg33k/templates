#!/bin/bash
#
MNTSHARE=$(mount | grep backup | awk '{print $3}')
# Checks to confirm directory exist.
if [ "$MNTSHARE" == /backup ]; then
		rsync -av --log-file=/root/backup_log/root_dir_backup_log_$(date +%Y%m%d).log /root/ /backup/root_dir/
# If directory does not exist, make note
elif
	[ "$MNTSHARE" != /backup ]; then

		echo "directory doesn't exit" > nobackupdirectory

fi

# Delete log files older than 15 days
find /root/backup_log/*.log -mtime +15 -exec rm {} \;

