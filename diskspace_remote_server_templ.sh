#!/bin/bash
#set -x
# Checks the server disk space on a remote server and sends notification to DE. Ideal for a cron job. 
# The ssh session assumes ssh keys exist on remote server
ssh -q -t server df -h | grep /directory | awk '{print $5}' | sed 's/%//g' | tee file
# Sets variable for getting the file information from the line above
CURRENT=`cat file`
# Sets variable for disk threshold
THRESHOLD=74
# Sends notification if above the threshold
if [ "$CURRENT" -gt "$THRESHOLD" ]; then
	#notify-send -t 60000 'Disk Space is above 90%'
  echo "space is above 70%"
fi
