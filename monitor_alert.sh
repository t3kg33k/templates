#!/bin/bash
#
# This script reads a log file from ping_monitor.sh and
# send a notification via notify-send to Desktop Environment

RESULT=$(grep "loss" /path/to/log.log | awk '{print $6}')
HOSTIP=$(grep PING /path/to/log.log | awk '{print $2}')

if [ "$RESULT" == "100%" ]; then
	notify-send --urgency=normal "$HOSTIP is down"
	cp /path/to/log.log /path/to/logs/log_`date +%Y%m%d%H%M%S`.log
else [ "$RESULT" == "0%" ] 
	rm /path/to/log.log
fi
