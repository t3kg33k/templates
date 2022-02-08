#!/bin/bash
# Checks the machine disk space and sends notification to the DE if a threshold is met.
# Ideal for cron job

CURRENT=$(df / | grep / | awk '{print $5}' | sed 's/%//g')
THRESHOLD=90
# Sends notification if above the threshold
if [ "$CURRENT" -gt "$THRESHOLD" ]; then
	notify-send -t 60000 'Disk Space is above 90%'
fi
