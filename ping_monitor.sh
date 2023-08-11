#!/bin/bash
#
# Monitor a server by ping and create a log based on results
# This script is intended to be scheduled in crontab for every x minutes (e.g. 15 minutes)

{ date && ping -c5 -q ipaddress; } > /path/to/log.log 2>&1

# This script reads a log file from ping_monitor.sh and
# send a notification via notify-send to Desktop Environment

bash /path/to/monitor_alert.sh
