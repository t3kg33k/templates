#!/bin/bash
#set -x
# Checks the server disk space
ssh -q -t almanc01 df -h | grep /mnt/volume_nyc3_01 | awk '{print $5}' | sed 's/%//g' | tee almanc01space  
CURRENT=`cat almanc01space`
THRESHOLD=80
# Sends notification if above the threshold
if [ "$CURRENT" -gt "$THRESHOLD" ]; then
  notify-send -t 0 'almanc01 Disk Space is above 80%'
fi
