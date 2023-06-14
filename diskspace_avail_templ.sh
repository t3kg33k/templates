#!/bin/bash
avail=`df -h | grep /dev/sdX1 | awk '{print $4}'`
size=`df -h | grep /dev/sdX1 | awk '{print $2}'`
echo "There is $avail of $size available on the X on Y"
