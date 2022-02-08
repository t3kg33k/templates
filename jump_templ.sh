#!/bin/bash
# Script used on a ssh jump server for autoconnect via ssh to a specific host.
# Script to be placed in .profile
echo 
clear
echo
echo "^^^ Do you want to connect to workstation? (yes/no) ^^^"
read REPLY
if [ "$REPLY" == "yes" ]; then 
	echo
	echo "*** connecting to hostname ***"
	echo
	echo
	# SSH to the workstation 
	ssh username@hostname
elif [ "$REPLY" == "no" ]; then
	echo
	echo "--- not connecting ---" 
	echo "---"
	echo
else
	echo
	echo "invalid answer, type yes or no"; 
fi 
