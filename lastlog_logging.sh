#!/bin/bash

# Collects lastlog file from specified servers
echo
echo "=============================================================="
echo
echo "Removing residual log files in the Documents directory..."
rm -f $HOME/Documents/*_lastlog.log
echo
echo "=============================================================="
echo
echo "Will now connect to all the servers to collect the last logon..."
echo
echo "=============================================================="
echo
ssh webserver1 lastlog | egrep 'pts|tty' > $HOME/Documents/web1_lastlog.log
ssh webserver2 lastlog | egrep 'pts|tty' > $HOME/Documents/web2_lastlog.log
ssh sqlserver lastlog | egrep 'pts|tty' > $HOME/Documents/sql_lastlog.log
sleep 3
echo
echo "=============================================================="
sleep 3
echo
echo "Will now combine all the collected logs into one log with label headings..."
tail -n +1 $HOME/Documents/*_lastlog.log > $HOME/Documents/servers_lastlogons.log
sleep 3
echo
echo "Will now remove any residual log files from the Documents directory..."
rm -f $HOME/Documents/*_lastlog.log
sleep 3
clear
echo
echo "Done"
echo
echo "Would you like to read the file? Yes or No?: "
read response
if [ "$response" == "Yes" ]; then
	less $HOME/Documents/servers_lastlogons.log
else [ "$response" == "No" ]; 
	echo
fi

