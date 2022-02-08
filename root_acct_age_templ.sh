#!/bin/bash
#
# This script will remotely connect to a server and then
# create a log of the root account expiry information
# then combine all the logs into one file 
cd $HOME/Documents/reports
# Removes the old report, if it exist
rm -f report_root_acct_age.log
#
# Below two lines are alternate options if only one or two servers needed
#ssh -t server1 sudo chage -l root | tee -a root_acct_age_server1.log
#ssh -t server2 sudo chage -l root | tee -a root_acct_age_server2.log
#
# Reference a file with list of servers
SERVERLIST=`cat $HOME/servers`
for HOSTS in $SERVERLIST; do ssh -t $HOSTS sudo chage -l root | tee -a root_acct_age_$HOSTS.log; done
#
# Combine all the logs into one log
tail -n +1 root_acct_age*.log > report_root_acct_age.log
rm -f root_acct_age*.log
clear
cat $HOME/Documents/reports/report_root_acct_age.log
echo
echo
echo "@@@ The above was saved to the report log 'report_root_acct_age.log' @@@"
echo
echo
