#!/bin/bash

HOST=`uname -n`
USER=`id -u`
RECIP="user@email.com"
MAX=60
SYS=`uname`

#--- Need root permissions to run script

if [[ $USER -ne 0 ]];
           then
    echo "Must be root to run this script!!"
else 
                exit 2
   fi

#--- Number of Days since 1st Jan 1970 of root Password Change
DAYS=`grep $USER /etc/shadow | cut -d: -f3`

#--- Number of Days since 1st Jan 1970 to till date
DATE=`perl -e 'print int(time/(60*60*24))'`

#--- Compute the Age of the user's password
AGE=`echo $DATE - $DAYS | bc`

NOTIFY="The user's password is $AGE days old on $HOST"

if [[ $SYS == Linux ]];
   then
DAYS=`grep $USER /etc/shadow | cut -d: -f3`
fi

#--- If User expiry is 90 Days Alert will be generated 30 Days ago and mailed to user.

if [[ $AGE -ge $MAX ]];
   then
WARN=`echo 90 - $AGE | bc`
#echo $NOTIFY | mail -s "Root Password will expire in $WARN days"  $RECIP
echo $NOTIFY | mutt -e 'my_hdr From:user@email.com' -s "Root Password will expire in $WARN days"  $RECIP

fi
