#!/bin/bash 

HOST=`uname -n`
# If maximum days of password change is 90 then set the MAX
# within 10 days (i.e. 80) in order to be notified within 10 days. 
MAX=80

#--- Number of Days since 1st Jan 1970 of root Password Change
DAYS=`grep ed /etc/shadow | cut -d: -f3`

#--- Number of Days since 1st Jan 1970 to till date
DATE=`perl -e 'print int(time/(60*60*24))'`

#--- Compute the Age of the user's password
AGE=`echo $DATE - $DAYS | bc`

if [[ $AGE -ge $MAX ]];
   then
WARN=`echo 90 - $AGE | bc`
# If email is preferred, mutt installed and configured, uncomment the following line
#echo "Root password on $HOST will expire in $WARN days" | mutt -e 'my_hdr From:user@email.com' -s "Root password expire notice" user@email.com
echo "Root password on $HOST will expire in $WARN days" 

fi

