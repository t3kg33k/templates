#!/bin/bash
# ****************  THIS SCRIPT IS FOR UPDATING REMOTE SERVERS ON LOAD BALANCERS  *******************
clear
echo
echo
echo -e "      ---->>  \033[33;7mREMEMBER TO COMPLETE A VM SNAPSHOT OF THE SERVERS BEFORE PROCEEDING\033[0m  <<----"
echo
sleep 5
read -p "Press [ENTER] to continue "
echo
echo "**** Please remove WEB1 from load balance rotation ****"
echo
sleep 5
read -p "Once the WEB1 has been removed from rotation press [Enter] to continue to complete updates "
clear
echo
# ****************      UPDATES SECTION FOR WEB1     *******************
# SSH to the server and run local yum update
echo "**** Connection to WEB1 to update ****"
echo
ssh -t username@WEB1 sudo yum update -y 2>&1 | tee -a $HOME/updates_web1_`date +%Y%m%d`.log
echo
echo "**** Finished updating WEB1 ****"
clear
echo
# ****************      REBOOTS SECTION FOR WEB1     *******************
echo "^^^ Do you want to reboot WEB1? (yes/no) ^^^"
read REPLY
if [ "$REPLY" == "yes" ]; then
        echo
        echo "*** WARNING: You have selected to reboot WEB1  ***"
        sleep 3
        echo
        # SSH to the server and run shutdown
        ssh -t username@WEB1 sudo shutdown -r +1 Rebooting in 1 minute
        sleep 30
elif [ "$REPLY" == "no"  ]; then
        echo
        echo "--- WEB1 will not reboot ---"
        sleep 2
else
        echo
        echo "invalid answer, type yes or no";
fi
echo
echo "**** Please test WEB1 before moving on to the next phase ****"
sleep 5
echo
read -p "Once WEB1 is up after a reboot (if rebooted) and has been tested press [Enter] to continue to WEB2"
echo
# ****************     DONE WITH REBOOTS SECTION FOR WEB1     *******************
clear
echo "**** Please add WEB1 back into rotation and remove WEB2 from load balance rotation ****"
echo
sleep 5
read -p "Once WEB2 has been removed from rotation press [Enter] to continue to complete updates "
clear
echo
# ****************      UPDATES SECTION FOR WEB2     *******************
# SSH to the server and run local yum update
echo "**** Connection to WEB2 to update ****"
echo
ssh -t username@WEB2 sudo yum update -y 2>&1 | tee -a $HOME/updates_104_`date +%Y%m%d`.log
echo
echo "**** Finished updating WEB2 ****"
clear
echo
# ****************      REBOOTS SECTION FOR WEB2     *******************
echo "^^^ Do you want to reboot WEB2? (yes/no) ^^^"
read REPLY
if [ "$REPLY" == "yes" ]; then
        echo
        echo "*** WARNING: You have selected to reboot WEB2 ***"
        sleep 3
        echo
        # SSH to the server and run shutdown
        ssh -t username@WEB2 sudo shutdown -r +1 Rebooting in 1 minute
        sleep 30
elif [ "$REPLY" == "no"  ]; then
        echo
        echo "--- WEB2 will not reboot ---"
        sleep 2
else
        echo
        echo "invalid answer, type yes or no";
fi
echo
echo "**** Please test the WEB2 before moving on to the next phase ****"
sleep 5
echo
read -p "Once WEB2 is up after a reboot (if rebooted) and has been tested, add WEB2 back into rotation and press [Enter] to continue "
echo
# ****************     DONE WITH REBOOTS SECTION FOR WEB2     *******************
clear
