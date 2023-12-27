#!/bin/bash
# script to complete a post-install auto setup

echo
nmtui
echo
sleep 3
# Change the system's hostname
echo "^^^ The current hostname is -> `hostname` <-. Would you like to change the machine hostname? yes or no: ^^^"
read HOSTCHANGE
echo
if [ "$HOSTCHANGE" == "yes" ]; then
	echo
	echo "**** Changing the hostname. What would you like to change it to? ****"
	read HOSTNAME
	sudo hostnamectl set-hostname $HOSTNAME
	echo
	hostnamectl status
	sleep 7
fi
echo
# Setup new user
echo "^^^ Would you like to setup a new user? yes or no: "
read NEWUSERADD
if [ "$NEWUSERADD" == "yes" ]; then
	echo
	echo -n "Enter a username: "
	read NAME
	useradd -m $NAME
	passwd $NAME
else [ "$NEWUSERADD" == "no" ]
	echo
	read -p "**** Not creating a user. Hit [Enter] to continue ****"
fi
# Add new user to wheel group
echo "^^^ Add new user to the wheel group? yes or no: "
read NEWUSERWHEEL
if [ "$NEWUSERWHEEL" == "yes" ]; then
	echo
	usermod -aG wheel $NAME
else [ "$NEWUSERWHEEL" == "no" ]
	echo
	read -p "**** Not adding to wheel group. Hit [Enter} to continue ****"
fi
# Disable selinux?
echo "^^^ Disable selinux? yes or no: ^^^" 
read SELINUXCHANGE
echo
if [ "$SELINUXCHANGE" == "yes" ]; then
	echo
	sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
	sleep 3
else [ "$SELINUXCHANGE" == "no" ]
	echo
	read -p "**** Not changing. Hit [Enter] to continue ****"
fi
echo
echo "^^^ Disable firewall? yes or no: ^^^" 
read FIREWALLCHANGE
echo
if [ "$FIREWALLCHANGE" == "yes" ]; then
	echo
	systemctl disable firewalld
	sleep 7
else [ "$FIREWALLCHANGE" == "no" ]
	echo
	read -p "**** Not changing. Hit [Enter] to continue ****"
fi

echo
echo "---- Proceeding with setup ----"
echo
echo "** Installing prefered applications **"
sudo dnf install epel-release -y
sudo dnf install vim bash-completion htop mlocate nfs-utils traceroute whois policycoreutils* bind-utils -y
echo
# Completes system and OS updates
echo
echo "^^^ Would you like to complete OS updates? yes or no: ^^^"
read UPDATESRESPONSE
echo
if [ "$UPDATESRESPONSE" == "yes" ]; then
	echo
	echo "**** Completing OS updates ****"
	echo
	sleep 3
	sudo dnf update -y
else [ "$UPDATESRESPONSE" == "no" ]
	echo
fi
sleep 3
echo
# A choice to reboot or not
echo "^^^ Would you like to reboot? yes or no: ^^^"
read REBOOTRESPONSE
echo
if [ "$REBOOTRESPONSE" == "yes" ]; then
        echo
        echo "**** Rebooting ****"
        sleep 3
        sudo shutdown -r now
else [ "$REBOOTRESPONSE" == "no" ]
		echo
		read -p "**** Done with configuration of system. Hit [Enter] to continue ****"
fi
echo
exit
