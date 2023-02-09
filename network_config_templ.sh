#!/bin/bash
#
# This script configures network. It will change the following:
# hostname, network interface, resolv.conf, and joins the sccsdev domain
#
clear
echo
echo
echo "***** Prepare to provide the following information for this script:"
echo
echo "Hostname, interface to use, IP address, Netmask, Gateway, "
echo "Hardware MAC address of the interface"
echo
echo "*****"
sleep 7
clear
# Changing hostname
#
echo "^^^ Would you like to change the hostname? yes or no: "
read HOSTNAMECHANGE
if [ "$HOSTNAMECHANGE" == "yes" ]; then
	echo
	echo "*** Changing the hostname. What would you like to change it to? "
	read HOSTNAME
	hostnamectl set-hostname $HOSTNAME
	echo
	sleep 7

else [ "$HOSTNAMECHANGE" == "no" ]
	echo
	echo "Not changing hostname"
fi
#
# Changing network
#
clear
echo "^^^ Current network ^^^"
echo
echo "^^^ Take note...    ^^^"
echo
ip addr
echo
read -p "Press any key to resume... "
echo
echo "^^^ What will be the network interface name? e.g. em1 eno3, eno1np0, etc.  "
read INTERFACENAME
touch /etc/sysconfig/network-scripts/ifcfg-$INTERFACENAME
echo "ONBOOT=yes" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACENAME
echo "DEVICE=$INTERFACENAME" > /etc/sysconfig/network-scripts/ifcfg-$INTERFACENAME
echo "^^^ What is the IP address? "
read IPADDRESSNUM
echo "IPADDR=$IPADDRESSNUM" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACENAME
echo "^^^ What is the netmask? "
read NETMASKNUM
echo "NETMASK=$NETMASKNUM" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACENAME
echo "^^^ What is the gateway? "
read GATEWAYNUM
echo "GATEWAY=$GATEWAYNUM" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACENAME
clear
echo
echo "Here is the current network again. Note hardware address."
echo
echo
ip addr
echo
echo "^^^ What is the hardware address? Copy/Paste from above "
read HDWRNUM
echo "HWADDR=$HDWRNUM" >> /etc/sysconfig/network-scripts/ifcfg-$INTERFACENAME
clear
#
# Resetting the network
#
ip addr
echo
echo "What is the old interface name? "
read OLDINTERFACE
ip link set $OLDINTERFACE down
echo "What is the new interface name? "
read NEWINTERFACE
ip link set $OLDINTERFACE name $NEWINTERFACE
systemctl restart NetworkManager
ip link set $NEWINTERFACE up
sleep 2
echo "Done"
clear

# A choice to reboot or not
echo "^^^ Would you like to reboot? yes or no: ^^^"
read REBOOTRESPONSE
if [ "$REBOOTRESPONSE" == "yes" ]; then
        echo
        echo "**** Rebooting ****"
        sleep 3
        shutdown -r now
else [ "$REBOOTRESPONSE" == "no" ]
    echo
    read -p "**** Done with configuration of system. Hit [Enter] to continue ****"
fi
echo
exit
