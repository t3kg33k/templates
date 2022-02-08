#!/bin/bash
#
# Script for managing guest VMs on a KVM server
echo 
clear
echo
selection=
until [ "$selection" = "0" ]; do
	clear
        echo ""
        echo -e "   \033[33;7m-------------------------\033[0m"
        echo -e "   \033[33;7m*      KVM MENU         *\033[0m"
        echo -e "   \033[33;7m-------------------------\033[0m"
        echo ""
        echo -e " \033[33;7m1 - List VMs powered off     \033[0m"
        echo -e " \033[33;7m2 - List VMs powered on      \033[0m"
        echo -e " \033[33;7m3 - Power on a VM            \033[0m"
        echo -e " \033[33;7m4 - Shutdown a VM            \033[0m"
        echo -e " \033[33;7m5 - Reboot a VM              \033[0m"
        echo -e " \033[33;7m6 - Create snapshots of a VM \033[0m"
        echo -e " \033[33;7m7 - List snapshots of a VM   \033[0m"
        echo -e " \033[33;7m8 - Revert snapshots of a VM \033[0m"
        echo ""
        echo -e " \033[33;7m0 - exit program\033[0m"
        echo ""
        echo -en " \033[33;7mEnter selection:\033[0m"
        read selection
        echo ""
case $selection in
        1 ) echo \*** && virsh list --inactive | awk 'NR>2{print $2}' && echo \***;;
        2 ) echo \*** && virsh list | awk 'NR>2{print $2}' && echo \*** ;;
        3 ) echo \*** && read -p "enter the vm name: " response && virsh start $response && echo \***;;
        4 ) echo \*** && read -p "enter the vm name: " response && virsh shutdown $response && echo \***;;
        5 ) echo \*** && read -p "enter the vm name: " response && virsh reboot $response && echo \***;;
        6 ) echo \*** && read -p "enter the vm name: " response && virsh snapshot-create-as --domain $response && echo \***;;
        7 ) echo \*** && read -p "enter the vm name: " response && virsh snapshot-list $response && echo \***;;
        8 ) echo \*** && read -p "enter the vm name: " response && virsh snapshot-revert $response --current && echo \***;;
        0 ) exit ;;
        * ) echo "Please enter 1 - 8 or 0"
esac
echo -e " \033[33;7mEnter return to continue\033[0m \c"
read input
done

