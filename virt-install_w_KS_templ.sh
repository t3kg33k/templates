#!/bin/bash
#
# This script is used to deploy a VM on KVM host using virt-install and a Kickstart file.
# NOTE: For the current config, the Kickstart file should be in the home folder.
 
## Define variables
MEM_SIZE=2048       # Memory setting in MiB
VCPUS=2             # CPU Cores count
OS_VARIANT="almalinux8" # List with osinfo-query  os
ISO_FILE="/home/isos/AlmaLinux-8.4-x86_64-minimal.iso" # Path to ISO file

echo -en "Enter vm name: "
read VM_NAME
OS_TYPE="linux"
echo -en "Enter virtual disk size : "
read DISK_SIZE
 
sudo virt-install \
     --name ${VM_NAME} \
     --memory=${MEM_SIZE} \
     --vcpus=${VCPUS} \
     --os-type ${OS_TYPE} \
     --location ${ISO_FILE} \
     # Change the following to the location where you want the image file to reside
     --disk path=/home/images/${VM_NAME}.qcow2,format=qcow2,bus=virtio,size=${DISK_SIZE}  \
     # Change the following to your network preference
     --network bridge=br0 \
     # The following line used for terminal based install
     --graphics=none \
     --os-variant=${OS_VARIANT} \
     # The following line used for terminal based install
     --console pty,target_type=serial \
     # Be sure to place preferred Kickstart file in your home directory in the following line
     --initrd-inject Alma8-ks_VM.cfg --extra-args "inst.ks=file:/Alma8-ks_VM.cfg console=tty0 console=ttyS0,115200n8"
#     --extra-args="ks=http://192.168.15.31/Alma8-ks_VM.cfg console=tty0 console=ttyS0,115200" --check all=off
#
