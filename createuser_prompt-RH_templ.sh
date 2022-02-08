#!/bin/bash
# This scripts creates a user and passwd with a prompt for the user to change password at first login
echo -n "Enter a username: "
read name
useradd -m $name
passwd $name
#chage -d 0 $name
passwd -e $name
