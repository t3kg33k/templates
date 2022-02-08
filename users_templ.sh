#!/bin/bash
# print user from passwd file and output to file
sudo cat /etc/passwd | awk -F : '{print $1}' > alluser.txt

