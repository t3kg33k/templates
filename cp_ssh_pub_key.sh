#!/bin/bash

# This script references a list of servers in your home directory and
# copies it to those servers.
#
# Alternate options for one server:
# 1. ssh-copy-id username@remote_host
# 2. cat ~/.ssh/id_rsa.pub | ssh username@remote_host "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

for ip in `cat /home/list_of_servers`; do
    ssh-copy-id -i ~/.ssh/id_rsa.pub $ip
done
