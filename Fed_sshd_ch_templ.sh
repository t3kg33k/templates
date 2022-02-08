#!/bin/bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config_`date +%Y%m%d%H%M%S`.bk
sed -i 's/#Protocol 2/Protocol 2/g' /etc/ssh/sshd_config
sed -i 's/#LogLevel INFO/LogLevel INFO/g' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/g' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
