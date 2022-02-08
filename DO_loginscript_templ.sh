#!/bin/bash
clear
echo
echo -n "Enter a username: "
sleep 1
read name
useradd -m $name
passwd $name
chage -d 0 $name
clear
echo
echo "** Adding user to sudoers **"
sleep 1
echo "ed ALL=(ALL) ALL" >> /etc/sudoers
clear
echo
echo "** Making a backup of user's .bashrc and making changes **"
sleep 1
cp /home/ed/.bashrc /home/ed/.bashrc.bk
cat <<EOT >> /home/ed/.bashrc
alias ll='ls -lh --color=auto'
alias la='ls -lha --color=auto'
alias l='ls -CF'
PS1="\[\033[0;31m\][\u@\h:\[\033[0;31m\] \W\[\033[0;31m\]]\$\[\033[0m\] "
export HISTTIMEFORMAT="%F %T "
EOT
clear
echo
echo "** Making a copy of ssh config file and making changes **"
sleep 1
cp /etc/ssh/sshd_config /etc/ssh/sshd_config_`date +%Y%m%d%H%M%S`.bk
sed -i 's/#Protocol 2/Protocol 2/g' /etc/ssh/sshd_config
sed -i 's/#LogLevel INFO/LogLevel INFO/g' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/g' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 480/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
clear
echo
echo "** Restoring root's .bash_profile from backup **"
sleep 1
cp /root/.bash_profile.bk /root/.bash_profile
