#!/bin/bash
# Script used for Digital Ocean new droplet

# Makes a copy of .bashrc before adding
cp /root/.bashrc /root/.bashrc.bk
cat <<EOT >> /root/.bashrc
alias ll='ls -lh --color=auto'
alias la='ls -lha --color=auto'
alias l='ls -CF'
PS1="\[\033[0;31m\][\u@\h:\[\033[0;31m\] \W\[\033[0;31m\]]\$\[\033[0m\] "
export HISTTIMEFORMAT="%F %T "
EOT
# Makes a copy of .bash_profile before inserting login script
cp /root/.bash_profile /root/.bash_profile.bk
# Creates login script
cat <<EOT >> /root/.bash_profile
sh /root/loginscript.sh
EOT
touch /root/loginscript.sh
chmod 744 /root/loginscript.sh
cat <<EOF >> /root/loginscript.sh
#!/bin/bash
clear
echo
clear
# Creating a user named ed. This can be replaced with any user
echo
echo "** Creating new user Ed **"
echo
sleep 3
useradd -m ed
echo
echo "*** Change password of user to temp password ***"
echo
passwd ed
chage -d 0 ed
clear
echo
echo "** Adding user to wheel **"
sleep 2
usermod -aG wheel ed
clear
echo
# Creates custom .bashrc for the new user
echo "** Making a backup of user's .bashrc and making changes **"
sleep 3
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
sleep 3
cp /etc/ssh/sshd_config /etc/ssh/sshd_config_`date +%Y%m%d%H%M%S`.bk
# Locking down ssh
sed -i 's/#Protocol 2/Protocol 2/g' /etc/ssh/sshd_config
sed -i 's/#LogLevel INFO/LogLevel INFO/g' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/g' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
sed -i 's/ClientAliveInterval 120/ClientAliveInterval 480/g' /etc/ssh/sshd_config
sed -i 's/ClientAliveCountMax 2/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
clear
echo
systemctl restart sshd
echo "** Restoring root's .bash_profile from backup **"
sleep 3
cp /root/.bash_profile.bk /root/.bash_profile
# Installing packages
dnf install vim bash-completion epel-release -y
dnf install ansible -y
EOF
