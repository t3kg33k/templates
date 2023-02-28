#!/bin/bash
#
# Installs LAMP for Nextcloud on AlmaLinux
clear
echo
echo "** Installing packages for http/Apache and PHP **"
echo
sleep 5
dnf install wget httpd httpd-tools mod_ssl epel-release -y
echo
sleep 3
dnf module install php:7.4 -y
echo
sleep 3
dnf install php-mysqlnd php-dom php-simplexml php-xml php-xmlreader php-curl php-exif php-ftp php-gd php-iconv  php-json php-mbstring php-posix php-sockets php-tokenizer -y
echo
sleep 3
systemctl start httpd && systemctl enable httpd && systemctl status httpd
echo
sleep 5
echo
clear
echo
echo "** Starting firewalld and adding web ports **"
echo
sleep 2
firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --permanent --zone=public --add-service=https
firewall-cmd --reload
systemctl restart httpd
sleep 2
echo
clear
echo
echo "Adding test PHP page... "
echo
sleep 3
echo "<?php phpinfo() ?>" > /var/www/html/info.php
echo "Verify..."
clear
echo
cat /var/www/html/info.php
echo
sleep 5
echo "** Now verify the test page by going to http://serverIP/info.php"
read -p "Press [Enter] to continue after verifying..."
echo
echo "** Installing and setting up MariaDB **"
echo
sleep 3
dnf install mariadb-server mariadb -y
echo
sleep 2
systemctl enable mariadb && systemctl start mariadb && systemctl status mariadb
echo
sleep 5
clear
echo
echo "** Securing MariaDB **"
echo
sleep 3
echo
clear
echo
mysql_secure_installation
echo
sleep 2
clear
echo
echo "Verify MariaDB..."
echo
sleep 3
echo
mysql -e "SHOW DATABASES;" -p
echo
echo
echo "^^^ LAMP install complete ^^^"
echo
