#!/bin/bash
#
# Checks the operating system version and installs Apache 
rhel_version=`cat /etc/redhat-release`
rhel='CentOS Linux'
version7='release 7'
index=`awk -v a="$rhel_version" -v b="$rhel" 'BEGIN{print index(a,b)}'`
if [ $index -ne 0 ]; then
    index=`awk -v a="$rhel_version" -v b="$version7" 'BEGIN{print index(a,b)}'`
    if [ $index -ne 0 ]; then
        echo "Installing Apache"
        yum install httpd -y
        systemctl enable httpd
        echo "Start httpd service and enable."
        systemctl start httpd
        systemctl enable httpd
        systemctl status httpd
        sleep 2
    else
        echo "Installing Apache."
        yum install httpd -y
        echo "Start httpd service and enable."
        service httpd start
        chkconfig httpd on
    fi
else
    echo "The current operating system is not Red Hat Enterprise Linux."
    exit 1
fi

cd /etc/httpd/conf
sudo cp httpd.conf httpd.conf.bk
sudo touch /var/www/html/index.html
sudo bash -c 'cat <<EOF > /var/www/html/index.html
<html>
  <head>
    <title>New site! Please configure me.</title>
  </head>
  <body>
    <h1>Success! The new site is working!</h1>
  </body>
</html>
EOF'
clear
echo
echo "*** Your temporary site has been configured. ***"
