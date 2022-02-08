#!/bin/bash
# This script assumes mutt is installed and already configured
yes | cp -f /var/log/secure.d/*.secure /root/securitylogs/
tar -zcf securitylogs.tar.gz securitylogs
echo "Daily security logs" | mutt -e 'my_hdr From:user@email.com' -s "security logs" admin@email.com -a securitylogs.tar.gz





