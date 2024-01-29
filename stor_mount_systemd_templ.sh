#!/bin/bash
# This script creates a systemd unit file to mount the secondary storage. This script assumes
# the storage has been created and configured to be mounted on /stor directory.
#
# Creating systemd file
cat <<EOT >> stor.mount
[Unit]
Description=Mount stor directory
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
After=swap.target

[Mount]
What=/dev/disk/by-uuid/tempid
Where=/stor
Type=xfs
Options=defaults

[Install]
WantedBy=multi-user.target
EOT
# Getting the UUID of sdb1 (assuming secondary storage was created there) and
# adding to the new systemd unit file
blockid=$(blkid | grep sdb1 | awk '{print $2}' | sed 's/UUID=//g' | sed 's/"//g')
sed -i "s/tempid/$blockid/g" stor.mount
# Moving file to the required location
echo "^^^ Would you like to move the file to the correct location? yes or no: ^^^"
read MOVERESPONSE
if [ "$MOVERESPONSE" == "yes" ]; then
	mv stor.mount /usr/lib/systemd/system/
	chown root:root /usr/lib/systemd/system/stor.mount
	chmod 644 /usr/lib/systemd/system/stor.mount
        systemctl daemon-reload
	systemctl enable --now stor.mount	
	mount | grep /stor
else [ "$MOVERESPONSE" == "no" ]
	echo "File not moved"
