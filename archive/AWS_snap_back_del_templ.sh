#!/bin/bash

# Script found on Linux Academy - Creating An AWS EBS Snapshot Bash Backup Script Nugget
# This script will complete a snapshot of all instances and deletion of all snapshots within the age specified
# run the script with the following actions:
# ./backup backup
# ./backup delete 10 # where 10 is the number of days
#
# Place this script in crontab
# Example:
# 12:00 am everyday
# 0 0 * * * /root/backup.sh backup
# 0 0 * * * /root/backup.sh delete 10


ACTION=$1
AGE=$2

if [ -z $ACTION ];
then
	echo "Usage $1: Define ACTION of backup or delete"
	exit 1
fi

if [ "$ACTION" = "delete" ] && [ -z $AGE ];
then
	echo "Please enter the age of backups you would like to delete"
	exit 1
fi

function backup_ebs () {
	
	for volume in $(aws ec2 describe-volumes | jq .Volumes[].VolumeId | sed 's/\"//g')
	do
		echo Creating snapshot for $volume $(aws ec2 create-snapshot --volume-id $volume --description "backup-script")
	done
}


function delete_snapshots () {

	for snapshot in $(aws ec2 describe-snapshots --filters Name=description,Values=backup-script | jq .Snapshots[].StartTime | sed 's/\"//g')
	do
		SNAPSHOTDATE=$(aws ec2 describe-snapshots --filters Name=snapshot-id,Values=$snapshot | jq .Snapshots[].StartTime | cut -d T -f1 | sed 's/\"//g')
		STARTDATE=$(date +%s)
		ENDDATE=$(date -d $SNAPSHOTDATE +%s)
		INTERVAL=$[ (STARTDATE - ENDDATE) / (60*60*24) ]
		if (( $INTERVAL >= $AGE ));
		then
			echo "Deleting snapshot $snapshot"
			aws ec2 delete-snapshot --snapshot-id $snapshot
		fi
	done	
}
#
# The following is optional for specific volumes
#

#function backup_ebs () {

 #       aws ec2 create-snapshot --volume-id "vol-0a7702decce22402d" --description "snapshot of WinLab server"
#}

#function delete_snapshots () {

#       for snapshot in $(aws ec2 describe-snapshots --filters Name=description,Values="snapshot of WinLab server" | jq .Snapshots[].SnapshotId | sed 's/\"//g')
#        do
#                SNAPSHOTDATE=$(aws ec2 describe-snapshots --filters Name=snapshot-id,Values=$snapshot | jq .Snapshots[].StartTime | cut -d T -f1 | sed 's/\"//g')
#                STARTDATE=$(date +%s)
#                ENDDATE=$(date -d $SNAPSHOTDATE +%s)
#                INTERVAL=$[ (STARTDATE - ENDDATE) / (60*60*24) ]
#                if (( $INTERVAL >= $AGE ));
#                then
#                        echo "Deleting snapshot $snapshot"
#                        aws ec2 delete-snapshot --snapshot-id $snapshot
#                fi
#        done
#}


case $ACTION in
		"backup")
				backup_ebs
			;;
			"delete")
				delete_snapshots
			;;
esac
