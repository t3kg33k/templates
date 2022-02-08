#!/bin/bash
sudo mount -t cifs -o rw,noperm,username=user,file_mode=0777,dir_mode=0777 //server/backup /mnt/share
