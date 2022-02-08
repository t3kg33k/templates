#!/bin/bash
#exclude directory and files with exclude file
rsync -a --progress --exclude="subdirectory" --exclude=".log*" --exclude-from 'dir.txt' /source_directory/sub-directory ~/dest_directory/sub-directory
tar cvfz ~/dest_directory/sub-directory_`date +%Y%m%d%H%M%S`.tar.gz ~/dest_directory/sub-directory
rm -rf ~/dest_directory/sub-directory