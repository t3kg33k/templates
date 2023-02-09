#!/bin/bash
#set -x

# Check if files exist in path1; if so, rsync to path2
#
# set this to the path where the lock files are created
FILE_PATH1="/home/ed/test01/*";
FILE_PATH2="/home/ed/test02/";
#number of minutes to look for changes
AGE_IN_MINUTES=60
#get all the file in the folder with a specific age
FILES=$(find $FILE_PATH1  -type f -mmin -$AGE_IN_MINUTES)

# check if we picked up any files
if [[ $FILES != "" ]]
then
   LS=$(ls -l $FILE_PATH1)
   rsync -av $FILE_PATH1 $FILE_PATH2;
else
   echo "No files exist";
fi
