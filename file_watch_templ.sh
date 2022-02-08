#!/bin/bash
# set this to the path where the lock files are created
FILE_PATH="";
#number of minutes that elapsed before an issue is detected
AGE_IN_MINUTES=30
#get all the file in the folder with an age > AGE_IN_MINUTES
FILES=$(find $FILE_PATH  -type f -amin +$AGE_IN_MINUTES)

# subject of the mail
SUBJECT="Lock file problem for "
# email address to send; seperate email addresses with comma
EMAIL="user@example.com"

# check if we picked up any files
if [[ $FILES != "" ]]
then
   #email the contents of the folder if files are found
   LS=$(ls -l $FILE_PATH)
   echo printf "$LS\n" | mail -s "$SUBJECT$FILE_PATH" $EMAIL;
else
   echo "No files exist";
fi
