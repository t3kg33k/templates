#!/bin/bash
# This script copies a file to many servers. Server list is required
# Enter a text file that references all servers
for dest in $(<textfile); do
# Enter the file and directory location (absolute path) on the server
  scp file ${dest}:directory
done
