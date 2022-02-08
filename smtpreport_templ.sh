#!/bin/bash
# this script will look at a directory with smtp logs, pull all lines that have a specific email address in it and only show the outbound emailer
grep -h "user@email.com" *.log > smtp_log.txt
perl -i -pe 's/^.*OutboundConnectionCommand.*\n$//' smtp_log.txt
