#!/bin/bash
# this script emails a log file. It assumes mutt is installed and configured
#
# Before mutt can be used a .muttrc file must exist in the user's
# home directory
# --- Example: ---
#
# set copy=yes
# set smtp_url = "smtp://smtp-server.server.com:25/"
# set from = "your@email.com"
# set realname = 'Ed"
#
# --- end example ---
mutt -e 'my_hdr From:user@email.com' -s "backup log"  -i $HOME/backupadmin/bkuplog.txt user@email.com
