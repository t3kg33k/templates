#!/bin/bash
tar -cvpzf /path_to_storage/servername_backup_`date +%Y%m%d%H%M%S`.tar.gz --exclude=/directory --exclude=/path_to_storage/servername_backup*.tar.gz --one-file-system /
