#!/bin/bash
cd /var/www/html/nextcloud/
sudo -u apache php occ maintenance:mode --on
mysqldump --lock-tables -u root -p nextclouddb > /var/www/html/nextcloud/data/nextcloud-sqlbkp_`date +"%Y%m%d"`.bak
tar -cvpzf /var/www/html/nextcloud/data/tyrell_backup_`date +%Y%m%d%H%M%S`.tar.gz --exclude=/var/www/html/nextcloud/data/ed --exclude=/var/www/html/nextcloud/data/tyrell_backup*.tar.gz --one-file-system /
cd /var/www/html/nextcloud/
sudo -u apache php occ maintenance:mode --off
