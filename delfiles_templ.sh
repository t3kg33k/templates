#!/bin/bash
# Delete files older than 15 days
find /directory/*.tar.gz -mtime +15 -exec rm {} \;
