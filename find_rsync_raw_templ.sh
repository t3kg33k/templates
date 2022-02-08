#!/bin/bash
# Look for files with a specific extention and rsync to a different directory
find $HOME/Pictures/2018 -name \*.NEF -print0 | xargs -I{} -0 rsync -a --progress {} $HOME/Pictures/Raw
