#!/bin/bash
# Script used as a quick run to push updates to a repository
cd $HOME/scripts_repo
git add *
git commit -m "update from work"
git push
git status
