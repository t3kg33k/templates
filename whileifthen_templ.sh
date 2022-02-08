#!/bin/bash

# Ask for input and if input is not properly met keep asking until met

#echo " Which team do you prefer, FSU or UF?"
#read -r TEAM
#while [[ "$TEAM" != "FSU" && "$TEAM" != "UF" ]]; do
#	echo "That was not one of your choices. Please choose FSU or UF"
#	read -r TEAM
#done
#if [ "$TEAM" == "FSU" ]; then
#	echo "You chose the better team"
#else [ "$TEAM" == "UF" ]; 
#	echo "You did NOT choose the better team"
#fi

echo " Which NCAA team is the best?"
read -r TEAM
while [[ "$TEAM" != "FSU" ]]; do
	echo "Nope. Your choice is not valid"
	read -r TEAM
if [ "$TEAM" == "FSU" ];
then
	echo "You picked a winner!"
fi
done
