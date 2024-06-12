#!/bin/bash


echo -e "Hello!"
echo -e ""
read -p "Hit enter to start."


echo -ne "Checking test 1..."
echo -e " OK!"


echo -ne "Checking test 2..."
sleep 5s
echo -e " OK!"


echo -ne "Checking test 3..."
sleep 5s
echo -e " nok."


echo -ne "Checking test 4..."
sleep 5s
echo -e " failed!"


echo -e ""
echo -e "Finished!"


exit 0