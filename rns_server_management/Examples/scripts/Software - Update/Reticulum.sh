#!/bin/bash


if [[ $EUID -ne 0 ]]; then
  echo -e "Error: You need to run this script as root (UID=0)"
  exit 1
fi

if [ -p /dev/stdin ]; then
  echo -e "Error: This script can't be piped!"
  exit 1
fi


LOG_FILE="/tmp/scripts.log"
echo "" > "${LOG_FILE}"


echo -ne "Updating Reticulum..."
if ! pip3 install rns --upgrade >> "${LOG_FILE}" 2>&1; then
  echo -e " failed!"
  exit 1
fi
echo -e " OK!"


echo -e "Finished!"


exit 0