#!/bin/bash


if [[ $EUID -ne 0 ]]; then
  echo -e "Error: You need to run this script as root (UID=0)"
  exit 1
fi

if [ -p /dev/stdin ]; then
  echo -e "Error: This script can't be piped!"
  exit 1
fi


echo -e "The management server will restart. You must reconnect to re-establish a connection."
sleep 2
systemctl restart rns_server_management
exit 0


exit 1