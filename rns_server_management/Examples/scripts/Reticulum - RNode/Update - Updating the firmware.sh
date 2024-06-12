#!/bin/bash


if [[ $EUID -ne 0 ]]; then
  echo -e "Error: You need to run this script as root (UID=0)"
  exit 1
fi

if [ -p /dev/stdin ]; then
  echo -e "Error: This script can't be piped!"
  exit 1
fi


echo -e "Please connect the device you wish to setup now."
read -p "Hit enter when it is connected."


PORTS=()
PORTLIST=$(ls /dev/ | grep 'ttyACM\|ttyUSB')
for s in $PORTLIST; do
  PORTS+=("/dev/$s")
done

if [ -d "/dev/serial/by-id/" ]; then
  PORTLIST=$(ls /dev/serial/by-id/)
  for s in $PORTLIST; do
    PORTS+=("/dev/serial/by-id/$s")
  done
fi


if [ ${#PORTS[@]} -eq 0 ]; then
  echo -e "Could not find any port, exiting now."
  exit 1
fi


echo -e "What serial port is your device connected to?"
select PORT in "${PORTS[@]}"; do
  REPLY=$REPLY-1
  if [[ ${PORTS[$REPLY]} ]]; then
    echo -e "Ok, using device on ${PORTS[$REPLY]}"
    rnodeconf ${PORTS[$REPLY]} -u
    exit 0
  else
    echo -e "Could not find specified port, exiting now."
    exit 1
  fi
done


echo -e "Finished!"


exit 0