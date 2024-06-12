#!/bin/bash


if [[ $EUID -ne 0 ]]; then
  echo -e "Error: You need to run this script as root (UID=0)"
  exit 1
fi

if [ -p /dev/stdin ]; then
  echo -e "Error: This script can't be piped!"
  exit 1
fi


files=(/etc/systemd/system/bridge_*)
if [ ${#files[@]} -eq 0 ]; then
  echo "No installed services found. Exiting."
  exit 1
fi

if [ "${files[0]}" == "/etc/systemd/system/bridge_*" ]; then
  echo "No installed services found. Exiting."
  exit 1
fi

filenames=()
for file in "${files[@]}"; do
  filenames+=("$(basename "$file")")
done

LOOP=1
while [ $LOOP -eq 1 ]; do
  echo -e ""
  echo -e "Select a service:"
  select opt in "${filenames[@]}"; do
    if [ -n "$opt" ]; then
      SETTINGS_SERVICE_NAME="$opt"
      LOOP=0
      break
    else
      echo -e ""
      echo -e "Invalid choice!"
    fi
  done
done


systemctl stop "$SETTINGS_SERVICE_NAME" || true
systemctl disable "$SETTINGS_SERVICE_NAME" || true

rm -f "/etc/systemd/system/$SETTINGS_SERVICE_NAME"

systemctl daemon-reload


echo -e "Uninstallation successfully completed!"
echo -e ""
echo -e "Finished!"


exit 0