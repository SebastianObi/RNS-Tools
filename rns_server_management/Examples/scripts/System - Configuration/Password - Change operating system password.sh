#!/bin/bash


if [[ $EUID -ne 0 ]]; then
  echo -e "Error: You need to run this script as root (UID=0)"
  exit 1
fi

if [ -p /dev/stdin ]; then
  echo -e "Error: This script can't be piped!"
  exit 1
fi


USERS=()
USERS+=("root")
USERLIST=$(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
for s in $USERLIST; do
  USERS+=("$s")
done


if [ ${#USERS[@]} -eq 0 ]; then
  echo -e "Could not find any user, exiting now."
  exit 1
fi


while true; do
  if [ ${#USERS[@]} -eq 1 ]; then
    REPLY=0
    echo -e ""
    echo -e "Define the password for user '${USERS[$REPLY]}':"
    read -sp "" VAR
    echo -e ""
    echo -ne "Updating password..."
    if echo -e "$VAR\n$VAR" | passwd ${USERS[$REPLY]} >> /dev/null 2>&1; then
      echo -e " OK!"
      break
    else
      echo -e " failed!"
      break
    fi
  else
    echo -e "Which user would you like to edit?"
    select USER in "${USERS[@]}"; do
      REPLY=$REPLY-1
      if [[ ${USERS[$REPLY]} ]]; then
        echo -e ""
        echo -e "Define the password for user '${USERS[$REPLY]}':"
        read -sp "" VAR
        echo -e ""
        echo -ne "Updating password..."
        if echo -e "$VAR\n$VAR" | passwd ${USERS[$REPLY]} >> /dev/null 2>&1; then
          echo -e " OK!"
          break
        else
          echo -e " failed!"
          break
        fi
      fi
    done
  fi

  if [ ${#USERS[@]} -eq 1 ]; then
    break
  fi

  echo -e ""
  read -p "Do you want to edit another user? [y/n]" YN
    case $YN in 
      [Yy]*)
        ;;
      [Nn]*)
        break;;
      *)
        echo -e ""
        echo -e "Please answer yes or no.";;
    esac
done


echo -e "Finished!"


exit 0