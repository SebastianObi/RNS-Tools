#!/bin/bash


echo -e "Hello!"
echo -e ""
read -p "#1 Hit enter to start."


echo -e ""
read -p "#2 Do you want to proceed? [y/n]" YN
case $YN in 
  [Yy])
    echo -e "Ok, proceeding..."
    ;;
  [Nn])
    echo -e "No, exiting now."
    exit 1
    ;;
  *)
    echo -e "Please answer yes or no."
    ;;
esac


echo -e ""
read -p "#3 Do you want to proceed? (y/n)" YN
case $YN in 
  [Yy])
    echo -e "Ok, proceeding..."
    ;;
  [Nn])
    echo -e "No, exiting now."
    exit 1
    ;;
  *)
    echo -e "Please answer yes or no."
    ;;
esac


echo -e ""
read -p "#4 Do you want to proceed? [yes/no]" YN
case $YN in 
  yes)
    echo -e "Ok, proceeding..."
    ;;
  no)
    echo -e "No, exiting now."
    exit 1
    ;;
  *)
    echo -e "Please answer yes or no."
    ;;
esac


echo -e ""
read -p "#5 Do you want to proceed? (yes/no)" YN
case $YN in 
  yes)
    echo -e "Ok, proceeding..."
    ;;
  no)
    echo -e "No, exiting now."
    exit 1
    ;;
  *)
    echo -e "Please answer yes or no."
    ;;
esac


echo -e ""
read -p "#6 Do you want to proceed? [y/n/c]" YN
case $YN in 
  [Yy])
    echo -e "Ok, proceeding..."
    ;;
  [Nn])
    echo -e "No, exiting now."
    exit 1
    ;;
  [Cc])
    echo -e "Cancel, exiting now."
    exit 1
    ;;
  *)
    echo -e "Please answer yes or no."
    ;;
esac


echo -e ""
read -p "#7 Do you want to proceed? (y/n/c)" YN
case $YN in 
  [Yy])
    echo -e "Ok, proceeding..."
    ;;
  [Nn])
    echo -e "No, exiting now."
    exit 1
    ;;
  [Cc])
    echo -e "Cancel, exiting now."
    exit 1
    ;;
  *)
    echo -e "Please answer yes or no."
    ;;
esac


echo -e ""
echo -e "#8 What option do you want to choose?"
echo -e "1. Option 1"
echo -e "2. Option 2"
echo -e "3. Option 3"
read OPTION
case $OPTION in
  [1])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [2])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [3])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  *)
    echo -e "Error: That option does not exist, exiting now."
    exit 1
    ;;
esac


echo -e ""
echo -e "#9 What option do you want to choose?"
echo -e "[1] Option 1"
echo -e "[2] Option 2"
echo -e "[3] Option 3"
read OPTION
case $OPTION in
  [1])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [2])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [3])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  *)
    echo -e "Error: That option does not exist, exiting now."
    exit 1
    ;;
esac


echo -e ""
echo -e "#10 What option do you want to choose?"
unset OPTIONS
OPTIONS+=("Option 1")
OPTIONS+=("Option 2")
OPTIONS+=("Option 3")
select OPTION in "${OPTIONS[@]}"; do
  case ${OPTION} in
    $OPTIONS)
      echo -e "Ok, selected: ${OPTION}"
      break
      ;;
    *)
      echo -e "Error: That option does not exist, exiting now."
      exit 1
      ;;
  esac
done


echo -e ""
echo -e "#11 What option do you want to choose?"
unset OPTIONS
OPTIONS+=("Option 1")
OPTIONS+=("Option 2")
OPTIONS+=("Option 3")
OPTIONS+=("Option-4")
OPTIONS+=("Option-5")
OPTIONS+=("Option-6")
OPTIONS+=("Option 7")
OPTIONS+=("Option 8")
OPTIONS+=("Option 9")
OPTIONS+=("None/Exit")
select OPTION in "${OPTIONS[@]}"; do
  case ${OPTION} in
    $OPTIONS)
      echo -e "Ok, selected: ${OPTION}"
      break
      ;;
    *)
      echo -e "Error: That option does not exist, exiting now."
      exit 1
      ;;
  esac
done


echo -e ""
echo -e "#12 What option do you want to choose? [1/2/3/4/5]"
read OPTION
case $OPTION in
  [1])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [2])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [3])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [4])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [5])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  *)
    echo -e "Error: That option does not exist, exiting now."
    exit 1
    ;;
esac


echo -e ""
echo -e "#13 What option do you want to choose? (1/2/3/4/5)"
read OPTION
case $OPTION in
  [1])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [2])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [3])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [4])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  [5])
    echo -e "Ok, selected: ${OPTION}"
    ;;
  *)
    echo -e "Error: That option does not exist, exiting now."
    exit 1
    ;;
esac


echo -e ""
read -p "#14 Enter username/text:" TEXT;
echo -e "Ok, username/text: ${TEXT}"


echo -e ""
read -s -p "#15 Enter password:" TEXT;
echo -e "Ok, password: ${TEXT}"


echo -e ""
echo -e "Finished!"


exit 0