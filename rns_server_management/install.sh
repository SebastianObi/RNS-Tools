#!/bin/bash


##############################################################################################################
# Configuration


SOFTWARE_NAME="rns_server_management"
SOFTWARE_PATH_SRC=$(dirname $(realpath $0))
SOFTWARE_PATH_DST="/usr/local/bin"
SOFTWARE_CONFIG_SRC="$SOFTWARE_PATH_SRC/Examples"
SOFTWARE_CONFIG_DST="$HOME/.config/$SOFTWARE_NAME"
RETICULUM_CONFIG_DST=("$HOME/.config/reticulum" "$HOME/.reticulum")


##############################################################################################################
# Functions


_divider() {
  echo -e "..............................................................................."
}


_settings_user() {
  SETTINGS_USER=$USER
  SETTINGS_USER_TARGET=""

  USERS=()
  USERS+=("root")
  USERLIST=$(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
  for s in $USERLIST; do
    USERS+=("$s")
  done

  if [ ${#USERS[@]} -ne 1 ]; then
    echo -e "Do you want the installed services to run under a different user? If so, please select a user."
    select OPTION in "${USERS[@]}"; do
      REPLY=$REPLY-1
      if [[ ${USERS[$REPLY]} ]]; then
        if [ "${USERS[$REPLY]}" != "root" ]; then
          SETTINGS_USER="${USERS[$REPLY]}"
          SETTINGS_USER_TARGET="user_target = ${USERS[$REPLY]}"
          RETICULUM_CONFIG_DST_TMP=("/home/${USERS[$REPLY]}/.config/reticulum" "/home/${USERS[$REPLY]}/.reticulum", "${RETICULUM_CONFIG_DST[@]}")
          RETICULUM_CONFIG_DST=("${RETICULUM_CONFIG_DST_TMP[@]}")
        fi
      fi
      break
    done
  fi
}


_install_core_software() {
  if ! command -v python3-pip; then
      apt -y -q update
      apt install python3-pip
  fi

  pip3 install rns
  pip3 install pyserial netifaces
  pip3 install lxmf
  pip3 install nomadnet
}


_install_core_config() {
  if [ "$SETTINGS_USER" != "$USER" ]; then
    CONFIG_FOLDER="/home/$SETTINGS_USER/.config/reticulum"
  else
    CONFIG_FOLDER="$HOME/.config/reticulum"
  fi

  mkdir -p "$CONFIG_FOLDER"

  cat <<EOF | tee "$CONFIG_FOLDER/config" > /dev/null
[reticulum]
  enable_transport = True 
  share_instance = Yes
  shared_instance_port = 37428
  instance_control_port = 37429
  panic_on_interface_error = No

[logging]
  loglevel = 6

[interfaces]

[[Default Interface]]
type = AutoInterface
enabled = True
mode = gateway
networkname = fdn
passphrase = FreieDeutscheGesellschaft

[[TCP FDN]]
type = TCPClientInterface
enabled = True
outgoing = True
mode = boundary
target_host = fdn.freiedeutschegesellschaft.org
target_port = 42043
networkname = fdn
passphrase = FreieDeutscheGesellschaft
EOF

  if [ "$SETTINGS_USER" != "$USER" ]; then
    chown -R $SETTINGS_USER $CONFIG_FOLDER
  fi
}


_install_core_service() {
  cat <<EOF | tee "/etc/systemd/system/rnsd.service" > /dev/null
[Unit]
Description=Reticulum Network Stack Daemon
After=multi-user.target

[Service]
#ExecStartPre=/bin/sleep 10
Type=simple
Restart=always
RestartSec=3
User=$SETTINGS_USER
ExecStart=rnsd --service

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload

  systemctl enable rnsd
  systemctl start rnsd
}


_install_software() {
  #pip3 install polib
  apt -y -q update
  apt -y -q install python3-polib

  cp -a "$SOFTWARE_PATH_SRC"/*.py "$SOFTWARE_PATH_DST"
  chmod +x "$SOFTWARE_PATH_DST"/*.py
}


_install_config() {
  mkdir -p "$SOFTWARE_CONFIG_DST"
  cp -r "$SOFTWARE_CONFIG_SRC"/* "$SOFTWARE_CONFIG_DST"
  find "$SOFTWARE_CONFIG_DST" -type f -name "*.sh" -exec chmod +x {} \;
  find "$SOFTWARE_CONFIG_DST" -type f -name "*.py" -exec chmod +x {} \;


  read -p "Enter the display name for the application: " SETTINGS_DISPLAY_NAME_RAW
  SETTINGS_DISPLAY_NAME="$SETTINGS_DISPLAY_NAME_RAW"

  read -p "Enter the admin user address: " SETTINGS_ALLOWED_RAW
  SETTINGS_ALLOWED="$SETTINGS_ALLOWED_RAW"


  cat <<EOF | tee "$SOFTWARE_CONFIG_DST/config.cfg.owr" > /dev/null
# This is the user configuration file to override the default configuration file.
# All settings made here have precedence.
# This file can be used to clearly summarize all settings that deviate from the default.
# This also has the advantage that all changed settings can be kept when updating the program.


#### Main program settings ####
[main]
fields_announce = False


#### RNS server settings ####
[rns_server]
display_name = $SETTINGS_DISPLAY_NAME

announce_startup = Yes
announce_startup_delay = 0 #Seconds

announce_periodic = Yes
announce_periodic_interval = 120 #Minutes


#### Telemetry settings ####
[telemetry]
location_enabled = False
location_lat = 0
location_lon = 0

state_enabled = False
state_data = 0


#### Right settings ####
[allowed]
$SETTINGS_ALLOWED


#### Environment settings ####
[environment_variables]
$SETTINGS_USER_TARGET
EOF
}


_install_service() {
  RETICULUM_CONFIG=""
  for folder in "${RETICULUM_CONFIG_DST[@]}"; do
    if [ -e "$folder" ]; then
        RETICULUM_CONFIG=" -pr $folder"
      break
    fi
  done

  cat <<EOF | tee "/etc/systemd/system/$SOFTWARE_NAME.service" > /dev/null
[Unit]
Description=$SOFTWARE_NAME
After=multi-user.target

[Service]
ExecStartPre=/bin/sleep 10
Type=simple
Restart=always
RestartSec=3
User=$USER
ExecStart=$SOFTWARE_PATH_DST/$SOFTWARE_NAME.py$RETICULUM_CONFIG

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload

  systemctl enable "$SOFTWARE_NAME"
  systemctl start "$SOFTWARE_NAME"
}


_install_footer() {
  _divider
  echo -e "You have successfully installed $SOFTWARE_NAME"
  echo -e "To edit the configuration please edit the files in the following folder and then restart the service:"
  echo -e $SOFTWARE_CONFIG_DST
  _divider
}


_uninstall_software() {
  echo -e ""
}


_uninstall_service() {
  systemctl stop "$SOFTWARE_NAME" || true
  systemctl disable "$SOFTWARE_NAME" || true

  rm -f "/etc/systemd/system/$SOFTWARE_NAME"

  systemctl daemon-reload
}


_uninstall_footer() {
  _divider
  echo -e "You have successfully uninstalled $SOFTWARE_NAME"
  _divider
}


_update_software() {
  cp -a "$SOFTWARE_PATH_SRC"/*.py "$SOFTWARE_PATH_DST"
  chmod +x "$SOFTWARE_PATH_DST"/*.py
}


_update_footer() {
  _divider
  echo -e "You have successfully updated $SOFTWARE_NAME"
  echo -e "In order for it to become active, you must restart the individual services or restart the entire operating system."
  _divider
}


_reboot() {
  echo -e "You need to reboot the system."
  echo -e "Do you want to do this now?"

  LOOP=1
  while [ $LOOP -eq 1 ]; do
    options=("Yes, reboot now" "No, reboot manually")
    select opt in "${options[@]}"; do
      case $opt in
      "Yes, reboot now"*)
        echo -e ""
        echo -e "Rebooting..."
        init 6
        LOOP=0
        break;;
      "No, reboot manually"*)
        echo -e ""
        LOOP=0
        break;;
      *)
        echo -e ""
        echo -e "Invalid choice!";;
      esac
    done
  done
}


##############################################################################################################
# Setup/Start


if [[ $EUID -ne 0 ]]; then
  echo -e "Error: You need to run this script as root (UID=0)"
  exit 1
fi

if [ -p /dev/stdin ]; then
  echo -e "Error: This script can't be piped!"
  exit 1
fi

_divider
echo -e "Installer/uninstaller for $SOFTWARE_NAME"
_divider

echo -e "If Reticulum is already installed, please select 2, otherwise please select 1."
echo -e "The installation of the dependencies may not work on some systems. In this case, please install Reticulum manually and then select 2."

  LOOP=1
  while [ $LOOP -eq 1 ]; do
    echo -e ""
    echo -e "Select a function:"
    options=("Install Core+Software" "Install" "Uninstall" "Update" "None/Exit")
    select opt in "${options[@]}"; do
      case $opt in
      "Install Core+Software"*)
        echo -e ""
        _settings_user
        _install_core_software
        _install_core_config
        _install_core_service
        _install_software
        _install_config
        _install_service
        _install_footer
        _reboot
        LOOP=0
        break;;
      "Install"*)
        echo -e ""
        _settings_user
        _install_software
        _install_config
        _install_service
        _install_footer
        _reboot
        LOOP=0
        break;;
      "Uninstall"*)
        echo -e ""
        _uninstall_software
        _uninstall_service
        _uninstall_footer
        LOOP=0
        break;;
      "Update"*)
        _update_software
        _update_footer
        LOOP=0
        break;;
      "None/Exit"*)
        echo -e ""
        LOOP=0
        break;;
      *)
        echo -e ""
        echo -e "Invalid choice!";;
      esac
    done
  done
