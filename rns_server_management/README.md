# rns_server_management
This program provides a server for system management and administration over Reticulum. And work in conjunction with the client app (which is not yet released).


### Features
- View system/software/hardware status.
- Running external scripts/programs as a wizard and display in the client interface.
- Translate wizard output to different languages.
- Manage services (Start/Stop/Enable/Disable).
- File explorer (Copy/Move/Rename/Download/Upload).
- Console/Terminal.
- View log files.
- Multi language support.
- Customizable folder/object structure.
- Easy to integrate additional configurations.
- Relatively easy to customize (even without programming knowledge) within the given widgets/elements.

For more information, see the configuration options (at the end of the program files). Everything else is briefly documented there. After the first start this configuration will be created as default config in the corresponding file.


## Current Status
It should currently be considered beta software and still work in progress.

All core features are implemented and functioning, but additions will probably occur as real-world use is explored.

There may be errors or the compatibility after an update is no longer guaranteed.

The full documentation is not yet available. Due to lack of time I can also not say when this will be further processed.


## Quick commands

Installation - Easy:
```bash
wget -O - https://example.com/path/to/rns_server_management.tar.gz | tar -xzvf - --one-top-level=install_files && chmod +x install_files/install.sh && ./install_files/install.sh
```


Installation - Easy (Already downloaded):
```bash
tar -xzvf rns_server_management.tar.gz --one-top-level=install_files && chmod +x install_files/install.sh && ./install_files/install.sh
```


Installation:

- Copy all files and folders to a temporary folder.
- Make it executable with the following command.
  ```bash
  chmod +x install.sh
  ```
- Execute it.
```bash
./install.sh
```


## Installation manual

### Install:
- Install all required prerequisites. (Default Reticulum installation. Only necessary if reticulum is not yet installed.)
  ```bash
  apt update
  apt upgrade
  
  apt install python3-pip
  
  pip install pip --upgrade
  reboot
  
  pip3 install rns
  pip3 install pyserial netifaces
  ```
- Change the Reticulum configuration to suit your needs and use-case.
  ```bash
  nano /.reticulum/config
  ```
- Download the [file](rns_server_management.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/RNS-Tools/main/rns_server_management/rns_server_management.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x rns_server_management.py
  ```

### Start:
- Start it
  ```bash
  ./rns_server_management.py
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.
- Example minimal configuration (override of the default config `config.cfg`). These are the most relevant settings that need to be adjusted. All other settings are in `config.cfg`
  ```bash
  nano /root/.rns_server_management/config.cfg.owr
  ```
  ```bash
  ```
- Start it again. Finished!
  ```bash
  ./rns_server_management.py
  ```


### Run as a system service/deamon:
- Create a service file.
  ```bash
  nano /etc/systemd/system/rns_server_management.service
  ```
- Copy and edit the following content to your own needs.
  ```bash
  [Unit]
  Description=rns_server_management
  After=multi-user.target
  [Service]
  # ExecStartPre=/bin/sleep 10
  Type=simple
  Restart=always
  RestartSec=3
  User=root
  Group=root
  ExecStart=/root/rns_server_management.py
  [Install]
  WantedBy=multi-user.target
  ```
- Enable the service.
  ```bash
  systemctl enable rns_server_management
  ```
- Start the service.
  ```bash
  systemctl start rns_server_management
  ```


### Start/Stop service:
  ```bash
  systemctl start rns_server_management
  systemctl stop rns_server_management
  ```


### Enable/Disable service:
  ```bash
  systemctl enable rns_server_management
  systemctl disable rns_server_management
  ```


### Run several instances (To copy the same application):
- Run the program with a different configuration path.
  ```bash
  ./rns_server_management.py -p /root/.rns_server_management_2nd
  ./rns_server_management.py -p /root/.rns_server_management_3nd
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.


### First usage:
- With a manual start via the console, the own RNS address is displayed:
  ```
  [] ...............................................................................
  [] RNS - Address: <801f48d54bc71cb3e0886944832aaf8d>
  [] ...............................................................................`
  ```
- This address is also annouced at startup in the default setting.
- Now the software can be used.


### Startup parameters:
```bash
usage: rns_server_management.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--exampleconfig] [--exampleconfigoverride]

RNS Server Management

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Path to alternative config directory
  -pr PATH_RNS, --path_rns PATH_RNS
                        Path to alternative Reticulum config directory
  -pl PATH_LOG, --path_log PATH_LOG
                        Path to alternative log directory
  -l LOGLEVEL, --loglevel LOGLEVEL
  -s, --service         Running as a service and should log to file
  --exampleconfig       Print verbose configuration example to stdout and exit
  --exampleconfigoverride
                        Print verbose configuration example to stdout and exit
```


### Config/data files:
- config.cfg
  
  This is the default config file.

- config.cfg.owr
  
  This is the user configuration file to override the default configuration file.
  All settings made here have precedence.
  This file can be used to clearly summarize all settings that deviate from the default.
  This also has the advantage that all changed settings can be kept when updating the program.


## Instructions for the administration

In each folder that is relevant for the administration there are example folders and files. These files should explain the functionality of this tool.


### Folders
- configs

This folder is used for the "configs" functionality. Each subfolder provides a main menu item. All files in a folder are then processed together and displayed on one page in the app.
Executable files are executed and the returned data (json string) is used. Json is used for receiving and sending the configuration. This data can then be further processed as required within the executable file/script.

JSON input:
```
{"<key>": <value>}
{"Example": "Test data"}
```

JSON output:
```
{"<key>": ["<icon>", "<text line 1>", "<text line 2>", "<type>", "<current value>", "<default value>"]}
{"Example": ["text", "Text input", "GUI test", "t", "Some text", ""]}
```

- infos

This folder is used for the "infos" functionality. Each subfolder provides a main menu item. All files in a folder are then processed together and displayed on one page in the app.
Executable files are executed and the returned data (json string) is used. Non-executable files are read directly as a json string.

JSON output:
```
{"<text line 1>": ["<text line 2>", "<text line 3>", "<icon>", <status>]}
{"Example": ["Test data", "", "text", 0]}
```

The following hex/integer status values can be used:
```
0x00: None/Empty
0x01: OK
0x01: Info
0x03: Warning
0x04: Error
0x05: Critical
0xFF: Unknown
```

- locales
This folder contains the gettext translations for all functions of the server. If a match is found, the text/menu is translated automatically. New text blocks must be added to the "base.pot" file and then defined for the respective languages.

- logs

This folder is used for the "logs" functionality. Each subfolder provides a main menu item. All files in a folder provides a sub menu item for one page.
Executable files are executed and the returned data (plain text string) is used. Non-executable files are read line by line where each line contains a path to a log file. If there is a match (file exists), this is read in as a plain text string and then returned. Only the first file is used.

- scripts

This folder is used for the "scripts" functionality. Each subfolder provides a main menu item. All files in a folder provides a sub menu item for one page.
Only executable files can be used. The executable file or script is then started in a console. The output and input is done as plain text. The output is processed in the app and translated into GUI elements. 

- services

This folder is used for the "services" functionality. Each subfolder provides a main menu item. All files in a folder are then processed together and displayed on one page in the app.
Executable files are executed and the returned data (json string) is used. Json is used for sending the service status information.

JSON output:
```
{"<service name>": ["<enabled status>", "<running status>"]}
{"Example": ["disabled", "inactive"]}
```

The following hex/integer enabled status values can be used:
```
0x00: Disabled
0x01: Enabled
0x02: Manual
0x03: Permanently disabled
0x04: Alias
0xFF: Unknown
```

The following hex/integer running status values can be used:
```
0x00: Inactive
0x01: Active
0x02: Activating
0x03: Deactivating
0x04: Failed
0xFF: Unknown
```


## FAQ

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)