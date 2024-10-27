# rns_announce_directory
This program provides the collection and storage of received announcements in a database. These can then later be read and displayed from a NomadNet page.

For more information, see the configuration options (at the end of the program files). Everything else is briefly documented there. After the first start this configuration will be created as default config in the corresponding file.


### Features
- Compatible with (NomadNet, ...)


## Current Status
It should currently be considered beta software and still work in progress.

All core features are implemented and functioning, but additions will probably occur as real-world use is explored.

There may be errors or the compatibility after an update is no longer guaranteed.

The full documentation is not yet available. Due to lack of time I can also not say when this will be further processed.


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
- Install all required prerequisites.
  ```bash
  pip3 install sqlite3
  pip3 install psycopg2
  pip3 install psycopg2-binary
  ```
- Change the Reticulum configuration to suit your needs and use-case.
  ```bash
  nano /.reticulum/config
  ```
- Download the [file](rns_announce_directory.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/RNS-Tools/main/rns_announce_directory/rns_announce_directory.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x rns_announce_directory.py
  ```

### NomadNet files:
- Copy the NonadNet .mu files into your page directory. Pay attention to the filename or change the configuration in the .mu files to get the access to the correct database.
- By default the database folder is identical to the filename.

### Start:
- Start it
  ```bash
  ./rns_announce_directory.py
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.
- Example minimal configuration (override of the default config `config.cfg`). These are the most relevant settings that need to be adjusted. All other settings are in `config.cfg`
  ```bash
  nano /root/.rns_announce_directory/config.cfg.owr
  ```
  ```bash
  ```
- Start it again. Finished!
  ```bash
  ./rns_announce_directory.py
  ```


### Run as a system service/deamon:
- Create a service file.
  ```bash
  nano /etc/systemd/system/rns_announce_directory.service
  ```
- Copy and edit the following content to your own needs.
  ```bash
  [Unit]
  Description=rns_announce_directory
  After=multi-user.target
  [Service]
  # ExecStartPre=/bin/sleep 10
  Type=simple
  Restart=always
  RestartSec=3
  User=root
  Group=root
  ExecStart=/root/rns_announce_directory.py
  [Install]
  WantedBy=multi-user.target
  ```
- Enable the service.
  ```bash
  systemctl enable rns_announce_directory
  ```
- Start the service.
  ```bash
  systemctl start rns_announce_directory
  ```


### Start/Stop service:
  ```bash
  systemctl start rns_announce_directory
  systemctl stop rns_announce_directory
  ```


### Enable/Disable service:
  ```bash
  systemctl enable rns_announce_directory
  systemctl disable rns_announce_directory
  ```


### Run several instances (To copy the same application):
- Run the program with a different configuration path.
  ```bash
  ./rns_announce_directory.py -p /root/.rns_announce_directory_2nd
  ./rns_announce_directory.py -p /root/.rns_announce_directory_3nd
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.


### First usage:
- There is nothing to consider here.


### Startup parameters:
```bash
usage: rns_announce_directory.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--exampleconfig] [--exampleconfigoverride] [--cmd]
                                 [--cmd_status]

RNS Announce Directory - Database for the collection of received announcements

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
  --cmd                 Database command interface (Execute any sql database command)
  --cmd_status          Database status interface (Shows the current status)
```


### Config/data files:
- config.cfg
  
  This is the default config file.

- config.cfg.owr
  
  This is the user configuration file to override the default configuration file.
  All settings made here have precedence.
  This file can be used to clearly summarize all settings that deviate from the default.
  This also has the advantage that all changed settings can be kept when updating the program.


## FAQ

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)