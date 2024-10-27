# rns_server_provisioning
This program offers the possibility of provisioning clients. This includes, for example: The announcement of software updates. Registration of new users. Saving telemetry data that the clients send to the server. The data is stored in a PostgreSQL database. The source code can of course be customized to store the data in a different way.

For more information, see the configuration options (at the end of the program files). Everything else is briefly documented there. After the first start this configuration will be created as default config in the corresponding file.


### Features
- Compatible with all Reticulum managed apps (Communicator which is another project that is not part of this github)
- Announcement of the server and software versions
- User registration
- Collection of telemetry data
- Storage of data in PostgreSQL, ...


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
  pip3 install psycopg2
  pip3 install psycopg2-binary
  ```
- Change the Reticulum configuration to suit your needs and use-case.
  ```bash
  nano /.reticulum/config
  ```
- Download the [file](rns_server_provisioning.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/RNS-Tools/main/rns_server_provisioning/rns_server_provisioning.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x rns_server_provisioning.py
  ```

### Start:
- Start it
  ```bash
  ./rns_server_provisioning.py
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.
- Example minimal configuration (override of the default config `config.cfg`). These are the most relevant settings that need to be adjusted. All other settings are in `config.cfg`
  ```bash
  nano /root/.rns_server_provisioning/config.cfg.owr
  ```
  ```bash
  ```
- Start it again. Finished!
  ```bash
  ./rns_server_provisioning.py
  ```


### Run as a system service/deamon:
- Create a service file.
  ```bash
  nano /etc/systemd/system/rns_server_provisioning.service
  ```
- Copy and edit the following content to your own needs.
  ```bash
  [Unit]
  Description=rns_server_provisioning
  After=multi-user.target
  [Service]
  # ExecStartPre=/bin/sleep 10
  Type=simple
  Restart=always
  RestartSec=3
  User=root
  Group=root
  ExecStart=/root/rns_server_provisioning.py
  [Install]
  WantedBy=multi-user.target
  ```
- Enable the service.
  ```bash
  systemctl enable rns_server_provisioning
  ```
- Start the service.
  ```bash
  systemctl start rns_server_provisioning
  ```


### Start/Stop service:
  ```bash
  systemctl start rns_server_provisioning
  systemctl stop rns_server_provisioning
  ```


### Enable/Disable service:
  ```bash
  systemctl enable rns_server_provisioning
  systemctl disable rns_server_provisioning
  ```


### Run several instances (To copy the same application):
- Run the program with a different configuration path.
  ```bash
  ./rns_server_provisioning.py -p /root/.rns_server_provisioning_2nd
  ./rns_server_provisioning.py -p /root/.rns_server_provisioning_3nd
  ```


### First usage:
- With a manual start via the console, the own RNS address is displayed:
  ```
  [] ...............................................................................
  [] RNS - Address: <801f48d54bc71cb3e0886944832aaf8d>
  [] ...............................................................................`
  ```
- This address is also annouced at startup in the default setting.
- This provisioning server address must be added to the clients.
- Now the software can be used.


### Startup parameters:
```bash
usage: rns_server_provisioning.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--exampleconfig] [--exampleconfigoverride]

RNS Server Provisioning - Provisioning for RNS based apps

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


## FAQ

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)