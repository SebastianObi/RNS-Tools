# rns_server_shop
This program provides a server for shop hosting of the "Communicator" app.


### Features
- Compatible with all Reticulum shop apps (Communicator)


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
  
  pip3 install lxmf
  ```
- Change the Reticulum configuration to suit your needs and use-case.
  ```bash
  nano /.reticulum/config
  ```
- Download the [file](rns_server_shop.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/RNS-Tools/main/rns_server_shop/rns_server_shop.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x rns_server_shop.py
  ```

### Start:
- Start it. Finished!
  ```bash
  ./rns_server_shop.py
  ```
- After the first start you must perform the initial configuration. This is done in the client application.
- To do this, start the client app and then the shop server. In the announcement list you should see a new unconfigured shop. Open it to take over the administration. The first active user who opens a shop will automatically become the administrator.


### Run as a system service/deamon:
- Create a service file.
  ```bash
  nano /etc/systemd/system/rns_server_shop.service
  ```
- Copy and edit the following content to your own needs.
  ```bash
  [Unit]
  Description=rns_server_shop.py Daemon
  After=multi-user.target
  [Service]
  # ExecStartPre=/bin/sleep 10
  Type=simple
  Restart=always
  RestartSec=3
  User=root
  Group=root
  ExecStart=/root/rns_server_shop.py
  [Install]
  WantedBy=multi-user.target
  ```
- Enable the service.
  ```bash
  systemctl enable rns_server_shop
  ```
- Start the service.
  ```bash
  systemctl start rns_server_shop
  ```


### Start/Stop service:
  ```bash
  systemctl start rns_server_shop
  systemctl stop rns_server_shop
  ```


### Enable/Disable service:
  ```bash
  systemctl enable rns_server_shop
  systemctl disable rns_server_shop
  ```


### Run several instances (To copy the same application):
- Run the program with a different configuration path.
  ```bash
  ./rns_server_shop.py -p /root/.rns_server_shop_2nd
  ./rns_server_shop.py -p /root/.rns_server_shop_3nd
  ```
- After the first start you must perform the initial configuration. This is done in the client application.
- To do this, start the client app and then the shop server. In the announcement list you should see a new unconfigured shop. Open it to take over the administration. The first active user who opens a shop will automatically become the administrator.


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
usage: rns_server_shop.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--cmd] [--cmd_status]

RNS Server Shop - Shop hosting functions for RNS based apps

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Path to alternative config directory
  -pr PATH_RNS, --path_rns PATH_RNS
                        Path to alternative Reticulum config directory
  -pl PATH_LOG, --path_log PATH_LOG
                        Path to alternative log directory
  -l LOGLEVEL, --loglevel LOGLEVEL
  -s, --service         Running as a service and should log to file
  --cmd                 Database command interface (Execute any sql database command)
  --cmd_status          Database status interface (Shows the current status)
```


### Config/data files:
- database.db
  
  This is the database file.
  
  There are no direct configuration files. The configuration is done completely with the client app and stored in the database.


## FAQ

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)