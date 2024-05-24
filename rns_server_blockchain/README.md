# rns_server_blockchain
This program provides a gateway/bridge for payment/wallet of the "Communicator" app. Which is another project that is not part of this github.


### Features
- Compatible with all Reticulum payment/wallet apps (Communicator which is another project that is not part of this github)


## Current Status
It should currently be considered alpla and experimental demo software.

This does not include any blockchain and security functions!!!

It only serves as a test endpoint to simulate a central wallet!!!

The data is saved as plaintext in a file!!!

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
- Change the Reticulum configuration to suit your needs and use-case.
  ```bash
  nano /.reticulum/config
  ```
- Download the [file](rns_server_blockchain.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/RNS-Tools/main/rns_server_blockchain/rns_server_blockchain.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x rns_server_blockchain.py
  ```

### Start:
- Start it. Finished!
  ```bash
  ./rns_server_blockchain.py
  ```


### Run as a system service/deamon:
- Create a service file.
  ```bash
  nano /etc/systemd/system/rns_server_blockchain.service
  ```
- Copy and edit the following content to your own needs.
  ```bash
  [Unit]
  Description=rns_server_blockchain
  After=multi-user.target
  [Service]
  # ExecStartPre=/bin/sleep 10
  Type=simple
  Restart=always
  RestartSec=3
  User=root
  Group=root
  ExecStart=/root/rns_server_blockchain.py
  [Install]
  WantedBy=multi-user.target
  ```
- Enable the service.
  ```bash
  systemctl enable rns_server_blockchain
  ```
- Start the service.
  ```bash
  systemctl start rns_server_blockchain
  ```


### Start/Stop service:
  ```bash
  systemctl start rns_server_blockchain
  systemctl stop rns_server_blockchain
  ```


### Enable/Disable service:
  ```bash
  systemctl enable rns_server_blockchain
  systemctl disable rns_server_blockchain
  ```


### Run several instances (To copy the same application):
- Run the program with a different configuration path.
  ```bash
  ./rns_server_blockchain.py -p /root/.rns_server_blockchain_2nd
  ./rns_server_blockchain.py -p /root/.rns_server_blockchain_3nd
  ```


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
```


### Config/data files:


## FAQ

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)