# rns_server_blockchain
This program provides a gateway/bridge for payment/wallet of the "Communicator" app. Which is another project that is not part of this github.


### Features
- Compatible with all Reticulum payment/wallet apps (Communicator which is another project that is not part of this github)


### Supported coins/tokens
- HYD/DHYD/THYD (Hydraledger Utility Coin) `https://www.hydraledger.tech/`
- TEST (Test/Dummy Coin)


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
- Install all coins/tokens prerequisites - Hydraledger.
  ```bash
  sudo apt install curl
  sudo apt install pkg-config
  sudo apt install libssl-dev
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  . "$HOME/.cargo/env"
  pip3 install maturin
  pip3 install iop-python
  pip3 install requests
  ```

### Start:
- Start it
  ```bash
  ./rns_server_blockchain.py
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.
- Example minimal configuration (override of the default config `config.cfg`). These are the most relevant settings that need to be adjusted. All other settings are in `config.cfg`
  ```bash
  nano /root/.rns_server_blockchain/config.cfg.owr
  ```
  ```bash
  ```
- Start it again. Finished!
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
- This blockchain server address must be added to the clients.
- Now the software can be used.


### Startup parameters:
```bash
usage: rns_server_blockchain.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--exampleconfig] [--exampleconfigoverride]

RNS Server Blockchain - Gateway/Bridge for payment/wallet for RNS based apps

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