# RNS-Tools
Various small programs and tools which use the Reticulum Network Stack RNS from https://github.com/markqvist/Reticulum


## rns_call_echo
For more information, see the detailed [README.md](rns_call_echo).


## rns_server_page
For more information, see the detailed [README.md](rns_server_page).


## rns_server_shop
For more information, see the detailed [README.md](rns_server_shop).


## General Information for all tools/programs


### Current Status:
It should currently be considered beta software and still work in progress.

All core features are implemented and functioning, but additions will probably occur as real-world use is explored.

There may be errors or the compatibility after an update is no longer guaranteed.

The full documentation is not yet available. Due to lack of time I can also not say when this will be further processed.


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

- Download the [file](rns_server_page.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/RNS-Tools/main/rns_server_page/rns_server_page.py
  ```

- Make it executable with the following command
  ```bash
  chmod +x rns_server_page.py
  ```

### Start:
- Start it
  ```bash
  ./rns_server_page.py
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.
- Example minimal configuration (override of the default config `config.cfg`). These are the most relevant settings that need to be adjusted. All other settings are in `config.cfg`
  ```bash
  nano /root/.rns_server_page/config.cfg.owr
  ```
- Start it again. Finished!
  ```bash
  ./rns_server_page.py
  ```


### Run as a system service/deamon:
- Create a service file.
  ```bash
  nano /etc/systemd/system/rns_server_page.service
  ```
- Copy and edit the following content to your own needs.
  ```bash
  [Unit]
  Description=rns_server_page.py Daemon
  After=multi-user.target
  [Service]
  # ExecStartPre=/bin/sleep 10
  Type=simple
  Restart=always
  RestartSec=3
  User=root
  Group=root
  ExecStart=/root/rns_server_page.py
  [Install]
  WantedBy=multi-user.target
  ```
- Enable the service.
  ```bash
  systemctl enable rns_server_page
  ```
- Start the service.
  ```bash
  systemctl start rns_server_page
  ```


### Start/Stop service:
  ```bash
  systemctl start rns_server_page
  systemctl stop rns_server_page
  ```


### Enable/Disable service:
  ```bash
  systemctl enable rns_server_page
  systemctl disable rns_server_page
  ```


### Run several instances (To copy the same application):
- Run the program with a different configuration path.
  ```bash
  ./rns_server_page.py -p /root/.rns_server_page_2nd
  ./rns_server_page.py -p /root/.rns_server_page_3nd
  ```
- After the first start edit the configuration file to suit your needs and use-case. The file location is displayed.


## Support / Donations
You can help support the continued development by donating via one of the following channels:

- PayPal: https://paypal.me/SebastianObi
- Liberapay: https://liberapay.com/SebastianObi/donate


## Support in another way?
You are welcome to participate in the development. Just create a pull request. Or just contact me for further clarifications.


## Do you need a special function or customization?
Then feel free to contact me. Customizations or tools developed specifically for you can be realized.


## FAQ
