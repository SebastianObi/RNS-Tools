# rns_announce_view
This program is used to debug the received announcements. All received announcements are displayed in the console. There are various parameters to define the reception of announcements.


### Features
- View received announcements


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
- Download the [file](rns_announce_view.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/RNS-Tools/main/rns_announce_view/rns_announce_view.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x rns_announce_view.py
  ```


### Start:
- Start it
  ```bash
  ./rns_announce_view.py
  ```


### Startup parameters:
```bash
usage: rns_announce_view.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [--search SEARCH] -f ASPECT_FILTER [-a DEST_ALLOW] [-d DEST_DENY] [--hop_min HOP_MIN]
                            [--hop_max HOP_MAX] [-i HOP_INTERFACES] [--hidden] [--recall_app_data RECALL_APP_DATA]

RNS Announce View - View received announcements

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Path to alternative config directory
  -pr PATH_RNS, --path_rns PATH_RNS
                        Path to alternative Reticulum config directory
  -pl PATH_LOG, --path_log PATH_LOG
                        Path to alternative log directory
  -l LOGLEVEL, --loglevel LOGLEVEL
  -s, --service         Running as a service and should log to file
  --search SEARCH       Search string for destination, data or hop interface
  -f ASPECT_FILTER, --aspect_filter ASPECT_FILTER
                        Aspect ,-separated list with one ore more aspects
  -a DEST_ALLOW, --dest_allow DEST_ALLOW
                        Allow certain addresses ,-separated list with one ore more addresses
  -d DEST_DENY, --dest_deny DEST_DENY
                        Deny certain addresses ,-separated list with one ore more addresses
  --hop_min HOP_MIN     Minimum hop count
  --hop_max HOP_MAX     Maximum hop count
  -i HOP_INTERFACES, --hop_interfaces HOP_INTERFACES
                        Hop interfaces ,-separated list with interface names
  --hidden              View hidden announces
  --recall_app_data RECALL_APP_DATA
                        Recall app data with other aspect to get the announced data
```


## FAQ

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)