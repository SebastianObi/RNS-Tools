# rns_announce_test
This program sends an adjustable number of announces to the network. This tool can be useful to load the Reticulum network with a defined load of announces. This can be used to simulate a certain amount of users.

For more information, see the configuration options (at the end of the program files). Everything else is briefly documented there. After the first start this configuration will be created as default config in the corresponding file.


### Features
- Compatible with all Reticulum applications (NomadNet, Sideband, ...)


## Current Status
It should currently be considered beta software and still work in progress.

All core features are implemented and functioning, but additions will probably occur as real-world use is explored.

There may be errors or the compatibility after an update is no longer guaranteed.

The full documentation is not yet available. Due to lack of time I can also not say when this will be further processed.


## Screenshots / Usage examples
<img src="../docs/screenshots/rns_announce_test_01.png" width="1000px">


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
- Download the [file](rns_announce_test.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/RNS-Tools/main/rns_announce_test/rns_announce_test.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x rns_announce_test.py
  ```

### Start:
- Start it
  ```bash
  ./rns_announce_test.py
  ```


### Startup parameters:
```bash
usage: rns_announce_test.py [-h] [-p PATH] [-pr PATH_RNS] [-pl PATH_LOG] [-l LOGLEVEL] -d DEST -v VALUE [-t TIME] [-s SIZE] [-c COUNT]

RNS Announce Test - Periodically sends announces

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Path to alternative config directory
  -pr PATH_RNS, --path_rns PATH_RNS
                        Path to alternative Reticulum config directory
  -pl PATH_LOG, --path_log PATH_LOG
                        Path to alternative log directory
  -l LOGLEVEL, --loglevel LOGLEVEL
  -d DEST, --dest DEST  Destination type (aspect)
  -v VALUE, --value VALUE
                        Value/Text to send
  -t TIME, --time TIME  Time between announces in seconds
  -s SIZE, --size SIZE  Size (lenght) of the announce content
  -c COUNT, --count COUNT
                        Maximum announce send count (0=no end)

```


## FAQ

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)