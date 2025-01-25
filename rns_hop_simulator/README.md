# rns_hop_simulator
This program offers a test possibility to simulate several hops. By starting several reticulum instances on the same system and automatically connecting them via TCP.

You only need to provide an interface configuration file for the entry and exit point. See startup parameters.


### Features
- Compatible with all Reticulum applications (NomadNet, Sideband, ...)


## Current Status
It should currently be considered beta software and still work in progress.

All core features are implemented and functioning, but additions will probably occur as real-world use is explored.

There may be errors or the compatibility after an update is no longer guaranteed.

The full documentation is not yet available. Due to lack of time I can also not say when this will be further processed.


## Screenshots / Usage examples
<img src="../docs/screenshots/rns_hop_simulator_01.png" width="1000px">


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
- Download the [file](rns_hop_simulator.py) from this repository.
  ```bash
  wget https://raw.githubusercontent.com/SebastianObi/RNS-Tools/main/rns_hop_simulator/rns_hop_simulator.py
  ```
- Make it executable with the following command
  ```bash
  chmod +x rns_hop_simulator.py
  ```

### Start:
- Start it
  ```bash
  ./rns_hop_simulator.py
  ```


### Startup parameters:
```bash
usage: rns_hop_simulator.py [-h] [-p PATH] [-pl PATH_LOG] [-l LOGLEVEL] [-s] [-c COUNT] [--cfg_entry CFG_ENTRY] [--cfg_exit CFG_EXIT] [-m MODE] [-r RNS]
                            [--example_cfg_entry] [--example_cfg_exit]

RNS Hop Simulator - Simulation and test system for several hops

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Path to alternative config directory
  -pl PATH_LOG, --path_log PATH_LOG
                        Path to alternative log directory
  -l LOGLEVEL, --loglevel LOGLEVEL
  -s, --service         Running as a service and should log to file
  -c COUNT, --count COUNT
                        Hop count
  --cfg_entry CFG_ENTRY
                        Interface configuration of the entry hop/node (Which clients connect to)
  --cfg_exit CFG_EXIT   Interface configuration of the exit hop/node (Which connects to an existing node)
  -m MODE, --mode MODE  Interface mode (full/accesspoint/roaming/boundary/gateway)
  -r RNS, --rns RNS     Internal start parameter of the RNS instance (do not use)
  --example_cfg_entry   Print verbose configuration example to stdout and exit
  --example_cfg_exit    Print verbose configuration example to stdout and exit
```


## FAQ

### How do I start with the software?
You should read the `Installation manual` section. There everything is explained briefly. Just work through everything from top to bottom :)