#!/usr/bin/env python3
##############################################################################################################
#
# Copyright (c) 2024 Sebastian Obele  /  obele.eu
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# This software uses the following software-parts:
# Reticulum  /  Copyright (c) 2016-2022 Mark Qvist  /  unsigned.io  /  MIT License
#
##############################################################################################################


##############################################################################################################
# Include


#### System ####
import sys
import os
import time
import datetime
import argparse
import random

#### UID ####
import uuid

#### Config ####
import configparser

#### Process ####
import signal
import threading
import subprocess

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "RNS Server Blockchain"
DESCRIPTION = "Gateway/Bridge for payment/wallet for RNS based apps"
VERSION = "0.0.1 (2024-05-31)"
COPYRIGHT = "(c) 2024 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/"+os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None


#### Global Variables - System (Not changeable) ####
CONFIG = None
RNS_CONNECTION = None
RNS_SERVER_BLOCKCHAIN = None


##############################################################################################################
# ServerBlockchain Class


class ServerBlockchain:
    RESULT_ERROR       = 0x00
    RESULT_OK          = 0x01
    RESULT_SYNCRONIZE  = 0x02
    RESULT_NO_IDENTITY = 0x03
    RESULT_NO_RIGHT    = 0x04
    RESULT_DISABLED    = 0xFE
    RESULT_BLOCKED     = 0xFF


    def __init__(self, storage_path=None, identity_file="identity", identity=None, destination_name="nomadnetwork", destination_type="bc", announce_startup=False, announce_startup_delay=0, announce_periodic=False, announce_periodic_interval=360, announce_data="", announce_hidden=False, register_startup=True, register_startup_delay=0, register_periodic=True, register_periodic_interval=30):
        self.storage_path = storage_path

        self.identity_file = identity_file
        self.identity = identity

        self.destination_name = destination_name
        self.destination_type = destination_type
        self.aspect_filter = self.destination_name + "." + self.destination_type

        self.announce_startup = announce_startup
        self.announce_startup_delay = int(announce_startup_delay)
        if self.announce_startup_delay == 0:
            self.announce_startup_delay = random.randint(5, 30)

        self.announce_periodic = announce_periodic
        self.announce_periodic_interval = int(announce_periodic_interval)

        self.announce_data = announce_data
        self.announce_hidden = announce_hidden

        if self.storage_path:
            if not os.path.isdir(self.storage_path):
                os.makedirs(self.storage_path)
                RNS.log("Server - Storage path was created", RNS.LOG_NOTICE)
            RNS.log("Server - Storage path: " + self.storage_path, RNS.LOG_INFO)

        if self.identity:
            RNS.log("Server - Using existing Primary Identity %s" % (str(self.identity)))
        else:
            if not self.storage_path:
                RNS.log("Server - No storage_path parameter", RNS.LOG_ERROR)
                return
            if not self.identity_file:
                self.identity_file = "identity"
            self.identity_path = self.storage_path + "/" + self.identity_file
            if os.path.isfile(self.identity_path):
                try:
                    self.identity = RNS.Identity.from_file(self.identity_path)
                    if self.identity != None:
                        RNS.log("Server - Loaded Primary Identity %s from %s" % (str(self.identity), self.identity_path))
                    else:
                        RNS.log("Server - Could not load the Primary Identity from "+self.identity_path, RNS.LOG_ERROR)
                except Exception as e:
                    RNS.log("Server - Could not load the Primary Identity from "+self.identity_path, RNS.LOG_ERROR)
                    RNS.log("Server - The contained exception was: %s" % (str(e)), RNS.LOG_ERROR)
            else:
                try:
                    RNS.log("Server - No Primary Identity file found, creating new...")
                    self.identity = RNS.Identity()
                    self.identity.to_file(self.identity_path)
                    RNS.log("Server - Created new Primary Identity %s" % (str(self.identity)))
                except Exception as e:
                    RNS.log("Server - Could not create and save a new Primary Identity", RNS.LOG_ERROR)
                    RNS.log("Server - The contained exception was: %s" % (str(e)), RNS.LOG_ERROR)

        self.destination = RNS.Destination(self.identity, RNS.Destination.IN, RNS.Destination.SINGLE, self.destination_name, self.destination_type)

        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)

        self.destination.set_link_established_callback(self.peer_connected)

        if self.announce_startup or self.announce_periodic:
            self.announce(initial=True)

        self.register()


        #### Load dummy data ####
        self.data_dummy_load()


    def start(self):
        pass


    def stop(self):
        pass


    #### Dummy data functions ####
    def data_dummy_load(self):
        try:
            file = self.storage_path + "/data_dummy"
            if os.path.isfile(file):
                fh = open(file, "rb")
                self.data_dummy = msgpack.unpackb(fh.read())
                fh.close()
            else:
                self.data_dummy_default()
                fh = open(self.storage_path + "/data_dummy", "wb")
                fh.write(msgpack.packb(self.data_dummy))
                fh.close()
        except:
            self.data_dummy_default()


    #### Dummy data functions ####
    def data_dummy_save(self):
        try:
            file = self.storage_path + "/data_dummy"
            fh = open(self.storage_path + "/data_dummy", "wb")
            fh.write(msgpack.packb(self.data_dummy))
            fh.close()
        except:
            pass


    #### Dummy data functions ####
    def data_dummy_default(self):
        self.data_dummy = {}
        self.data_dummy["accounts"] = {}
        self.data_dummy["transactions"] = {}
        self.data_dummy["uid"] = str(uuid.uuid4())


    def register_announce_callback(self, handler_function):
        self.announce_callback = handler_function(self.aspect_filter)
        RNS.Transport.register_announce_handler(self.announce_callback)


    def destination_hash(self):
        return self.destination.hash


    def destination_hash_str(self):
        return RNS.hexrep(self.destination.hash, False)


    def destination_check(self, destination):
        if type(destination) is not bytes:
            if len(destination) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                destination = destination[1:-1]

            if len(destination) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                RNS.log("Server - Destination length is invalid", RNS.LOG_ERROR)
                return False

            try:    
                destination = bytes.fromhex(destination)
            except Exception as e:
                RNS.log("Server - Destination is invalid", RNS.LOG_ERROR)
                return False

        return True


    def destination_correct(self, destination):
        if type(destination) is not bytes:
            if len(destination) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                destination = destination[1:-1]

            if len(destination) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                return ""

            try:
                destination_bytes = bytes.fromhex(destination)
                return destination
            except Exception as e:
                return ""

        return ""


    def announce(self, app_data=None, attached_interface=None, initial=False):
        announce_timer = None

        if self.announce_periodic and self.announce_periodic_interval > 0:
            announce_timer = threading.Timer(self.announce_periodic_interval*60, self.announce)
            announce_timer.daemon = True
            announce_timer.start()

        if initial:
            if self.announce_startup:
                if self.announce_startup_delay > 0:
                    if announce_timer is not None:
                        announce_timer.cancel()
                    announce_timer = threading.Timer(self.announce_startup_delay, self.announce)
                    announce_timer.daemon = True
                    announce_timer.start()
                else:
                    self.announce_now(app_data=app_data, attached_interface=attached_interface)
            return

        self.announce_now(app_data=app_data, attached_interface=attached_interface)


    def announce_now(self, app_data=None, attached_interface=None):
        if self.announce_hidden:
            self.destination.announce("".encode("utf-8"), attached_interface=attached_interface)
            RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +" (Hidden)", RNS.LOG_DEBUG)
        elif app_data != None:
            if isinstance(app_data, str):
                self.destination.announce(app_data.encode("utf-8"), attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +": " + app_data, RNS.LOG_DEBUG)
            else:
                self.destination.announce(app_data, attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()), RNS.LOG_DEBUG)
        else:
            if isinstance(self.announce_data, str):
                self.destination.announce(self.announce_data.encode("utf-8"), attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +": " + self.announce_data, RNS.LOG_DEBUG)
            else:
                self.destination.announce(self.announce_data, attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()), RNS.LOG_DEBUG)


    def register(self):
        RNS.log("Server - Register", RNS.LOG_DEBUG)
        self.destination.register_request_handler("sync", response_generator=self.sync, allow=RNS.Destination.ALLOW_ALL)


    def peer_connected(self, link):
        RNS.log("Server - Peer connected to "+str(self.destination), RNS.LOG_VERBOSE)

        link.set_link_closed_callback(self.peer_disconnected)
        link.set_remote_identified_callback(self.peer_identified)


    def peer_disconnected(self, link):
        RNS.log("Server - Peer disconnected from "+str(self.destination), RNS.LOG_VERBOSE)


    def peer_identified(self, link, identity):
        if not identity:
            link.teardown()


    def sync(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return None

        # Temporary debug output
        print("---- sync ----")
        print("Dict received: "+str(data))

        data_dummy_save = False

        data_return = {}

        # Processing dummy data - Performing new transactions
        if "transactions" in data:
            for transaction_id, transaction in data["transactions"].items():
                # Check whether the transaction id does not yet exist
                if transaction_id not in self.data_dummy["transactions"]:
                    # Check whether source and destination account exist
                    if transaction["dest"] in self.data_dummy["accounts"] and transaction["source"] in self.data_dummy["accounts"]:
                        if self.data_dummy["accounts"][transaction["source"]]["balance"] >= transaction["value"]:
                            state = 0x01
                        else:
                            state = 0x00
                        # Add transaction
                        self.data_dummy["transactions"][transaction_id] = {}
                        self.data_dummy["transactions"][transaction_id]["dest"] = transaction["dest"]
                        self.data_dummy["transactions"][transaction_id]["source"] = transaction["source"]
                        self.data_dummy["transactions"][transaction_id]["value"] = transaction["value"]
                        self.data_dummy["transactions"][transaction_id]["comment"] = transaction["comment"]
                        self.data_dummy["transactions"][transaction_id]["fee"] = 0
                        self.data_dummy["transactions"][transaction_id]["state"] = state
                        self.data_dummy["transactions"][transaction_id]["ts"] = time.time()
                        if state == 0x01:
                            # Calculate new account balance
                            self.data_dummy["accounts"][transaction["dest"]]["balance"] += transaction["value"]
                            self.data_dummy["accounts"][transaction["source"]]["balance"] -= transaction["value"]
                        # Saving dummy data
                        data_dummy_save = True

        # Processing of dummy data - Return of account data and transactions of these accounts
        if "accounts" in data:
            data_return["accounts"] = {}

            # Loop to process all requested accounts
            for account_id, ts in data["accounts"].items():
                # Check whether the account already exists
                if account_id not in self.data_dummy["accounts"]:
                    # Add initial transaction with dummy starting balance
                    self.data_dummy["accounts"][account_id] = {}
                    self.data_dummy["accounts"][account_id]["balance"] = 100
                    self.data_dummy["accounts"][account_id]["currency"] = "FDM"
                    uid = str(uuid.uuid4())
                    self.data_dummy["transactions"][uid] = {}
                    self.data_dummy["transactions"][uid]["dest"] = account_id
                    self.data_dummy["transactions"][uid]["source"] = self.data_dummy["uid"]
                    self.data_dummy["transactions"][uid]["value"] = 100
                    self.data_dummy["transactions"][uid]["comment"] = ""
                    self.data_dummy["transactions"][uid]["fee"] = 0
                    self.data_dummy["transactions"][uid]["state"] = 0x01
                    self.data_dummy["transactions"][uid]["ts"] = time.time()
                    # Saving dummy data
                    data_dummy_save = True

                # Return general account data
                data_return["accounts"][account_id] = {}
                data_return["accounts"][account_id]["balance"] = self.data_dummy["accounts"][account_id]["balance"]
                data_return["accounts"][account_id]["currency"] = self.data_dummy["accounts"][account_id]["currency"]

                # Loop over all transactions
                for transaction_id, transaction in self.data_dummy["transactions"].items():
                    # Checking whether the account is included in a transaction as a source or destination
                    if (transaction["dest"] == account_id or transaction["source"] == account_id) and transaction["ts"] > ts:
                        # Return transaction data
                        data_return["accounts"][account_id]["transactions"] = {}
                        data_return["accounts"][account_id]["transactions"][transaction_id] = {}
                        data_return["accounts"][account_id]["transactions"][transaction_id]["dest"] = transaction["dest"]
                        data_return["accounts"][account_id]["transactions"][transaction_id]["source"] = transaction["source"]
                        data_return["accounts"][account_id]["transactions"][transaction_id]["value"] = transaction["value"]
                        data_return["accounts"][account_id]["transactions"][transaction_id]["comment"] = transaction["comment"]
                        data_return["accounts"][account_id]["transactions"][transaction_id]["fee"] = transaction["fee"]
                        data_return["accounts"][account_id]["transactions"][transaction_id]["state"] = transaction["state"]
                        data_return["accounts"][account_id]["transactions"][transaction_id]["ts"] = transaction["ts"]

        # Saving dummy data
        if data_dummy_save:
            self.data_dummy_save()

        data_return["result"] = ServerBlockchain.RESULT_OK

        # Temporary debug output
        print("Dict send: "+str(data_return))

        data_return = msgpack.packb(data_return)

        return data_return


##############################################################################################################
# Config


#### Config - Get #####
def config_get(config, section, key, default="", lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return config[section][key+lng_key]
    elif config.has_option(section, key):
        return config[section][key]
    return default


def config_getint(config, section, key, default=0, lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return config.getint(section, key+lng_key)
    elif config.has_option(section, key):
        return config.getint(section, key)
    return default


def config_getboolean(config, section, key, default=False, lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return config[section].getboolean(key+lng_key)
    elif config.has_option(section, key):
        return config[section].getboolean(key)
    return default


def config_getsection(config, section, default="", lng_key=""):
    if not config or section == "": return default
    if not config.has_section(section): return default
    if config.has_section(section+lng_key):
        return key+lng_key
    elif config.has_section(section):
        return key
    return default


def config_getoption(config, section, key, default=False, lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return key+lng_key
    elif config.has_option(section, key):
        return key
    return default


#### Config - Read #####
def config_read(file=None, file_override=None):
    global CONFIG

    if file is None:
        return False
    else:
        CONFIG = configparser.ConfigParser(allow_no_value=True, inline_comment_prefixes="#")
        CONFIG.sections()
        if os.path.isfile(file):
            try:
                if file_override is None:
                    CONFIG.read(file, encoding='utf-8')
                elif os.path.isfile(file_override):
                    CONFIG.read([file, file_override], encoding='utf-8')
                else:
                    CONFIG.read(file, encoding='utf-8')
            except Exception as e:
                return False
        else:
            if not config_default(file=file, file_override=file_override):
                return False
    return True


#### Config - Save #####
def config_save(file=None):
    global CONFIG

    if file is None:
        return False
    else:
        if os.path.isfile(file):
            try:
                with open(file,"w") as file:
                    CONFIG.write(file)
            except Exception as e:
                return False
        else:
            return False
    return True


#### Config - Default #####
def config_default(file=None, file_override=None):
    global CONFIG

    if file is None:
        return False
    elif DEFAULT_CONFIG != "":
        if file_override and DEFAULT_CONFIG_OVERRIDE != "":
            if not os.path.isdir(os.path.dirname(file_override)):
                try:
                    os.makedirs(os.path.dirname(file_override))
                except Exception:
                    return False
            if not os.path.exists(file_override):
                try:
                    config_file = open(file_override, "w")
                    config_file.write(DEFAULT_CONFIG_OVERRIDE)
                    config_file.close()
                except:
                    return False

        if not os.path.isdir(os.path.dirname(file)):
            try:
                os.makedirs(os.path.dirname(file))
            except Exception:
                return False
        try:
            config_file = open(file, "w")
            config_file.write(DEFAULT_CONFIG)
            config_file.close()
            if not config_read(file=file, file_override=file_override):
                return False
        except:
            return False
    else:
        return False

    if not CONFIG.has_section("main"): CONFIG.add_section("main")
    CONFIG["main"]["default_config"] = "True"
    return True


##############################################################################################################
# Log


LOG_FORCE    = -1
LOG_CRITICAL = 0
LOG_ERROR    = 1
LOG_WARNING  = 2
LOG_NOTICE   = 3
LOG_INFO     = 4
LOG_VERBOSE  = 5
LOG_DEBUG    = 6
LOG_EXTREME  = 7

LOG_LEVEL         = LOG_NOTICE
LOG_LEVEL_SERVICE = LOG_NOTICE
LOG_TIMEFMT       = "%Y-%m-%d %H:%M:%S"
LOG_MAXSIZE       = 5*1024*1024
LOG_PREFIX        = ""
LOG_SUFFIX        = ""
LOG_FILE          = ""


def log(text, level=3, file=None):
    if not LOG_LEVEL:
        return

    if LOG_LEVEL >= level:
        name = "Unknown"
        if (level == LOG_FORCE):
            name = ""
        if (level == LOG_CRITICAL):
            name = "Critical"
        if (level == LOG_ERROR):
            name = "Error"
        if (level == LOG_WARNING):
            name = "Warning"
        if (level == LOG_NOTICE):
            name = "Notice"
        if (level == LOG_INFO):
            name = "Info"
        if (level == LOG_VERBOSE):
            name = "Verbose"
        if (level == LOG_DEBUG):
            name = "Debug"
        if (level == LOG_EXTREME):
            name = "Extra"

        if not isinstance(text, str):
            text = str(text)

        text = "[" + time.strftime(LOG_TIMEFMT, time.localtime(time.time())) +"] [" + name + "] " + LOG_PREFIX + text + LOG_SUFFIX

        if file == None and LOG_FILE != "":
            file = LOG_FILE

        if file == None:
            print(text)
        else:
            try:
                file_handle = open(file, "a")
                file_handle.write(text + "\n")
                file_handle.close()
                
                if os.path.getsize(file) > LOG_MAXSIZE:
                    file_prev = file + ".1"
                    if os.path.isfile(file_prev):
                        os.unlink(file_prev)
                    os.rename(file, file_prev)
            except:
                return


##############################################################################################################
# System


#### Panic #####
def panic():
    sys.exit(255)


#### Exit #####
def exit():
    sys.exit(0)


##############################################################################################################
# Setup/Start


#### Setup #####
def setup(path=None, path_rns=None, path_log=None, loglevel=None, service=False):
    global PATH
    global PATH_RNS
    global LOG_LEVEL
    global LOG_FILE
    global RNS_CONNECTION
    global RNS_SERVER_BLOCKCHAIN

    if path is not None:
        if path.endswith("/"):
            path = path[:-1]
        PATH = path

    if path_rns is not None:
        if path_rns.endswith("/"):
            path_rns = path_rns[:-1]
        PATH_RNS = path_rns

    if loglevel is not None:
        LOG_LEVEL = loglevel
        rns_loglevel = loglevel
    else:
        rns_loglevel = None

    if service:
        LOG_LEVEL = LOG_LEVEL_SERVICE
        if path_log is not None:
            if path_log.endswith("/"):
                path_log = path_log[:-1]
            LOG_FILE = path_log
        else:
            LOG_FILE = PATH
        LOG_FILE = LOG_FILE + "/" + NAME + ".log"
        rns_loglevel = None

    if not config_read(PATH + "/config.cfg", PATH + "/config.cfg.owr"):
        print("Config - Error reading config file " + PATH + "/config.cfg")
        panic()

    if CONFIG["main"].getboolean("default_config"):
        print("Exit!")
        print("First start with the default config!")
        print("You should probably edit the config file \"" + PATH + "/config.cfg\" to suit your needs and use-case!")
        print("You should make all your changes at the user configuration file \"" + PATH + "/config.cfg.owr\" to override the default configuration file!")
        print("Then restart this program again!")
        exit()

    if not CONFIG["main"].getboolean("enabled"):
        print("Disabled in config file. Exit!")
        exit()

    RNS_CONNECTION = RNS.Reticulum(configdir=PATH_RNS, loglevel=rns_loglevel)

    log("...............................................................................", LOG_INFO)
    log("        Name: " + CONFIG["main"]["name"], LOG_INFO)
    log("Program File: " + __file__, LOG_INFO)
    log(" Config File: " + PATH + "/config", LOG_INFO)
    log("     Version: " + VERSION, LOG_INFO)
    log("   Copyright: " + COPYRIGHT, LOG_INFO)
    log("...............................................................................", LOG_INFO)

    log("RNS - Connecting ...", LOG_DEBUG)

    if path is None:
        path = PATH

    RNS_SERVER_BLOCKCHAIN = ServerBlockchain(
        storage_path=path,
        identity_file="identity",
        identity=None,
        destination_name=CONFIG["rns_server"]["destination_name"],
        destination_type=CONFIG["rns_server"]["destination_type"],
        announce_startup=CONFIG["rns_server"].getboolean("announce_startup"),
        announce_startup_delay=CONFIG["rns_server"]["announce_startup_delay"],
        announce_periodic=CONFIG["rns_server"].getboolean("announce_periodic"),
        announce_periodic_interval=CONFIG["rns_server"]["announce_periodic_interval"],
        announce_data=CONFIG["rns_server"]["display_name"],
        announce_hidden=CONFIG["rns_server"].getboolean("announce_hidden")
    )

    log("RNS - Connected", LOG_DEBUG)

    log("...............................................................................", LOG_FORCE)
    log("RNS - Address: " + RNS.prettyhexrep(RNS_SERVER_BLOCKCHAIN.destination_hash()), LOG_FORCE)
    log("...............................................................................", LOG_FORCE)

    while True:
        time.sleep(1)


#### Start ####
def main():
    try:
        description = NAME + " - " + DESCRIPTION
        parser = argparse.ArgumentParser(description=description)

        parser.add_argument("-p", "--path", action="store", type=str, default=None, help="Path to alternative config directory")
        parser.add_argument("-pr", "--path_rns", action="store", type=str, default=None, help="Path to alternative Reticulum config directory")
        parser.add_argument("-pl", "--path_log", action="store", type=str, default=None, help="Path to alternative log directory")
        parser.add_argument("-l", "--loglevel", action="store", type=int, default=LOG_LEVEL)
        parser.add_argument("-s", "--service", action="store_true", default=False, help="Running as a service and should log to file")
        parser.add_argument("--exampleconfig", action="store_true", default=False, help="Print verbose configuration example to stdout and exit")
        parser.add_argument("--exampleconfigoverride", action="store_true", default=False, help="Print verbose configuration example to stdout and exit")

        params = parser.parse_args()

        if params.exampleconfig:
            print("Config File: " + PATH + "/config.cfg")
            print("Content:")
            print(DEFAULT_CONFIG)
            exit()

        if params.exampleconfigoverride:
            print("Config Override File: " + PATH + "/config.cfg.owr")
            print("Content:")
            print(DEFAULT_CONFIG_OVERRIDE)
            exit()

        setup(path=params.path, path_rns=params.path_rns, path_log=params.path_log, loglevel=params.loglevel, service=params.service)

    except KeyboardInterrupt:
        print("Terminated by CTRL-C")
        exit()


##############################################################################################################
# Files


#### Default configuration override file ####
DEFAULT_CONFIG_OVERRIDE = '''# This is the user configuration file to override the default configuration file.
# All settings made here have precedence.
# This file can be used to clearly summarize all settings that deviate from the default.
# This also has the advantage that all changed settings can be kept when updating the program.

#### RNS server settings ####
[rns_server]
display_name = Server

announce_startup = Yes
announce_startup_delay = 0 #Seconds

announce_periodic = Yes
announce_periodic_interval = 120 #Minutes

'''


#### Default configuration file ####
DEFAULT_CONFIG = '''# This is the default config file.
# You should probably edit it to suit your needs and use-case.


#### Main program settings ####
[main]

# Enable/Disable this functionality.
enabled = True

# Name of the program. Only for display in the log or program startup.
name = RNS Server Blockchain


#### RNS server settings ####
[rns_server]

# Destination name & type need to fits the RNS protocoll
# to be compatibel with other RNS programs.
destination_name = nomadnetwork
destination_type = bc

# The name will be visible to other peers
# on the network, and included in announces.
display_name = Server

# The server is announced at startup
# to let clients reach it immediately.
announce_startup = Yes
announce_startup_delay = 0 #Seconds

# The server is announced periodically
# to let clients reach it.
announce_periodic = Yes
announce_periodic_interval = 120 #Minutes

# The announce is hidden for client applications
# but is still used for the routing tables.
announce_hidden = No
'''


##############################################################################################################
# Init


if __name__ == "__main__":
    main()