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
import argparse

#### Config ####
import configparser
import base64

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack

#### Internal ####
from utils.utils import install_requirements
from server.server import ServerProvisioning


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "RNS Server Provisioning"
DESCRIPTION = "Provisioning for RNS based apps"
VERSION = "0.0.1 (2024-11-22)"
COPYRIGHT = "(c) 2024 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/rns_server_provisioning"
PATH_RNS = None


#### Global Variables - System (Not changeable) ####
CONFIG = None
RNS_CONNECTION = None
RNS_SERVER_PROVISIONING = None

ANNOUNCE_DATA_CONTENT = 0x00
ANNOUNCE_DATA_FIELDS  = 0x01
ANNOUNCE_DATA_TITLE   = 0x02

MSG_FIELD_EMBEDDED_LXMS    = 0x01
MSG_FIELD_TELEMETRY        = 0x02
MSG_FIELD_TELEMETRY_STREAM = 0x03
MSG_FIELD_ICON             = 0x04
MSG_FIELD_FILE_ATTACHMENTS = 0x05
MSG_FIELD_IMAGE            = 0x06
MSG_FIELD_AUDIO            = 0x07
MSG_FIELD_THREAD           = 0x08
MSG_FIELD_COMMANDS         = 0x09
MSG_FIELD_RESULTS          = 0x0A

MSG_FIELD_ANSWER             = 0xA0
MSG_FIELD_ATTACHMENT         = 0xA1
MSG_FIELD_COMMANDS_EXECUTE   = 0xA2
MSG_FIELD_COMMANDS_RESULT    = 0xA3
MSG_FIELD_CONTACT            = 0xA4
MSG_FIELD_DATA               = 0xA5
MSG_FIELD_DELETE             = 0xA6
MSG_FIELD_EDIT               = 0xA7
MSG_FIELD_GROUP              = 0xA8
MSG_FIELD_HASH               = 0xA9
MSG_FIELD_ICON_MENU          = 0xAA
MSG_FIELD_ICON_SRC           = 0xAB
MSG_FIELD_KEYBOARD           = 0xAC
MSG_FIELD_KEYBOARD_INLINE    = 0xAD
MSG_FIELD_LOCATION           = 0xAE
MSG_FIELD_OWNER              = 0xC0
MSG_FIELD_POLL               = 0xAF
MSG_FIELD_POLL_ANSWER        = 0xB0
MSG_FIELD_REACTION           = 0xB1
MSG_FIELD_RECEIPT            = 0xB2
MSG_FIELD_SCHEDULED          = 0xB3
MSG_FIELD_SILENT             = 0xB4
MSG_FIELD_SRC                = 0xB5
MSG_FIELD_STATE              = 0xB6
MSG_FIELD_STICKER            = 0xB7
MSG_FIELD_TELEMETRY_DB       = 0xB8
MSG_FIELD_TELEMETRY_PEER     = 0xB9
MSG_FIELD_TELEMETRY_COMMANDS = 0xBA
MSG_FIELD_TEMPLATE           = 0xBB
MSG_FIELD_TOPIC              = 0xBC
MSG_FIELD_TYPE               = 0xBD
MSG_FIELD_TYPE_FIELDS        = 0xBE
MSG_FIELD_VOICE              = 0xBF


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
                    CONFIG.read(file, encoding="utf-8")
                elif os.path.isfile(file_override):
                    CONFIG.read([file, file_override], encoding="utf-8")
                else:
                    CONFIG.read(file, encoding="utf-8")
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


def log_exception(e, text="", level=1):
    import traceback

    log(text+" - An "+str(type(e))+" occurred: "+str(e), level)
    log("".join(traceback.TracebackException.from_exception(e).format()), level)


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
    global RNS_SERVER_PROVISIONING

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

    announce_data = CONFIG["rns_server"]["display_name"]
    if CONFIG["main"].getboolean("fields_announce"):
        fields = {}
        if CONFIG["telemetry"].getboolean("location_enabled"):
            try:
               fields[MSG_FIELD_LOCATION] = [CONFIG["telemetry"].getfloat("location_lat"), CONFIG["telemetry"].getfloat("location_lon")]
            except:
                pass
        if CONFIG["telemetry"].getboolean("owner_enabled"):
            try:
               fields[MSG_FIELD_OWNER] = bytes.fromhex(CONFIG["telemetry"]["owner_data"])
            except:
                pass
        if CONFIG["telemetry"].getboolean("state_enabled"):
            try:
               fields[MSG_FIELD_STATE] = [CONFIG["telemetry"].getint("state_data"), int(time.time())]
            except:
                pass
        if CONFIG["main"].getboolean("fields_announce_data"):
            section = "data"
            if CONFIG.has_section(section):
                type_fields = {}
                for (key, val) in CONFIG.items(section):
                    if key == "config_lxm":
                        try:
                            if val != "":
                                val = base64.urlsafe_b64decode(val.replace("lxm://", "").replace("/", "")+"==")
                                val = msgpack.unpackb(val)
                                if val and "data" in val:
                                    type_fields["config"] = val["data"]["data"]
                        except:
                            pass
                    else:
                        if "=" in val or ";" in val:
                            type_fields[key] = {}
                            keys = val.split(";")
                            for val in keys:
                                val = val.split("=")
                                if len(val) == 2:
                                    type_fields[key][val[0]] = val_to_val(val[1])
                        else:
                            type_fields[key] = val
                if len(type_fields) > 0:
                    fields[MSG_FIELD_TYPE_FIELDS] = type_fields
        if len(fields) > 0:
            announce_data = {ANNOUNCE_DATA_CONTENT: CONFIG["rns_server"]["display_name"].encode("utf-8"), ANNOUNCE_DATA_TITLE: None, ANNOUNCE_DATA_FIELDS: fields}
            log("RNS - Configured announce data: "+str(announce_data), LOG_DEBUG)
            announce_data = msgpack.packb(announce_data)

    admins = []
    section = "admins"
    if CONFIG.has_section(section):
        for (key, val) in CONFIG.items(section):
            admins.append(key)

    RNS_SERVER_PROVISIONING = ServerProvisioning(
        storage_path=path,
        identity_file="identity",
        identity=None,

        destination_name=CONFIG["rns_server"]["destination_name"],
        destination_type=CONFIG["rns_server"]["destination_type"],

        announce_startup=CONFIG["rns_server"].getboolean("announce_startup"),
        announce_startup_delay=CONFIG["rns_server"]["announce_startup_delay"],
        announce_periodic=CONFIG["rns_server"].getboolean("announce_periodic"),
        announce_periodic_interval=CONFIG["rns_server"]["announce_periodic_interval"],
        announce_data=announce_data,
        announce_hidden=CONFIG["rns_server"].getboolean("announce_hidden"),

        register_startup=True,
        register_startup_delay=0,
        register_periodic=CONFIG["rns_server"].getboolean("register_periodic"),
        register_periodic_interval=CONFIG["rns_server"]["register_periodic_interval"],

        config=CONFIG,
        admins=admins,

        limiter_server_enabled=CONFIG["rns_server"].getboolean("limiter_server_enabled"),
        limiter_server_calls=CONFIG["rns_server"]["limiter_server_calls"],
        limiter_server_size=CONFIG["rns_server"]["limiter_server_size"],
        limiter_server_duration=CONFIG["rns_server"]["limiter_server_duration"],

        limiter_peer_enabled=CONFIG["rns_server"].getboolean("limiter_peer_enabled"),
        limiter_peer_calls=CONFIG["rns_server"]["limiter_peer_calls"],
        limiter_peer_size=CONFIG["rns_server"]["limiter_peer_size"],
        limiter_peer_duration=CONFIG["rns_server"]["limiter_peer_duration"],
    )

    RNS_SERVER_PROVISIONING.start()

    log("RNS - Connected", LOG_DEBUG)

    log("...............................................................................", LOG_FORCE)
    log("RNS - Address: " + RNS.prettyhexrep(RNS_SERVER_PROVISIONING.destination_hash()), LOG_FORCE)
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
        parser.add_argument("-i", "--install", action="store_true", default=False, help="Check and install requirements.")
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

        if params.install:
            print("Checking and installing requirements...")
            install_requirements()
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


[main]
fields_announce_data = True


[rns_server]
display_name = Server

announce_startup = Yes
announce_startup_delay = 0 #Seconds

announce_periodic = Yes
announce_periodic_interval = 120 #Minutes


[database]
host = 127.0.0.1
port = 5432
user = postgres
password = password
database = database
encoding = utf8


[handler_api]
enabled = False


[handler_directory]
enabled = True


[handler_files]
enabled = True


[handler_iop]
enabled = False


[handler_sync]
enabled = True

account_create = True
account_delete = False
account_edit = True
account_prove = False
account_restore = True

account_auth = True
account_auth_state = 0
account_auth_role = 3

account_device_status = 0
account_device_type = 0

invitation_create = True
invitation_delete = True

service_create = True
service_edit = True
service_delete = True


[admins]


[data]
v = 0.0.0 #Version software
u = #URL Software
i = #Info Software
cmd = #CMD
config = #Config
config_lxm = #Config as lxm string


[telemetry]
location_enabled = False
location_lat = 0
location_lon = 0

owner_enabled = False
owner_data = 

state_enabled = False
state_data = 0
'''


#### Default configuration file ####
DEFAULT_CONFIG = '''# This is the default config file.
# You should probably edit it to suit your needs and use-case.


#### Main program settings ####
[main]

# Enable/Disable this functionality.
enabled = True

# Name of the program. Only for display in the log or program startup.
name = RNS Server Provisioning

# Transport extended data in the announce.
# This is needed for the integration of advanced client apps.
fields_announce = True
fields_announce_data = True


#### RNS server settings ####
[rns_server]

# Destination name & type need to fits the RNS protocoll
# to be compatibel with other RNS programs.
destination_name = nomadnetwork
destination_type = provisioning

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

# Register files/destinations periodically
register_periodic = Yes
register_periodic_interval = 30 #Minutes

# Limits the number of simultaneous requests/calls per server.
limiter_server_enabled = No
limiter_server_calls = 1000 # Number of calls per duration. 0=Any
limiter_server_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_server_duration = 60 # Seconds

# Limits the number of simultaneous requests/calls per peer.
limiter_peer_enabled = Yes
limiter_peer_calls = 30 # Number of calls per duration. 0=Any
limiter_peer_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_peer_duration = 60 # Seconds


#### Database connection settings ####
[database]
host = 127.0.0.1
port = 5432
user = postgres
password = password
database = database
encoding = utf8


#### Handler settings ####
[handler_api]
root = /api/
enabled = False
limiter_enabled = No
limiter_calls = 30 # Number of calls per duration. 0=Any
limiter_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_duration = 60 # Seconds


[handler_directory]
enabled = True
root = 
limiter_enabled = Yes
limiter_calls = 30 # Number of calls per duration. 0=Any
limiter_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_duration = 60 # Seconds


[handler_files]
enabled = True
root = 
path = files
ext_allow = #,-separated list
ext_deny = py,sh #,-separated list
limiter_enabled = No
limiter_calls = 30 # Number of calls per duration. 0=Any
limiter_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_duration = 60 # Seconds


[handler_iop]
enabled = False
root = /iop/
limiter_enabled = No
limiter_calls = 30 # Number of calls per duration. 0=Any
limiter_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_duration = 60 # Seconds


[handler_sync]
enabled = True
root = 
limiter_enabled = Yes
limiter_calls = 15 # Number of calls per duration. 0=Any
limiter_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_duration = 60 # Seconds

account_create = True
account_delete = False
account_edit = True
account_prove = False
account_restore = True

account_auth = True
account_auth_state = 0
account_auth_role = 3

account_device_status = 0
account_device_type = 0

account_limiter_enabled = No
account_limiter_calls = 15 # Number of calls per duration. 0=Any
account_limiter_size = 0 # Data transfer size in bytes per duration. 0=Any
account_limiter_duration = 60 # Seconds

invitation_create = True
invitation_delete = True

invitation_limiter_enabled = Yes
invitation_limiter_calls = 5 # Number of calls per duration. 0=Any
invitation_limiter_size = 0 # Data transfer size in bytes per duration. 0=Any
invitation_limiter_duration = 60 # Seconds

service_create = True
service_edit = True
service_delete = True

service_limiter_enabled = No
service_limiter_calls = 15 # Number of calls per duration. 0=Any
service_limiter_size = 0 # Data transfer size in bytes per duration. 0=Any
service_limiter_duration = 60 # Seconds


#### Admin users ####
# Source addresses/hashs
[admins]
#2858b7a096899116cd529559cc679ffe


#### Data settings ####
[data]
v = 0.0.0 #Version software
u = #URL Software
i = #Info Software
cmd = #CMD
config = #Config
config_lxm = #Config as lxm string


#### Telemetry settings ####
[telemetry]
location_enabled = False
location_lat = 0
location_lon = 0

owner_enabled = False
owner_data = 

state_enabled = False
state_data = 0
'''


##############################################################################################################
# Init


if __name__ == "__main__":
    main()
