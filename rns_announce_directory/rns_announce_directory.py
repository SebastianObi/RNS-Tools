#!/usr/bin/env python3
##############################################################################################################
#
# Copyright (c) 2023 Sebastian Obele  /  obele.eu
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

#### Database ####
import sqlite3

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "RNS Announce Directory"
DESCRIPTION = "Database for the collection of received announcements"
VERSION = "0.0.1 (2023-01-12)"
COPYRIGHT = "(c) 2023 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~") + "/." + os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None


#### Global Variables - System (Not changeable) ####
CONFIG = None
DB = None
RNS_CONNECTION = None
RNS_ANNOUNCE_HANDLER = None


##############################################################################################################
# AnnounceHandler Class


class AnnounceHandler:
    def __init__(self, aspect_filter=None, callback=None, dest_type=None, hidden=False, hop_min=0, hop_max=0, hop_interfaces=[], recall_app_data=None, dest_deny=[]):
        self.aspect_filter = aspect_filter
        self.callback = callback
        self.dest_type = dest_type
        self.hidden = hidden
        self.hop_min = hop_min
        self.hop_max = hop_max
        self.hop_interfaces = hop_interfaces
        self.recall_app_data = recall_app_data
        self.dest_deny = dest_deny


    def received_announce(self, destination_hash, announced_identity, app_data):
        if app_data == None:
            if self.hidden:
                app_data = b''
            else:
                return

        if len(app_data) == 0:
            if self.hidden:
                app_data = b''
            else:
                return

        dest_type = self.dest_type

        if self.recall_app_data and self.recall_app_data != "":
            try:
                identity = RNS.Identity.recall(destination_hash)
                if identity != None:
                    app_data = RNS.Identity.recall_app_data(RNS.Destination.hash_from_name_and_identity(self.recall_app_data, identity))
                    if app_data != None and len(app_data) > 0:
                        pass
                    else:
                        app_data = b''
                else:
                    app_data = b''
            except:
                pass
        else:
            try:
                app_data_dict = msgpack.unpackb(app_data)
                if isinstance(app_data_dict, dict):
                    if "c" in app_data_dict:
                        app_data = app_data_dict["c"]
                    if "f" in app_data_dict and "type" in app_data_dict["f"]:
                        dest_type = app_data_dict["f"]["type"]
            except:
                pass

        try:
            app_data = app_data.decode("utf-8")
            hop_count = RNS.Transport.hops_to(destination_hash)
            hop_interface = RNS_CONNECTION.get_next_hop_if_name(destination_hash)

            if self.hop_min > 0 and hop_count < self.hop_min:
                return

            if self.hop_max > 0 and hop_count < self.hop_max:
                return

            if len(self.hop_interfaces) > 0 and hop_interface not in self.hop_interfaces:
                return

            if len(self.dest_deny) > 0 and destination_hash in self.dest_deny:
                return

            log("RNS - Received '"+self.aspect_filter+"' announce for "+RNS.prettyhexrep(destination_hash)+" "+str(hop_count)+" hops away with data: "+app_data, LOG_DEBUG)

            self.callback(
                dest=destination_hash,
                app_data=app_data,
                dest_type=dest_type,
                hop_count=hop_count,
                hop_interface=hop_interface,
                hop_dest=None
            )

        except Exception as e:
            log("RNS - Error while processing received announce: "+str(e), LOG_ERROR)


##############################################################################################################
# Database


def db_connect():
    global DB

    if DB == None:
        DB = sqlite3.connect(PATH+"/database.db", isolation_level=None, check_same_thread=False)

    return DB


def db_commit():
    global DB

    if DB != None:
        try:
            DB.commit()
        except:
            pass


def db_init(init=True):
    db = db_connect()
    dbc = db.cursor()

    if init:
        dbc.execute("DROP TABLE IF EXISTS announce")
    dbc.execute("CREATE TABLE IF NOT EXISTS announce (dest BLOB PRIMARY KEY, ts INTEGER DEFAULT 0, data TEXT DEFAULT '', type INTEGER DEFAULT 0, hop_count INTEGER DEFAULT 0, hop_interface TEXT DEFAULT '', hop_dest BLOB)")

    db_commit()


def db_migrate():
    db_init(False)

    db = db_connect()
    dbc = db.cursor()

    db_commit()

    db_init(False)


def db_indices():
    pass


def db_load():
    if not os.path.isfile(PATH+"/database.db"):
        db_init()
    else:
        db_migrate()
        db_indices()


def db_announce_add(dest, app_data, dest_type=0x01, hop_count=0, hop_interface="", hop_dest=None):
    db = db_connect()
    dbc = db.cursor()

    if app_data == "":
        query = "SELECT dest FROM announce WHERE dest = ?"
        dbc.execute(query, (dest,))
        result = dbc.fetchall()
        if len(result) > 0:
            query = "UPDATE announce SET ts = ?, type = ?, hop_count = ?, hop_interface = ?, hop_dest = ? WHERE dest = ?"
            dbc.execute(query, (time.time(), dest_type, hop_count, hop_interface, hop_dest, dest))
        else:
            query = "INSERT OR REPLACE INTO announce (dest, ts, data, type, hop_count, hop_interface, hop_dest) values (?, ?, ?, ?, ?, ?, ?)"
            dbc.execute(query, (dest, time.time(), app_data, dest_type, hop_count, hop_interface, hop_dest))
    else:
        query = "INSERT OR REPLACE INTO announce (dest, ts, data, type, hop_count, hop_interface, hop_dest) values (?, ?, ?, ?, ?, ?, ?)"
        dbc.execute(query, (dest, time.time(), app_data, dest_type, hop_count, hop_interface, hop_dest))

    db_commit()


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
# CMDs


def cmd(path=None):
    global PATH

    if path is not None:
        if path.endswith("/"):
            path = path[:-1]
        PATH = path

    try:
        import readline
    except ImportError:
        pass

    print("---- Database interface ----")
    print("")

    print("File: "+PATH+"/database.db")
    print("")

    db = db_connect()

    while True:
        try:
            print("> ")
            cmd = input()
            if cmd.strip() == "":
                continue
            readline.add_history(cmd)
            if cmd.lower() == "exit" or cmd.lower() == "quit":
                exit()

        except KeyboardInterrupt:
            exit()

        except EOFError:
            exit()

        if cmd.lower() == "clear":
            print("\033c", end="")
        else:
            try:
                dbc = db.cursor()
                dbc.execute(cmd)
                result = dbc.fetchall()
                print("Rows: "+str(len(result)))
                print("Data:")
                for row in result:
                    print(row)
                    print("")
                db_commit()
            except Exception as e:
                print("Error: "+str(e))


def cmd_status(path=None):
    global PATH

    if path is not None:
        if path.endswith("/"):
            path = path[:-1]
        PATH = path

    print("---- Database status ----")
    print("")

    print("File: "+PATH+"/database.db")
    print("Size: "+cmd_size_str(os.path.getsize(PATH+"/database.db")))

    db = db_connect()
    dbc = db.cursor()

    query = "SELECT name FROM sqlite_master WHERE type = 'table'"
    dbc.execute(query)
    result = dbc.fetchall()
    if len(result) < 1:
        print("Error: Empty result")
    else:
        query = ""
        for entry in result:
            query += "SELECT '"+entry[0]+"', count(*) FROM "+entry[0]+" UNION "
        query = query.removesuffix(' UNION ')
        dbc.execute(query)
        result = dbc.fetchall()
        if len(result) < 1:
            print("Error: Empty result")
        else:
            print("")
            print("Tables:")
            for entry in result:
                print(entry[0]+": "+str(entry[1]))


def cmd_size_str(num, suffix='B'):
    if num == None:
        return "0"+suffix
    units = ['','K','M','G','T','P','E','Z']
    last_unit = 'Y'
    if suffix == 'b':
        num *= 8
        units = ['','K','M','G','T','P','E','Z']
        last_unit = 'Y'
    for unit in units:
        if abs(num) < 1000.0:
            if unit == "":
                return "%.0f%s%s" % (num, unit, suffix)
            else:
                return "%.2f%s%s" % (num, unit, suffix)
        num /= 1000.0
    return "%.2f%s%s" % (num, last_unit, suffix)


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
    global RNS_ANNOUNCE_HANDLER

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
    log("        Name: " + NAME, LOG_INFO)
    log("Program File: " + __file__, LOG_INFO)
    log(" Config File: " + PATH + "/config.cfg", LOG_INFO)
    log("     DB File: " + PATH + "/database.db", LOG_INFO)
    log("     Version: " + VERSION, LOG_INFO)
    log("   Copyright: " + COPYRIGHT, LOG_INFO)
    log("...............................................................................", LOG_INFO)

    log("DB - Loading ...", LOG_DEBUG)

    db_load()

    log("DB - Loaded ...", LOG_DEBUG)

    log("RNS - Connecting ...", LOG_DEBUG)

    RNS_ANNOUNCE_HANDLER = {}

    dest_deny = []
    if CONFIG.has_section("deny"):
        for (key, val) in CONFIG.items("deny"):
            try:
                if len(val) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                    val = val[1:-1]
                if len(val) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                    continue
                val = bytes.fromhex(val)
                dest_deny.append(val)
            except:
                pass

    for section in CONFIG.sections():
        try:
            if section == "main" or section == "deny":
                continue
            if not config_getboolean(CONFIG, section, "enabled"):
                continue

            dest_type = int(config_get(CONFIG, section, "type"), 16)
            hidden = config_getboolean(CONFIG, section, "hidden")
            hop_min = config_getint(CONFIG, section, "hop_min")
            hop_max = config_getint(CONFIG, section, "hop_max")
            hop_interfaces = config_get(CONFIG, section, "hop_interfaces").strip()
            if hop_interfaces.strip() != "":
                hop_interfaces = hop_interfaces.strip().split(",")
            else:
                hop_interfaces = []
            recall_app_data = config_get(CONFIG, section, "recall_app_data")

            RNS_ANNOUNCE_HANDLER[section] = AnnounceHandler(section, db_announce_add, dest_type, hidden, hop_min, hop_max, hop_interfaces, recall_app_data, dest_deny)
            RNS.Transport.register_announce_handler(RNS_ANNOUNCE_HANDLER[section])

            log("RNS - Added announce handler for '"+section+"'", LOG_DEBUG)
        except Exception as e:
            log("RNS - Error while adding announce handler: "+str(e), LOG_ERROR)

    log("RNS - Connected with "+str(len(RNS_ANNOUNCE_HANDLER))+" announce handlers", LOG_DEBUG)

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

        parser.add_argument("--cmd", action="store_true", default=False, help="Database command interface (Execute any sql database command)")
        parser.add_argument("--cmd_status", action="store_true", default=False, help="Database status interface (Shows the current status)")

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

        if params.cmd:
            cmd(path=params.path)
            exit()

        if params.cmd_status:
            cmd_status(path=params.path)
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


#### All announce aspects and settings ####


[lxmf.delivery]
enabled = True
type = 0x01
hidden = False
hop_min = 0 #0=any
hop_max = 0 #0=any
hop_interfaces = #Comma separated list

[lxmf.propagation]
enabled = True
type = 0xAD
hidden = False
hop_min = 0 #0=any
hop_max = 0 #0=any
hop_interfaces = #Comma separated list
recall_app_data = nomadnetwork.node

[nomadnetwork.node]
enabled = True
type = 0xAC
hidden = False
hop_min = 0 #0=any
hop_max = 0 #0=any
hop_interfaces = #Comma separated list
'''


#### Default configuration file ####
DEFAULT_CONFIG = '''# This is the default config file.
# You should probably edit it to suit your needs and use-case.


#### Main program settings ####
[main]

# Enable/Disable this functionality.
enabled = True


#### Deny certain addresses/destinations ####
[deny]
#2858b7a096899116cd529559cc679ffe
'''


##############################################################################################################
# Init


if __name__ == "__main__":
    main()