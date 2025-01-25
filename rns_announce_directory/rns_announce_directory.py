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

#### Config ####
import configparser

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack

#### Database - SQLite ####
import sqlite3

#### Database - PostgreSQL ####
# Install: pip3 install psycopg2
# Install: pip3 install psycopg2-binary
# Source: https://pypi.org/project/psycopg2/
import psycopg2


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "RNS Announce Directory"
DESCRIPTION = "Database for the collection of received announcements"
VERSION = "0.0.1 (2024-05-31)"
COPYRIGHT = "(c) 2024 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/"+os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None


#### Global Variables - System (Not changeable) ####
CONFIG = None
DB = None
RNS_CONNECTION = None
RNS_ANNOUNCE_HANDLER = None

MSG_FIELD_EMBEDDED_LXMS    = 0x01
MSG_FIELD_TELEMETRY        = 0x02
MSG_FIELD_TELEMETRY_STREAM = 0x03
MSG_FIELD_ICON_APPEARANCE  = 0x04
MSG_FIELD_FILE_ATTACHMENTS = 0x05
MSG_FIELD_IMAGE            = 0x06
MSG_FIELD_AUDIO            = 0x07
MSG_FIELD_THREAD           = 0x08
MSG_FIELD_COMMANDS         = 0x09
MSG_FIELD_RESULTS          = 0x0A
MSG_FIELD_GROUP            = 0x0B
MSG_FIELD_TICKET           = 0x0C
MSG_FIELD_EVENT            = 0x0D
MSG_FIELD_RNR_REFS         = 0x0E
MSG_FIELD_RENDERER         = 0x0F
MSG_FIELD_CUSTOM_TYPE      = 0xFB
MSG_FIELD_CUSTOM_DATA      = 0xFC
MSG_FIELD_CUSTOM_META      = 0xFD
MSG_FIELD_NON_SPECIFIC     = 0xFE
MSG_FIELD_DEBUG            = 0xFF

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
MSG_FIELD_ICON               = 0xC1
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
# AnnounceHandler Class


class AnnounceHandler:
    def __init__(self, aspect_filter=None, callback=None, dest_type=None, hidden=False, hop_min=0, hop_max=0, hop_interfaces=[], recall_app_data=None, recall_app_data_type=None, dest_allow=[], dest_deny=[]):
        self.aspect_filter = aspect_filter
        self.callback = callback
        self.dest_type = dest_type
        self.hidden = hidden
        self.hop_min = hop_min
        self.hop_max = hop_max
        self.hop_interfaces = hop_interfaces
        self.recall_app_data = recall_app_data
        self.recall_app_data_type = recall_app_data_type
        self.dest_allow = dest_allow
        self.dest_deny = dest_deny


    def received_announce(self, destination_hash, announced_identity, app_data, announce_packet_hash):
        if app_data == None:
            if self.hidden:
                app_data = b""
            else:
                return

        if len(app_data) == 0:
            if self.hidden:
                app_data = b""
            else:
                return

        dest_type = [self.dest_type]
        dest_recall = None
        dest_recall_type = None

        data = b""
        metadata = {}
        fields = None

        rssi = RNS_CONNECTION.get_packet_rssi(announce_packet_hash)
        snr = RNS_CONNECTION.get_packet_snr(announce_packet_hash)
        q = RNS_CONNECTION.get_packet_q(announce_packet_hash)
        if rssi or snr or q:
            metadata["rssi"] = rssi
            metadata["snr"] = snr
            metadata["q"] = q

        if self.aspect_filter == "lxmf.propagation":
            try:
                unpacked = msgpack.unpackb(app_data)
                metadata["node_enabled"] = unpacked[0]
                metadata["node_ts"] = unpacked[1]
                metadata["node_transfer_limit"] = unpacked[2]
                app_data = unpacked[3] if len(unpacked) > 3 else  b""
                fields = unpacked[4] if len(unpacked) > 4 and unpacked[4] != None and isinstance(unpacked[4], dict) else None
            except:
                pass

        if self.recall_app_data:
            try:
                identity = RNS.Identity.recall(destination_hash)
                if identity != None:
                    dest_recall = RNS.Destination.hash_from_name_and_identity(self.recall_app_data, identity)
                    dest_recall_type = self.recall_app_data_type
                    recall_app_data = RNS.Identity.recall_app_data(dest_recall)
                    if recall_app_data != None and len(recall_app_data) > 0:
                        app_data = recall_app_data
            except:
                pass

        try:
            if (app_data[0] >= 0x90 and app_data[0] <= 0x9f) or app_data[0] == 0xdc:
                app_data = msgpack.unpackb(app_data)
                if isinstance(app_data, list):
                    if len(app_data) > 1 and app_data[0] != None:
                        data = app_data[0]
                        if app_data[1] != None and self.aspect_filter == "lxmf.delivery":
                            metadata["stamp_cost"] = app_data[1]
                    if len(app_data) > 2 and app_data[2] != None and isinstance(app_data[2], dict):
                        fields = app_data[2]
            else:
                data = app_data
        except:
            pass

        try:
            data = data.decode("utf-8")
            hop_count = RNS.Transport.hops_to(destination_hash)
            hop_interface = RNS_CONNECTION.get_next_hop_if_name(destination_hash)

            if self.hop_min > 0 and hop_count < self.hop_min:
                return

            if self.hop_max > 0 and hop_count > self.hop_max:
                return

            if len(self.hop_interfaces) > 0 and hop_interface not in self.hop_interfaces:
                return

            if len(self.dest_allow) > 0 and destination_hash not in self.dest_allow:
                return

            if len(self.dest_deny) > 0 and destination_hash in self.dest_deny:
                return

            location_lat = 0
            location_lon = 0
            owner = None
            state = 0
            state_ts = 0

            if fields:
                if MSG_FIELD_TYPE in fields:
                    dest_type = fields[MSG_FIELD_TYPE]
                    if not isinstance(dest_type, list):
                        dest_type = [dest_type]
                if MSG_FIELD_LOCATION in fields:
                    location_lat = fields[MSG_FIELD_LOCATION][0]
                    location_lon = fields[MSG_FIELD_LOCATION][1]
                if MSG_FIELD_OWNER in fields:
                    owner = fields[MSG_FIELD_OWNER]
                if MSG_FIELD_STATE in fields:
                    d_state = fields[MSG_FIELD_STATE]
                    if isinstance(d_state, list):
                        state = d_state[0]
                        state_ts = d_state[1]
                    else:
                        state = d_state
                        state_ts = 0

            log("RNS - Received '"+self.aspect_filter+"' announce for "+RNS.prettyhexrep(destination_hash)+" "+str(hop_count)+" hops away with data: "+data, LOG_DEBUG)

            for key in dest_type:
                self.callback(
                    dest=destination_hash,
                    dest_type=key,
                    dest_recall=dest_recall,
                    dest_recall_type=dest_recall_type,
                    data=data,
                    metadata=metadata if len(metadata) > 0 else None,
                    location_lat=location_lat,
                    location_lon=location_lon,
                    owner=owner,
                    state=state,
                    state_ts=state_ts,
                    hop_count=hop_count,
                    hop_interface=hop_interface,
                    hop_dest=None,
                    aspect_filter=self.aspect_filter
                )

        except Exception as e:
            log("RNS - Error while processing received announce: "+str(e), LOG_ERROR)


##############################################################################################################
# Database


def db_connect():
    global DB

    try:
        if DB == None:
            if CONFIG["database"]["type"] == "postgresql":
                DB = psycopg2.connect(user=CONFIG["database"]["user"], password=CONFIG["database"]["password"], host=CONFIG["database"]["host"], port=CONFIG["database"]["port"], database=CONFIG["database"]["database"], client_encoding=CONFIG["database"]["encoding"], connect_timeout=5)
            else:
                DB = sqlite3.connect(PATH+"/database.db", isolation_level=None, check_same_thread=False)
    except:
        DB = None

    return DB


def db_commit():
    global DB

    if DB != None:
        try:
            DB.commit()
        except:
            if CONFIG["database"]["type"] == "postgresql":
                DB.rollback()


def db_init(init=True):
    db = db_connect()
    dbc = db.cursor()

    if CONFIG["database"]["type"] == "postgresql":
        if init:
            dbc.execute("DROP TABLE IF EXISTS public.announces")
        dbc.execute("""CREATE TABLE IF NOT EXISTS public.announces(dest character varying(32) COLLATE pg_catalog."default" NOT NULL, dest_type integer NOT NULL, data character varying COLLATE pg_catalog."default", data_meta BYTEA, location_lat double precision, location_lon double precision, owner character varying(32) COLLATE pg_catalog."default", state integer, state_ts integer NOT NULL, hop_count integer, hop_interface character varying COLLATE pg_catalog."default", hop_dest character varying(32) COLLATE pg_catalog."default", ts_add integer NOT NULL, ts_edit integer NOT NULL, CONSTRAINT announces_pkey PRIMARY KEY (dest, dest_type))""")
    else:
        if init:
            dbc.execute("DROP TABLE IF EXISTS announces")
        dbc.execute("CREATE TABLE IF NOT EXISTS announces (dest BLOB, dest_type INTEGER DEFAULT 0, data TEXT DEFAULT '', metadata BLOB, location_lat REAL DEFAULT 0, location_lon REAL DEFAULT 0, owner BLOB, state INTEGER DEFAULT 0, state_ts INTEGER DEFAULT 0, hop_count INTEGER DEFAULT 0, hop_interface TEXT DEFAULT '', hop_dest BLOB, ts_add INTEGER DEFAULT 0, ts_edit INTEGER DEFAULT 0, PRIMARY KEY(dest, dest_type))")

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
    db_init(False)


def db_add(dest, dest_type=0x01, dest_recall=None, dest_recall_type=None, data="", metadata=None, location_lat=0, location_lon=0, owner=None, state=0, state_ts=0, hop_count=0, hop_interface="", hop_dest=None, aspect_filter=""):
    db = db_connect()
    dbc = db.cursor()

    if CONFIG["database"]["type"] == "postgresql":
        dest = RNS.hexrep(dest, False)

        if owner:
            owner = RNS.hexrep(owner, False)
        else:
            owner = ""

        if hop_dest == None:
            hop_dest = ""
        else:
            hop_dest = RNS.hexrep(hop_dest, False)

        ts = int(time.time())
        state_ts = int(state_ts)

        query = "SELECT dest FROM announces WHERE dest = %s AND dest_type = %s"
        dbc.execute(query, (dest, dest_type))
        exist = True if len(dbc.fetchall()) > 0 else False

        if dest_recall and dest_recall_type:
            query = "SELECT * FROM announces WHERE dest = %s AND dest_type = %s"
            dbc.execute(query, (RNS.hexrep(dest_recall, False), dest_recall_type))
            result = dbc.fetchall()
            if len(result) > 0:
                entry = result[0]
                data = entry[2].strip()
                location_lat = entry[4]
                location_lon = entry[5]
                owner = entry[6].strip()
                state = entry[7]
                state_ts = entry[8]

        if not exist:
            query = "INSERT INTO announces (dest, dest_type, data, data_meta, location_lat, location_lon, owner, state, state_ts, hop_count, hop_interface, hop_dest, ts_add, ts_edit) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            dbc.execute(query, (dest, dest_type, data, msgpack.packb(metadata), location_lat, location_lon, owner, state, state_ts, hop_count, hop_interface, hop_dest, ts, ts))
        elif data == "":
            query = "UPDATE announces SET hop_count = %s, hop_interface = %s, hop_dest = %s, ts_edit = %s WHERE dest = %s AND dest_type = %s"
            dbc.execute(query, (hop_count, hop_interface, hop_dest, ts, dest, dest_type))
        else:
            query = "UPDATE announces SET data = %s, data_meta = %s, location_lat = %s, location_lon = %s, owner = %s, state = %s, state_ts = %s, hop_count = %s, hop_interface = %s, hop_dest = %s, ts_edit = %s WHERE dest = %s AND dest_type = %s"
            dbc.execute(query, (data, msgpack.packb(metadata), location_lat, location_lon, owner, state, state_ts, hop_count, hop_interface, hop_dest, ts, dest, dest_type))

    else:
        ts = int(time.time())
        state_ts = int(state_ts)

        query = "SELECT dest FROM announces WHERE dest = ? AND dest_type = ?"
        dbc.execute(query, (dest, dest_type))
        exist = True if len(dbc.fetchall()) > 0 else False

        if dest_recall and dest_recall_type:
            query = "SELECT * FROM announces WHERE dest = ? AND dest_type = ?"
            dbc.execute(query, (dest_recall, dest_recall_type))
            result = dbc.fetchall()
            if len(result) > 0:
                entry = result[0]
                data = entry[2]
                metadata = msgpack.unpackb(entry[3])
                location_lat = entry[4]
                location_lon = entry[5]
                owner = entry[6]
                state = entry[7]
                state_ts = entry[8]

        if not exist:
            query = "INSERT OR REPLACE INTO announces (dest, dest_type, data, metadata, location_lat, location_lon, owner, state, state_ts, hop_count, hop_interface, hop_dest, ts_add, ts_edit) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            dbc.execute(query, (dest, dest_type, data, msgpack.packb(metadata), location_lat, location_lon, owner, state, state_ts, hop_count, hop_interface, hop_dest, ts, ts))
        elif data == "":
            query = "UPDATE announces SET hop_count = ?, hop_interface = ?, hop_dest = ?, ts_edit = ? WHERE dest = ? AND dest_type = ?"
            dbc.execute(query, (hop_count, hop_interface, hop_dest, ts , dest, dest_type))
        else:
            query = "UPDATE announces SET data = ?, metadata = ?, location_lat = ?, location_lon = ?, owner = ?, state = ?, state_ts = ?, hop_count = ?, hop_interface = ?, hop_dest = ?, ts_edit = ? WHERE dest = ? AND dest_type = ?"
            dbc.execute(query, (data, msgpack.packb(metadata), location_lat, location_lon, owner, state, state_ts, hop_count, hop_interface, hop_dest, ts, dest, dest_type))

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

    if CONFIG["database"]["type"] == "postgresql":
        print("Database: "+CONFIG["database"]["host"]+":"+CONFIG["database"]["port"]+"/"+CONFIG["database"]["database"])
        print("")
    else:
        print("File: "+PATH+"/database.db")
        print("")

    db = db_connect()

    while True:
        try:
            print("> ")
            cmd = input()
            if cmd.strip() == "":
                continue
            if cmd.lower() == "exit" or cmd.lower() == "quit":
                exit()
            readline.add_history(cmd)

        except KeyboardInterrupt:
            exit()

        except EOFError:
            exit()

        except:
            pass

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

    if CONFIG["database"]["type"] == "postgresql":
        print("Database: "+CONFIG["database"]["host"]+":"+CONFIG["database"]["port"]+"/"+CONFIG["database"]["database"])
        print("")
    else:
        print("File: "+PATH+"/database.db")
        print("Size: "+cmd_size_str(os.path.getsize(PATH+"/database.db")))

    db = db_connect()
    dbc = db.cursor()

    if CONFIG["database"]["type"] == "postgresql":
        query = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
    else:
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
def setup(path=None, path_rns=None, path_log=None, loglevel=None, service=False, require_shared_instance=False, cmd=None):
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

    if cmd:
        return

    RNS_CONNECTION = RNS.Reticulum(configdir=PATH_RNS, loglevel=rns_loglevel, require_shared_instance=require_shared_instance)

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

    dest_allow = []
    if CONFIG.has_section("allow"):
        for (key, val) in CONFIG.items("allow"):
            try:
                if len(val) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                    val = val[1:-1]
                if len(val) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                    continue
                val = bytes.fromhex(val)
                dest_allow.append(val)
            except:
                pass

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
            if recall_app_data:
                recall_app_data_type = int(config_get(CONFIG, recall_app_data, "type"), 16)
            else:
                recall_app_data_type = None

            RNS_ANNOUNCE_HANDLER[section] = AnnounceHandler(section, db_add, dest_type, hidden, hop_min, hop_max, hop_interfaces, recall_app_data, recall_app_data_type, dest_allow, dest_deny)
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
        parser.add_argument("-rs", "--require_shared_instance", action="store_true", default=False, help="Require a shared reticulum instance")

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

        setup(path=params.path, path_rns=params.path_rns, path_log=params.path_log, loglevel=params.loglevel, service=params.service, require_shared_instance=params.require_shared_instance, cmd=True if params.cmd or params.cmd_status else False)

        if params.cmd:
            cmd(path=params.path)
            exit()

        if params.cmd_status:
            cmd_status(path=params.path)
            exit()

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


[database]
type = sqlite #postgresql/sqlite
host = 127.0.0.1
port = 5432
user = postgres
password = password
database = database
encoding = utf8


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


#### Database connection settings ####
[database]
type = sqlite #postgresql/sqlite
host = 127.0.0.1
port = 5432
user = postgres
password = password
database = database
encoding = utf8


#### Deny certain addresses/destinations ####
[deny]
#2858b7a096899116cd529559cc679ffe
'''


##############################################################################################################
# Init


if __name__ == "__main__":
    main()