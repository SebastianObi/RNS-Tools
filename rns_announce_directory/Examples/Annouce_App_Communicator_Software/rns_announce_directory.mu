#!/usr/bin/env python3


##############################################################################################################
# Manual


# - This program is compatible with: Communicator
# - Copy file to any subfolder or root folder of nomadnet pages.
# - Make the file executable with the command chmod +x <filename>
# - Rename the file as you want.
# - Modify the configuration section in this file according to your own needs. This can, but does not have to be changed.


##############################################################################################################
# Configuration


# Debug mode (display of debug information).
DEBUG = False #True/False

# Alternative path
PATH = None

KEY_RESULT        = 0x0A # Result
KEY_RESULT_REASON = 0x0B # Result - Reason
KEY_DATA          = "var_data"
KEY_ENTRYS        = "rx_entrys"
KEY_ENTRYS_COUNT  = "rx_entrys_count"
KEY_CMD           = "cmd"
KEY_CMD_ENTRY     = "cmd_entry"
KEY_CMD_RESULT    = "cmd_result"

RESULT_ERROR = 0x00
RESULT_OK    = 0x01

# Admin destinations (LXMF-Adresses)
ADMINS = ["652cc196d9185407a09e7ff0386741e4"] #Array

# Admin CMDs
ADMINS_CMD       = [] #Array
ADMINS_CMD_ENTRY = ["delete"] #Array


##############################################################################################################
# Include


#### System ####
import sys
import os
import base64

#### Database ####
import sqlite3

#### Reticulum ####
import RNS
import RNS.vendor.umsgpack as msgpack


##############################################################################################################
# Globals  - System (Not changeable)


FILE = os.path.splitext(os.path.basename(__file__))[0]

if PATH == None:
    PATH = os.path.expanduser("~")+"/.config/"+FILE

DB = None


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


def db_sanitize(value):
    value = str(value)
    value = value.replace('\\', "")
    value = value.replace("\0", "")
    value = value.replace("\n", "")
    value = value.replace("\r", "")
    value = value.replace("'", "")
    value = value.replace('"', "")
    value = value.replace("\x1a", "")
    return value


def db_init(init=True):
   pass


def db_migrate():
    pass


def db_indices():
    pass


def db_load():
    pass


def db_filter(filter):
    if filter == None:
        return ""

    querys = []

    if "type" in filter and filter["type"] != None:
        if isinstance(filter["type"], int):
            querys.append("type = '"+db_sanitize(filter["type"])+"'")
        else:
            array = [db_sanitize(key) for key in filter["type"]]
            querys.append("(type = '"+"' OR type = '".join(array)+"')")

    if "hop_min" in filter and filter["hop_min"] != None:
        querys.append("hop_count >= "+db_sanitize(filter["hop_min"]))

    if "hop_max" in filter and filter["hop_max"] != None:
        querys.append("hop_count <= "+db_sanitize(filter["hop_max"]))

    if "interface" in filter and filter["interface"] != None:
        if isinstance(filter["interface"], str):
            querys.append("hop_interface LIKE '%"+db_sanitize(filter["interface"])+"%'")
        else:
            querys.append("(hop_interface LIKE '%"+"%' OR hop_interface LIKE '%".join(filter["interface"])+"%')")

    if "state" in filter:
        querys.append("state = '"+self.__db_sanitize(filter["state"])+"'")

    if "state_ts_min" in filter and filter["state_ts_min"] != None:
        querys.append("state_ts >= "+self.__db_sanitize(filter["state_ts_min"]))

    if "state_ts_max" in filter and filter["state_ts_max"] != None:
        querys.append("state_ts <= "+self.__db_sanitize(filter["state_ts_max"]))

    if "ts_add_min" in filter and filter["ts_add_min"] != None:
        querys.append("ts_add >= "+db_sanitize(filter["ts_add_min"]))

    if "ts_add_max" in filter and filter["ts_add_max"] != None:
        querys.append("ts_add <= "+db_sanitize(filter["ts_add_max"]))

    if "ts_edit_min" in filter and filter["ts_edit_min"] != None:
        querys.append("ts_edit >= "+db_sanitize(filter["ts_edit_min"]))

    if "ts_edit_max" in filter and filter["ts_edit_max"] != None:
        querys.append("ts_edit <= "+db_sanitize(filter["ts_edit_max"]))

    if "pin" in filter:
        if filter["pin"] == True:
            querys.append("pin = '1'")
        elif filter["pin"] == False:
            querys.append("pin = '0'")

    if "archiv" in filter:
        if filter["archiv"] == True:
            querys.append("archiv = '1'")
        elif filter["archiv"] == False:
            querys.append("archiv = '0'")

    if len(querys) > 0:
        query = " AND "+" AND ".join(querys)
    else:
        query = ""

    return query


def db_group(group):
    if group == None:
        return ""

    querys = []

    for key in group:
        querys.append(db_sanitize(key))

    if len(querys) > 0:
        query = " GROUP BY "+", ".join(querys)
    else:
        query = ""

    return query


def db_order(order):
    if order == "A-ASC":
        query = " ORDER BY data ASC"
    elif order == "A-DESC":
        query = " ORDER BY data DESC"
    elif order == "T-ASC":
        query = " ORDER BY type ASC, ts_edit ASC, data ASC"
    elif order == "T-DESC":
        query = " ORDER BY type DESC, ts_edit ASC, data ASC"
    elif order == "H-ASC":
        query = " ORDER BY hop_count ASC, ts_edit ASC, data ASC"
    elif order == "H-DESC":
        query = " ORDER BY hop_count DESC, ts_edit ASC, data ASC"
    elif order == "I-ASC":
        query = " ORDER BY hop_interface ASC, ts_edit ASC, data ASC"
    elif order == "I-DESC":
        query = " ORDER BY hop_interface DESC, ts_edit ASC, data ASC"
    elif order == "S-ASC":
        query = " ORDER BY state_ts ASC, data ASC"
    elif order == "S-DESC":
        query = " ORDER BY state_ts DESC, data ASC"
    elif order == "TSA-ASC":
        query = " ORDER BY ts_add ASC, data ASC"
    elif order == "TSA-DESC":
        query = " ORDER BY ts_add DESC, data ASC"
    elif order == "TSE-ASC":
        query = " ORDER BY ts_edit ASC, data ASC"
    elif order == "TSE-DESC":
        query = " ORDER BY ts_edit DESC, data ASC"
    else:
        query = ""

    return query


def db_list(filter=None, search=None, group=None, order=None, limit=None, limit_start=None):
    db = db_connect()
    dbc = db.cursor()

    query_filter = db_filter(filter)

    query_group = db_group(group)

    query_order = db_order(order)

    if limit == None or limit_start == None:
        query_limit = ""
    else:
        query_limit = " LIMIT "+db_sanitize(limit)+" OFFSET "+db_sanitize(limit_start)

    if search:
        search = "%"+search+"%"
        query = "SELECT * FROM announce WHERE ts_add > 0 AND data LIKE ? COLLATE NOCASE"+query_filter+query_group+query_order+query_limit
        dbc.execute(query, (search,))
    else:
        query = "SELECT * FROM announce WHERE ts_add > 0"+query_filter+query_group+query_order+query_limit
        dbc.execute(query)

    result = dbc.fetchall()

    if len(result) < 1:
        return []
    else:
        data = []
        for entry in result:
            data.append({
                "dest": entry[0],
                "type": entry[1],
                "data": entry[2],
                "location_lat": entry[3],
                "location_lon": entry[4],
                "owner": entry[5],
                "state": entry[6],
                "state_ts": entry[7],
                "hop_count": entry[8]
                "ts_add": entry[9],
                "ts_edit": entry[10],
            })

        return data


def db_count(filter=None, search=None, group=None):
    db = db_connect()
    dbc = db.cursor()

    query_filter = db_filter(filter)

    query_group = db_group(group)

    if search:
        search = "%"+search+"%"
        query = "SELECT COUNT(*) FROM announce WHERE ts_add > 0 AND data LIKE ? COLLATE NOCASE"+query_filter+query_group
        dbc.execute(query, (search,))
    else:
        query = "SELECT COUNT(*) FROM announce WHERE ts_add > 0"+query_filter+query_group
        dbc.execute(query)

    result = dbc.fetchall()

    if len(result) < 1:
        return 0
    else:
        return result[0][0]


def db_get(dest):
    db = db_connect()
    dbc = db.cursor()

    query = "SELECT * FROM announce WHERE dest = ?"
    dbc.execute(query, (dest,))

    result = dbc.fetchall()

    if len(result) < 1:
        return None
    else:
        entry = result[0]
        data = {
            "dest": entry[0],
            "type": entry[1],
            "data": entry[2],
            "location_lat": entry[3],
            "location_lon": entry[4],
            "owner": entry[5],
            "state": entry[6],
            "state_ts": entry[7],
            "hop_count": entry[8]
            "ts_add": entry[9],
            "ts_edit": entry[10],
        }
        return data


def db_delete(dest=None, dest_not=None):
    db = db_connect()
    dbc = db.cursor()

    if dest:
        query = "DELETE FROM announce WHERE dest = ?"
        dbc.execute(query, (dest,))
    elif dest_not:
        query = "DELETE FROM announce WHERE dest != ?"
        dbc.execute(query, (dest_not,))

    db_commit()


##############################################################################################################
# CMD

def cmd(cmd):
    if cmd[0] == "delete":
        db_delete(cmd[1])

    entry = db_get(cmd[1])
    if entry:
        return {KEY_CMD_RESULT: RESULT_OK, KEY_ENTRYS: [entry]}
    else:
        return {KEY_CMD_RESULT: RESULT_OK, KEY_ENTRYS: [{"dest": cmd[1], "type": 0, "data": "", "location_lat": 0, "location_lon": 0, "state": 0, "state_ts": 0, "hop_count": 0, "ts_add": 0, "ts_edit": 0}]}


##############################################################################################################
# Program


data_return = {}

try:
    data_return[KEY_RESULT] = RESULT_OK

    if DEBUG:
        print(os.environ)

    RIGHT = "user"
    if "remote_identity" in os.environ:
        dest = RNS.hexrep(RNS.Destination.hash_from_name_and_identity("lxmf.delivery", bytes.fromhex(os.environ["remote_identity"])), delimit=False)
        if dest != "" and dest in ADMINS:
            RIGHT = "admin"

    data = os.environ[KEY_DATA]
    data = msgpack.unpackb(base64.b64decode(data))

    if DEBUG:
        print(data)

    if "cmd" in data:
        if RIGHT == "admin":
            data_return.update(cmd(data["cmd"]))
    else:
        data_return[KEY_ENTRYS] = db_list(filter=data["filter"], search=data["search"], group=data["group"], order=data["order"], limit=data["limit"], limit_start=data["limit_start"])
        data_return[KEY_ENTRYS_COUNT] = db_count(filter=data["filter"], search=data["search"], group=data["group"])

        if RIGHT == "admin":
            data_return[KEY_CMD] = ADMINS_CMD
            data_return[KEY_CMD_ENTRY] = ADMINS_CMD_ENTRY

except Exception as e:
    data_return[KEY_RESULT] = RESULT_ERROR

sys.stdout.buffer.write(msgpack.packb(data_return))
sys.stdout.flush() 
