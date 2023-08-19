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

KEY_DATA = "var_data"
KEY_ENTRYS = "rx_entrys"
KEY_ENTRYS_COUNT = "rx_entrys_count"
KEY_RESULT = "result"

RESULT_OK    = 0x01
RESULT_ERROR = 0x00


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
import RNS.vendor.umsgpack as umsgpack


##############################################################################################################
# Globals  - System (Not changeable)


FILE = os.path.splitext(os.path.basename(__file__))[0]

if PATH == None:
    PATH = os.path.expanduser("~")+"/."+FILE

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

    if "ts_min" in filter and filter["ts_min"] != None:
        querys.append("ts >= "+db_sanitize(filter["ts_min"]))

    if "ts_max" in filter and filter["ts_max"] != None:
        querys.append("ts <= "+db_sanitize(filter["ts_max"]))

    if "hop_min" in filter and filter["hop_min"] != None:
        querys.append("hop_count >= "+db_sanitize(filter["hop_min"]))

    if "hop_max" in filter and filter["hop_max"] != None:
        querys.append("hop_count <= "+db_sanitize(filter["hop_max"]))

    if "interface" in filter and filter["interface"] != None:
        if isinstance(filter["interface"], str):
            querys.append("hop_interface LIKE '%"+db_sanitize(filter["interface"])+"%'")
        else:
            querys.append("(hop_interface LIKE '%"+"%' OR hop_interface LIKE '%".join(filter["interface"])+"%')")

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


def db_order(order):
    if order == "A-ASC":
        query = " ORDER BY data ASC"
    elif order == "A-DESC":
        query = " ORDER BY data DESC"
    elif order == "ASC":
        query = " ORDER BY ts ASC, data ASC"
    elif order == "DESC":
        query = " ORDER BY ts DESC, data ASC"
    else:
        query = ""

    return query


def db_list(filter=None, search=None, order=None, limit=None, limit_start=None):
    db = db_connect()
    dbc = db.cursor()

    query_filter = db_filter(filter)

    query_order = db_order(order)

    if limit == None or limit_start == None:
        query_limit = ""
    else:
        query_limit = " LIMIT "+db_sanitize(limit)+" OFFSET "+db_sanitize(limit_start)

    if search:
        search = "%"+search+"%"
        query = "SELECT * FROM announce WHERE ts > 0 AND data LIKE ? COLLATE NOCASE"+query_filter+query_order+query_limit
        dbc.execute(query, (search,))
    else:
        query = "SELECT * FROM announce WHERE ts > 0"+query_filter+query_order+query_limit
        dbc.execute(query)

    result = dbc.fetchall()

    if len(result) < 1:
        return []
    else:
        data = []
        for entry in result:
            data.append({
                "dest": entry[0],
                "ts": entry[1],
                "data": entry[2],
                "type": entry[3]
            })

        return data


def db_count(filter=None, search=None):
    db = db_connect()
    dbc = db.cursor()

    query_filter = db_filter(filter)

    if search:
        search = "%"+search+"%"
        query = "SELECT COUNT(*) FROM announce WHERE ts > 0 AND data LIKE ? COLLATE NOCASE"+query_filter
        dbc.execute(query, (search,))
    else:
        query = "SELECT COUNT(*) FROM announce WHERE ts > 0"+query_filter
        dbc.execute(query)

    result = dbc.fetchall()

    if len(result) < 1:
        return 0
    else:
        return result[0][0]


##############################################################################################################
# Program


data_return = {}

try:
    if DEBUG:
        print(os.environ)

    data = os.environ[KEY_DATA]
    data = umsgpack.unpackb(base64.b64decode(data))

    if DEBUG:
        print(data)

    data_return[KEY_ENTRYS] = db_list(filter=data["filter"], search=data["search"], order=data["order"], limit=data["limit"], limit_start=data["limit_start"])
    data_return[KEY_ENTRYS_COUNT] = db_count(filter=data["filter"], search=data["search"])

    data_return[KEY_RESULT] = RESULT_OK

except Exception as e:
    data_return[KEY_RESULT] = RESULT_ERROR

sys.stdout.buffer.write(umsgpack.packb(data_return))
sys.stdout.flush() 
