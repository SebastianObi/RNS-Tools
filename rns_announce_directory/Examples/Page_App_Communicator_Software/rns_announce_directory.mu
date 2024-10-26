#!/usr/bin/env python3


##############################################################################################################
# Manual


# - This program is compatible with: Communicator
# - Copy file to any subfolder or root folder of nomadnet pages.
# - Make the file executable with the command chmod +x <filename>
# - Rename the file as you want.
# - Modify the configuration section in this file according to your own needs. This can, but does not have to be changed.
# - Create a link to this file on the start page or another nomadnet page.
# - Open the page in nomandet client.
# - The first time the page is opened, the data file will be created in the .filename folder in the user's home directory.


##############################################################################################################
# Configuration


# Debug mode (display of debug information).
DEBUG = False #True/False

# Alternative path
PATH = None

# Number of datasets which will be viewed.
DATA_COUNT_VIEW = 50 #0=No limit

# Browser pages cache time in seconds.
CACHE_TIME = 0 #0=No cache, None=Default

# Date/time format for formatting on the screen.
DATE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Mapping the announcement type to the link type
TYPE_LINK = {0x01: "lxmf", 0xAC: "nnn", 0xB0: "shop", 0xB5: "task"}

# Screen template - Main (Use on all pages)
TEMPLATE_MAIN = """
>`cAnkündigungen Log

Letztes Update: {date_time}`c
{entrys}

`c`[Startseite`:/page/index.mu]`
"""

# Screen template - Entry (Use for each entry)
TEMPLATE_ENTRY = """`;2l;;{date_time} ({hop_count} Hops);{data};;{type_link}@{dest};`"""


##############################################################################################################
# Include


#### System ####
import os
import time

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


def db_init(init=True):
    db = db_connect()
    dbc = db.cursor()

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


def db_announce_filter(filter):
    if filter == None:
        return ""

    querys = []

    if "type" in filter and filter["type"] != None:
        if isinstance(filter["type"], int):
            querys.append("type = '"+str(filter["type"])+"'")
        else:
            array = [str(key) for key in filter["type"]]
            querys.append("(type = '"+"' OR type = '".join(array)+"')")

    if "ts_min" in filter and filter["ts_min"] != None:
        querys.append("ts >= "+str(filter["ts_min"]))

    if "ts_max" in filter and filter["ts_max"] != None:
        querys.append("ts <= "+str(filter["ts_max"]))

    if "hop_min" in filter and filter["hop_min"] != None:
        querys.append("hop_count >= "+str(filter["hop_min"]))

    if "hop_max" in filter and filter["hop_max"] != None:
        querys.append("hop_count <= "+str(filter["hop_max"]))

    if "interface" in filter and filter["interface"] != None:
        if isinstance(filter["interface"], str):
            querys.append("hop_interface LIKE '%"+filter["interface"]+"%'")
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


def db_announce_order(order):
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


def db_announce_list(filter=None, search=None, order=None, limit=None, limit_start=None):
    db = db_connect()
    dbc = db.cursor()

    query_filter = db_announce_filter(filter)

    query_order = db_announce_order(order)

    if limit == None or limit_start == None:
        query_limit = ""
    else:
        query_limit = " LIMIT "+str(limit)+" OFFSET "+str(limit_start)

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
                "type": entry[1],
                "ts": entry[2],
                "data": entry[3],
                "location_lat": entry[4],
                "location_lon": entry[5],
                "owner": entry[6],
                "state": entry[7],
                "state_ts": entry[8],
                "hop_count": entry[9]
            })

        return data


def db_announce_count(filter=None, search=None):
    db = db_connect()
    dbc = db.cursor()

    query_filter = db_announce_filter(filter)

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


if "remote_identity" in os.environ:
    DEST = RNS.hexrep(RNS.Destination.hash_from_name_and_identity("lxmf.delivery", bytes.fromhex(os.environ["remote_identity"])), delimit=False)
else:
    DEST = ""


if "var_dn" in os.environ:
    NAME = os.environ["var_dn"]
else:
    NAME = ""


if CACHE_TIME != None:
    print("#!c="+str(CACHE_TIME))


if DEBUG:
    print(os.environ)


db_load()


entrys = ""
for entry in db_announce_list(filter={}, search="", order="DESC", limit=DATA_COUNT_VIEW, limit_start=0):
    tpl = TEMPLATE_ENTRY
    if entry["type"] not in TYPE_LINK:
        continue
    tpl = tpl.replace("{type_link}", TYPE_LINK[entry["type"]])
    tpl = tpl.replace("{dest}", RNS.hexrep(entry["dest"], delimit=False))
    tpl = tpl.replace("{date_time}", time.strftime(DATE_TIME_FORMAT, time.localtime(entry["ts"])))
    tpl = tpl.replace("{data}", entry["data"])
    tpl = tpl.replace("{hop_count}", str(entry["hop_count"]))
    tpl = tpl.replace("{hop_interface}", entry["hop_interface"])
    entrys += tpl+"\n"


tpl = TEMPLATE_MAIN
tpl = tpl.replace("{self}", FILE)
tpl = tpl.replace("{date_time}", time.strftime(DATE_TIME_FORMAT, time.localtime(time.time())))
tpl = tpl.replace("{entrys}", entrys)
print(tpl)
