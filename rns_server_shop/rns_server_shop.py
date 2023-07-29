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

#### Process ####
import signal
import threading

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
NAME = "RNS Server Shop"
DESCRIPTION = "Shop hosting functions for RNS based apps"
VERSION = "0.0.1 (2023-07-20)"
COPYRIGHT = "(c) 2023 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~") + "/." + os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None
RIGHTS = {0: "User", 1: "Vendor", 2: "Admin", 255: "Blocked"}
DESTINATION_NAME = "nomadnetwork"
DESTINATION_TYPE = "shop"
DESTINATION_CONV_NAME = "lxmf"
DESTINATION_CONV_TYPE = "delivery"
DEFAULT_CONFIG = {
    "enabled": True,
    "title": "Unconfigured/New Shop",
    "subtitle": "Please configure me!",
    "header": None,
    "header_color": "",
    "header_enabled": True,
    "header_enabled_entrys": True,
    "template": 1,
    "announce_hidden": False,
    "announce_startup": True,
    "announce_periodic": True,
    "announce_interval": 1800,
    "state_first_run": True
}
DEFAULT_TITLE = None
DEFAULT_CATEGORYS = {0: [0, "Test Category 1"], 1: [0, "Test Category 2"], 2: [4, "Test Subcategory 1"], 3: [4, "Test Subcategory 2"]}
DEFAULT_PAGES = {}
DEFAULT_USERS = {"any": 0}
DEFAULT_USER = None
DEFAULT_RIGHT = 2


#### Global Variables - System (Not changeable) ####
CORE = None
RNS_CONNECTION = None
RNS_SERVER_SHOP = None


##############################################################################################################
# ServerShop Class


class ServerShop:
    RESULT_ERROR       = 0x00
    RESULT_OK          = 0x01
    RESULT_SYNCRONIZE  = 0x02
    RESULT_NO_IDENTITY = 0x03
    RESULT_NO_RIGHT    = 0x04
    RESULT_DISABLED    = 0xFE
    RESULT_BLOCKED     = 0xFF


    def __init__(self, core, storage_path=None, identity_file="identity", identity=None, destination_name="nomadnetwork", destination_type="shop", destination_conv_name="lxmf", destination_conv_type="delivery", statistic=None, default_config=None, default_title=None, default_categorys=None, default_pages=None, default_users=None, default_user=None, default_right=None):
        self.core = core

        self.storage_path = storage_path

        self.identity_file = identity_file
        self.identity = identity

        self.destination_name = destination_name
        self.destination_type = destination_type
        self.aspect_filter = self.destination_name + "." + self.destination_type
        self.destination_conv_name = destination_conv_name
        self.destination_conv_type = destination_conv_type
        self.aspect_filter_conv = self.destination_conv_name + "." + self.destination_conv_type

        if statistic:
            self.statistic = statistic
        else:
            self.statistic_reset()

        self.default_config = default_config
        self.default_title = default_title
        self.default_categorys = default_categorys
        self.default_pages = default_pages
        self.default_users = default_users
        self.default_user = default_user
        self.default_right = default_right

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

        config = self.core.db_shops_get_config(self.destination_hash())
        if not config:
            config = self.default_config
            if self.default_title:
                config["title"] = self.default_title
            users = self.default_users
            if self.default_user:
                users[self.default_user] = self.default_right
                del config["state_first_run"]
            self.core.db_shops_add(shop_id=self.destination_hash(), name="", name_announce="")
            self.core.db_shops_set_config(self.destination_hash(), config, time.time())
            self.core.db_shops_set_categorys(self.destination_hash(), default_categorys, time.time())
            self.core.db_shops_set_pages(self.destination_hash(), default_pages, time.time())
            self.core.db_shops_set_users(self.destination_hash(), users, time.time())

        config = self.core.db_shops_get_config(self.destination_hash())
        self.announce_data = config["title"]
        if config and (config["announce_startup"] or config["announce_periodic"]):
            self.announce(initial=True)

        self.register()


    def statistic_get(self):
        return self.statistic


    def statistic_set(self, statistic):
        self.statistic = statistic


    def statistic_reset(self):
        self.statistic = {"connects": 0, "sync_rx": 0, "sync_tx": 0}


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


    def announce(self, app_data=None, attached_interface=None, initial=False, reinit=False):
        config = self.core.db_shops_get_config(self.destination_hash())

        if config and config["announce_periodic"] and config["announce_interval"] > 0:
            announce_timer = threading.Timer(config["announce_interval"], self.announce)
            announce_timer.daemon = True
            announce_timer.start()

        if reinit:
            return

        if initial:
            if config and config["announce_startup"]:
                self.announce_now(app_data=app_data, attached_interface=attached_interface)
            return

        self.announce_now(app_data=app_data, attached_interface=attached_interface)


    def announce_now(self, app_data=None, attached_interface=None):
        config = self.core.db_shops_get_config(self.destination_hash())

        if config and not config["enabled"]:
            return

        if config and config["announce_hidden"]:
            self.destination.announce("".encode("utf-8"), attached_interface=attached_interface)
            RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +" (Hidden)", RNS.LOG_DEBUG)
        elif app_data != None:
            if isinstance(app_data, str):
                self.destination.announce(app_data.encode("utf-8"), attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +":" + app_data, RNS.LOG_DEBUG)
            else:
                self.destination.announce(app_data, attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()), RNS.LOG_DEBUG)
        elif config:
            self.announce_data = config["title"]
            self.destination.announce(config["title"].encode("utf-8"), attached_interface=attached_interface)
            RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +":" + config["title"], RNS.LOG_DEBUG)


    def register(self):
        RNS.log("Server - Register", RNS.LOG_DEBUG)
        self.destination.register_request_handler("sync_rx", response_generator=self.sync_rx, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("sync_tx", response_generator=self.sync_tx, allow=RNS.Destination.ALLOW_ALL)


    def peer_connected(self, link):
        RNS.log("Server - Peer connected to "+str(self.destination), RNS.LOG_VERBOSE)
        try:
            self.statistic["connects"] += 1
        except:
            pass
        link.set_link_closed_callback(self.peer_disconnected)
        link.set_remote_identified_callback(self.peer_identified)


    def peer_disconnected(self, link):
        RNS.log("Server - Peer disconnected from "+str(self.destination), RNS.LOG_VERBOSE)


    def peer_identified(self, link, identity):
        if identity:
            vendor_id = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, identity)
        else:
            link.teardown()


    def enabled(self):
        config = self.core.db_shops_get_config(self.destination_hash())

        if config and config["enabled"]:
            return True

        return False


    def right(self, dest, right):
        config = self.core.db_shops_get_config(self.destination_hash())
        users = self.core.db_shops_get_users(self.destination_hash())

        if users:
            if config and "state_first_run" in config:
                del config["state_first_run"]
                self.core.db_shops_set_config(self.destination_hash(), config, time.time())
                users[dest] = self.default_right
                self.core.db_shops_set_users(self.destination_hash(), users, time.time())
                return self.right(dest, right)

            if dest in users and users[dest] in right:
                return True
            elif "any" in users and users["any"] in right:
                return True

        return False


    def size_str(self, num, suffix='B'):
        units = ['','K','M','G','T','P','E','Z']
        last_unit = 'Y'

        if suffix == 'b':
            num *= 8
            units = ['','K','M','G','T','P','E','Z']
            last_unit = 'Y'

        for unit in units:
            if abs(num) < 1000.0:
                if unit == "":
                    return "%.0f %s%s" % (num, unit, suffix)
                else:
                    return "%.2f %s%s" % (num, unit, suffix)
            num /= 1000.0

        return "%.2f%s%s" % (num, last_unit, suffix)


    def log_request(self, request_id=None, path="", size_rx=0, size_tx=0, tag="Server - Request log"):
        RNS.log(tag + ":", RNS.LOG_DEBUG)
        if request_id:
            RNS.log("-      ID: " + RNS.prettyhexrep(request_id), RNS.LOG_DEBUG)
        else:
            RNS.log("-      ID: <local>", RNS.LOG_DEBUG)
        RNS.log("-    Path: " + str(path), RNS.LOG_DEBUG)
        RNS.log("- Size RX: " + self.size_str(size_rx), RNS.LOG_DEBUG)
        RNS.log("- Size TX: " + self.size_str(size_tx), RNS.LOG_DEBUG)


    #################################################
    # Entrys                                        #
    #################################################


    def entrys_compare_ts(self, entry, ts):
        if not entry:
            return None

        data = {}

        if "d" in ts and entry["ts_data"] > ts["d"]:
            data["category_id"] = entry["category_id"]
            data["type_id"] = entry["type_id"]
            data["enabled"] = entry["enabled"]
            data["option0"] = entry["option0"]
            data["option1"] = entry["option1"]
            data["option2"] = entry["option2"]
            data["option3"] = entry["option3"]
            data["option4"] = entry["option4"]
            data["option5"] = entry["option5"]
            data["option6"] = entry["option6"]
            data["option7"] = entry["option7"]
            data["tag0"] = entry["tag0"]
            data["tag1"] = entry["tag1"]
            data["tag2"] = entry["tag2"]
            data["tag3"] = entry["tag3"]
            data["tag4"] = entry["tag4"]
            data["tag5"] = entry["tag5"]
            data["tags0"] = entry["tags0"]
            data["tags1"] = entry["tags1"]
            data["price"] = entry["price"]
            data["currency"] = entry["currency"]
            data["variants"] = entry["variants"]
            data["q_available"] = entry["q_available"]
            data["q_min"] = entry["q_min"]
            data["q_max"] = entry["q_max"]
            data["weight"] = entry["weight"]
            data["rate"] = entry["rate"]
            data["location_lat"] = entry["location_lat"]
            data["location_lon"] = entry["location_lon"]
            data["ts_data"] = entry["ts_data"]

        if "t" in ts and entry["ts_text"] > ts["t"]:
            data["title0"] = entry["title0"]
            data["title1"] = entry["title1"]
            data["title2"] = entry["title2"]
            data["text0"] = entry["text0"]
            data["text1"] = entry["text1"]
            data["text2"] = entry["text2"]
            data["text3"] = entry["text3"]
            data["text4"] = entry["text4"]
            data["text5"] = entry["text5"]
            data["ts_text"] = entry["ts_text"]

        if "i" in ts and entry["ts_images"] > ts["i"]:
            data["images"] = entry["images"]
            data["ts_images"] = entry["ts_images"]

        if len(data) > 0:
            data["entry_id"] = entry["entry_id"]
            data["shop_id"] = entry["shop_id"]
            return data
        else:
            return None


    #################################################
    # Sync RX                                       #
    #################################################


    def sync_rx(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return None

        data_return = {}

        if remote_identity:
            vendor_id = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        else:
            data_return["result"] = ServerShop.RESULT_NO_IDENTITY
            return msgpack.packb(data_return)

        if self.right(vendor_id, [255]):
            data_return["result"] = ServerShop.RESULT_BLOCKED
            return msgpack.packb(data_return)

        if not self.enabled() and not self.right(vendor_id, [2]):
            data_return["result"] = ServerShop.RESULT_DISABLED
            if "ts_config" in data:
                if self.core.db_shops_get_config_ts(self.destination_hash()) > data["ts_config"]:
                    data_return["config"] = self.core.db_shops_get_config(self.destination_hash())
                    data_return["ts_config"] = self.core.db_shops_get_config_ts(self.destination_hash())
            return msgpack.packb(data_return)

        try:
            self.statistic["sync_rx"] += 1
        except:
            pass

        try:
            if "ts_config" in data:
                if self.core.db_shops_get_config_ts(self.destination_hash()) > data["ts_config"]:
                    data_return["config"] = self.core.db_shops_get_config(self.destination_hash())
                    data_return["ts_config"] = self.core.db_shops_get_config_ts(self.destination_hash())

            if "ts_categorys" in data:
                if self.core.db_shops_get_categorys_ts(self.destination_hash()) > data["ts_categorys"]:
                    data_return["categorys"] = self.core.db_shops_get_categorys(self.destination_hash())
                    data_return["ts_categorys"] = self.core.db_shops_get_categorys_ts(self.destination_hash())

            if "ts_categorys_count" in data:
                if self.core.db_shops_get_categorys_count_ts(self.destination_hash()) > data["ts_categorys_count"]:
                    data_return["categorys_count"] = self.core.db_shops_get_categorys_count(self.destination_hash())
                    data_return["ts_categorys_count"] = self.core.db_shops_get_categorys_count_ts(self.destination_hash())

            if "ts_pages" in data:
                if self.core.db_shops_get_pages_ts(self.destination_hash()) > data["ts_pages"]:
                    data_return["pages"] = self.core.db_shops_get_pages(self.destination_hash())
                    data_return["ts_pages"] = self.core.db_shops_get_pages_ts(self.destination_hash())

            if "ts_users" in data:
                if self.core.db_shops_get_users_ts(self.destination_hash()) > data["ts_users"]:
                    data_return["users"] = self.core.db_shops_get_users(self.destination_hash())
                    data_return["ts_users"] = self.core.db_shops_get_users_ts(self.destination_hash())

            if "entrys" in data:
                data_return["entrys"] = []
                data_return["entrys_count"] = self.core.db_shops_entrys_count(shop_id=self.destination_hash(), vendor_id=vendor_id, filter=data["filter"], search=data["search"])

                for entry in self.core.db_shops_entrys_list(shop_id=self.destination_hash(), vendor_id=vendor_id, filter=data["filter"], search=data["search"], order=data["order"], limit=data["limit"], limit_start=data["limit_start"], sync_images=data["sync_images"]):
                    if entry["entry_id"] in data["entrys"]:
                       entry_return = self.entrys_compare_ts(entry, data["entrys"][entry["entry_id"]])
                       del data["entrys"][entry["entry_id"]]
                       if entry_return:
                           data_return["entrys"].append(entry_return)
                    else:
                       data_return["entrys"].append(entry)

                for entry_id in data["entrys"]:
                    entry = self.core.db_shops_entrys_get(shop_id=self.destination_hash(), entry_id=entry_id)
                    if entry:
                        entry_return = self.entrys_compare_ts(entry, data["entrys"][entry_id])
                    else:
                        entry_return = {"entry_id": entry_id, "shop_id": self.destination_hash(), "ts": 0}
                    if entry_return:
                        data_return["entrys"].append(entry_return)

            data_return["result"] = ServerShop.RESULT_OK
        except Exception as e:
            RNS.log("Server - Sync TX: "+str(e), RNS.LOG_ERROR)
            data_return["result"] = ServerShop.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        self.log_request(request_id=request_id, path=path, size_rx=sys.getsizeof(data), size_tx=sys.getsizeof(data_return))

        return data_return


    #################################################
    # Sync TX                                       #
    #################################################


    def sync_tx(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return None

        data_return = {}

        if remote_identity:
            vendor_id = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        else:
            data_return["result"] = ServerShop.RESULT_NO_IDENTITY
            return msgpack.packb(data_return)

        if self.right(vendor_id, [255]):
            data_return["result"] = ServerShop.RESULT_BLOCKED
            return msgpack.packb(data_return)

        if not self.enabled() and not self.right(vendor_id, [2]):
            data_return["result"] = ServerShop.RESULT_DISABLED
            return msgpack.packb(data_return)

        if not self.right(vendor_id, [1, 2]):
            data_return["result"] = ServerShop.RESULT_NO_RIGHT
            return msgpack.packb(data_return)

        try:
            self.statistic["sync_tx"] += 1
        except:
            pass

        try:
            if "config" in data and "ts_config" in data and self.right(vendor_id, [2]):
                self.core.db_shops_set_config(self.destination_hash(), data["config"], data["ts_config"])
                self.announce(reinit=True)

            if "categorys" in data and "ts_categorys" in data and self.right(vendor_id, [2]):
                self.core.db_shops_set_categorys(self.destination_hash(), data["categorys"], data["ts_categorys"])

            if "pages" in data and "ts_pages" in data and self.right(vendor_id, [2]):
                self.core.db_shops_set_pages(self.destination_hash(), data["pages"], data["ts_pages"])

            if "users" in data and "ts_users" in data and self.right(vendor_id, [2]):
                self.core.db_shops_set_users(self.destination_hash(), data["users"], data["ts_users"])

            if "entrys" in data and self.right(vendor_id, [1, 2]):
                data_return["entrys_sync"] = []
                for entry in data["entrys"]:
                    if entry["shop_id"] != self.destination_hash():
                        continue
                    if self.core.db_shops_entrys_set(entry):
                        if entry["ts"] == 0:
                            data_return["entrys_sync"].append({"entry_id": entry["entry_id"], "shop_id": entry["shop_id"], "ts": entry["ts"]})
                        else:
                            data_return["entrys_sync"].append({"entry_id": entry["entry_id"], "shop_id": entry["shop_id"]})

                self.core.db_shops_update_categorys_count(self.destination_hash())

            data_return["result"] = ServerShop.RESULT_OK
        except Exception as e:
            RNS.log("Server - Sync RX: "+str(e), RNS.LOG_ERROR)
            data_return["result"] = ServerShop.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        self.log_request(request_id=request_id, path=path, size_rx=sys.getsizeof(data), size_tx=sys.getsizeof(data_return))

        return data_return


##############################################################################################################
# Core Class


class Core:
    def __init__(self, storage_path=None):
        self.storage_path = storage_path

        if self.storage_path:
            if not os.path.isdir(self.storage_path):
                os.makedirs(self.storage_path)
                RNS.log("Core - Storage path was created", RNS.LOG_DEBUG)
            RNS.log("Core - Storage path: " + self.storage_path, RNS.LOG_DEBUG)
        else:
            RNS.log("Core - No storage_path parameter", RNS.LOG_ERROR)
            return


        self.db = None
        self.db_path = self.storage_path + "/database.db"
        self.db_load()


    def __db_connect(self):
        if self.db == None:
            self.db = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)

        return self.db


    def __db_commit(self):
        if self.db != None:
            try:
                self.db.commit()
            except:
                pass


    def __db_init(self, init=True):
        RNS.log("Core - Initialize database...", RNS.LOG_DEBUG)
        db = self.__db_connect()
        dbc = db.cursor()

        if init:
            dbc.execute("DROP TABLE IF EXISTS shop")
        dbc.execute("CREATE TABLE IF NOT EXISTS shop (id BLOB PRIMARY KEY, config BLOB, categorys BLOB, categorys_count BLOB, pages BLOB, users BLOB, ts_config INTEGER DEFAULT 0, ts_categorys INTEGER DEFAULT 0, ts_categorys_count INTEGER DEFAULT 0, ts_pages INTEGER DEFAULT 0, ts_users INTEGER DEFAULT 0, ts_sync INTEGER DEFAULT 0, pin INTEGER DEFAULT 0, storage_duration INTEGER DEFAULT 0, archive INTEGER DEFAULT 0)")

        if init:
            dbc.execute("DROP TABLE IF EXISTS shop_entry")
        dbc.execute("CREATE TABLE IF NOT EXISTS shop_entry (entry_id BLOB, shop_id BLOB, vendor_id BLOB, category_id INTEGER DEFAULT 0, type_id INTEGER DEFAULT 0, enabled INTEGER DEFAULT 0, title0 TEXT DEFAULT '', title1 TEXT DEFAULT '', title2 TEXT DEFAULT '', text0 TEXT DEFAULT '', text1 TEXT DEFAULT '', text2 TEXT DEFAULT '', text3 TEXT DEFAULT '', text4 TEXT DEFAULT '', text5 TEXT DEFAULT '', option0 INTEGER DEFAULT 0, option1 INTEGER DEFAULT 0, option2 INTEGER DEFAULT 0, option3 INTEGER DEFAULT 0, option4 INTEGER DEFAULT 0, option5 INTEGER DEFAULT 0, option6 INTEGER DEFAULT 0, option7 INTEGER DEFAULT 0, tag0 INTEGER DEFAULT 0, tag1 INTEGER DEFAULT 0, tag2 INTEGER DEFAULT 0, tag3 INTEGER DEFAULT 0, tag4 INTEGER DEFAULT 0, tag5 INTEGER DEFAULT 0, tags0 TEXT DEFAULT '', tags1 TEXT DEFAULT '', images BLOB, price REAL DEFAULT 0, currency INTEGER DEFAULT 0, variants BLOB, q_available INTEGER DEFAULT 0, q_min INTEGER DEFAULT 0, q_max INTEGER DEFAULT 0, weight INTEGER DEFAULT 0, rate INTEGER DEFAULT 0, location_lat REAL DEFAULT 0, location_lon REAL DEFAULT 0, ts DEFAULT 0, ts_data INTEGER DEFAULT 0, ts_text INTEGER DEFAULT 0, ts_images INTEGER DEFAULT 0, ts_sync INTEGER DEFAULT 0, PRIMARY KEY(entry_id, shop_id))")

        self.__db_commit()


    def __db_migrate(self):
        RNS.log("Core - Migrating database...", RNS.LOG_DEBUG)
        self.__db_init(False)

        db = self.__db_connect()
        dbc = db.cursor()

        self.__db_commit()

        self.__db_init(False)


    def __db_migrate_exist(self, table, column=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if column:
            dbc.execute("SELECT 1 FROM PRAGMA_TABLE_INFO('"+table+"') WHERE name = '"+column+"'")
            if len(dbc.fetchall()) != 0:
                return True
        else:
            dbc.execute("SELECT 1 FROM PRAGMA_TABLE_INFO('"+table+"')")
            if len(dbc.fetchall()) != 0:
                return True

        return False


    def __db_migrate_table_delete(self, table):
        db = self.__db_connect()
        dbc = db.cursor()

        dbc.execute("DROP TABLE IF EXISTS "+table)

        self.__db_commit()


    def __db_migrate_column_delete(self, table, name):
        db = self.__db_connect()
        dbc = db.cursor()

        dbc.execute("SELECT 1 FROM PRAGMA_TABLE_INFO('"+table+"') WHERE name = '"+name+"'")
        if len(dbc.fetchall()) != 0:
            dbc.execute("ALTER TABLE "+table+" DROP COLUMN "+name)

        self.__db_commit()


    def __db_migrate_column_add(self, table, name, datatype, default=None, name_after=None):
        db = self.__db_connect()
        dbc = db.cursor()

        dbc.execute("SELECT 1 FROM PRAGMA_TABLE_INFO('"+table+"') WHERE name = '"+name+"'")
        if len(dbc.fetchall()) != 0:
            return

        if not name_after:
            dbc.execute("ALTER TABLE "+table+" ADD COLUMN "+name+" "+datatype+(f' DEFAULT {default}' if default is not None else ''))
        else:
            dbc.execute("SELECT 1 FROM PRAGMA_TABLE_INFO('"+table+"') WHERE name = '"+name_after+"'")
            if len(dbc.fetchall()) == 0:
                return

            dbc.execute(f"PRAGMA table_info({table})")
            columns_info_old = dbc.fetchall()

            primary_key = ""
            primary_keys = []
            for i, column in enumerate(columns_info_old):
                if column[5]:
                    primary_keys.append(column[1])
            if len(primary_keys) > 1:
                primary_key = ", PRIMARY KEY("+", ".join(primary_keys)+")"

            column_position = next(i for i, column in enumerate(columns_info_old) if column[1] == name_after) + 1
            columns_info_new = columns_info_old.copy()
            columns_info_new.insert(column_position, (column_position, name, datatype, 0, default, 0))

            dbc.execute(f"DROP TABLE IF EXISTS {table}_old")
            dbc.execute(f"ALTER TABLE {table} RENAME TO {table}_old")
            dbc.execute(f"CREATE TABLE {table} ({', '.join([(f'{col[1]} {col[2]}') + (f' DEFAULT {col[4]}' if col[4] is not None else '') + (' PRIMARY KEY' if col[5] and primary_key == '' else '') for col in columns_info_new])}"+primary_key+")")
            dbc.execute(f"INSERT INTO {table} ({', '.join([f'{col[1]}' for i, col in enumerate(columns_info_old)])}) SELECT {', '.join([f'{col[1]}' for i, col in enumerate(columns_info_old)])} FROM {table}_old")
            dbc.execute(f"DROP TABLE {table}_old")

        self.__db_commit()


    def __db_migrate_column_rename(self, table, name_old, name_new):
        db = self.__db_connect()
        dbc = db.cursor()

        dbc.execute("SELECT 1 FROM PRAGMA_TABLE_INFO('"+table+"') WHERE name = '"+name_old+"'")
        if len(dbc.fetchall()) != 0:
            dbc.execute("ALTER TABLE "+table+" RENAME '"+name_old+"' TO '"+name_new+"'")

        self.__db_commit()


    def __db_migrate_column_datatype(self, table, column, datatype, default=None):
        db = self.__db_connect()
        dbc = db.cursor()

        dbc.execute(f"PRAGMA table_info({table})")
        columns_info = dbc.fetchall()

        column_position = next(i for i, column_info in enumerate(columns_info) if column_info[1] == column)

        if datatype == columns_info[column_position][2]:
            return

        primary_key = ""
        primary_keys = []
        for i, column in enumerate(columns_info):
            if column[5]:
                primary_keys.append(column[1])
        if len(primary_keys) > 1:
            primary_key = ", PRIMARY KEY("+", ".join(primary_keys)+")"

        dbc.execute(f"DROP TABLE IF EXISTS {table}_old")
        dbc.execute(f"ALTER TABLE {table} RENAME TO {table}_old")
        dbc.execute(f"CREATE TABLE {table} ({', '.join([(f'{col[1]} {col[2]}' if col[1] != column else f'{col[1]} {datatype}') + ((f' DEFAULT {col[4]}' if col[4] is not None else '') if col[1] != column else (f' DEFAULT {default}' if default is not None else '')) + (' PRIMARY KEY' if col[5] and primary_key == '' else '') for col in columns_info])}"+primary_key+")")
        dbc.execute(f"INSERT INTO {table} SELECT {', '.join([f'{col[1]}' if i != column_position else f'CAST({col[1]} AS {datatype}) COLLATE NOCASE' for i, col in enumerate(columns_info)])} FROM {table}_old")
        dbc.execute(f"DROP TABLE {table}_old")

        self.__db_commit()


    def __db_indices(self):
        pass


    def db_load(self):
        RNS.log("Core - Loading database...", RNS.LOG_DEBUG)

        if not os.path.isfile(self.db_path):
            self.__db_init()
        else:
            self.__db_migrate()
            self.__db_indices()


    def db_shops_entrys_filter(self, filter):
        if filter == None:
            return ""

        querys = []

        if "category_id" in filter and filter["category_id"] != None:
            if isinstance(filter["category_id"], list):
                querys.append("category_id IN ("+",".join(str(x) for x in filter["category_id"])+")")
            else:
                querys.append("category_id = "+str(filter["category_id"]))

        if "type_id" in filter and filter["type_id"] != None and filter["type_id"] != 0:
            querys.append("type_id = "+str(filter["type_id"]))

        if "enabled" in filter:
            if filter["enabled"]:
                querys.append("enabled = 1")
            else:
                querys.append("enabled = 0")

        if "title0" in filter:
            querys.append("title0 LIKE '"+str(filter["title0"])+"'")

        if "title1" in filter:
            querys.append("title1 LIKE '"+str(filter["title1"])+"'")

        if "title2" in filter:
            querys.append("title2 LIKE '"+str(filter["title2"])+"'")

        if "text0" in filter:
            querys.append("text0 LIKE '"+str(filter["text0"])+"'")

        if "text1" in filter:
            querys.append("text1 LIKE '"+str(filter["text1"])+"'")

        if "text2" in filter:
            querys.append("text2 LIKE '"+str(filter["text2"])+"'")

        if "text3" in filter:
            querys.append("text3 LIKE '"+str(filter["text3"])+"'")

        if "text4" in filter:
            querys.append("text4 LIKE '"+str(filter["text4"])+"'")

        if "text5" in filter:
            querys.append("text5 LIKE '"+str(filter["text5"])+"'")

        if "option0" in filter:
            querys.append("option0 = "+str(filter["option0"]))

        if "option1" in filter:
            querys.append("option1 = "+str(filter["option1"]))

        if "option2" in filter:
            querys.append("option2 = "+str(filter["option2"]))

        if "option3" in filter:
            querys.append("option3 = "+str(filter["option3"]))

        if "option4" in filter:
            querys.append("option4 = "+str(filter["option4"]))

        if "option5" in filter:
            querys.append("option5 = "+str(filter["option5"]))

        if "option6" in filter:
            querys.append("option6 = "+str(filter["option6"]))

        if "option7" in filter:
            querys.append("option7 = "+str(filter["option7"]))

        if "tag0" in filter:
            querys.append("tag0 = 1")

        if "tag1" in filter:
            querys.append("tag1 = 1")

        if "tag2" in filter:
            querys.append("tag2 = 1")

        if "tag3" in filter:
            querys.append("tag3 = 1")

        if "tag4" in filter:
            querys.append("tag4 = 1")

        if "tag5" in filter:
            querys.append("tag5 = 1")

        if "price_min" in filter:
            querys.append("price >= "+str(filter["price_min"]))

        if "price_max" in filter:
            querys.append("price <= "+str(filter["price_max"]))

        if "ts_min" in filter:
            querys.append("ts >= "+str(filter["ts_min"]))

        if "ts_max" in filter:
            querys.append("ts <= "+str(filter["ts_max"]))

        if "currency" in filter:
            querys.append("currency = "+str(filter["currency"]))

        if len(querys) > 0:
            query = " AND "+" AND ".join(querys)
        else:
            query = ""

        return query


    def db_shops_entrys_order(self, order):
        if order == "A-ASC":
            query = " ORDER BY shop_entry.title0 ASC"
        elif order == "A-DESC":
            query = " ORDER BY shop_entry.title0 DESC"
        elif order == "P-ASC":
            query = " ORDER BY shop_entry.price ASC, shop_entry.title0 ASC"
        elif order == "P-DESC":
            query = " ORDER BY shop_entry.price DESC, shop_entry.title0 ASC"
        elif order == "R-ASC":
            query = " ORDER BY shop_entry.rate ASC, shop_entry.title0 ASC"
        elif order == "R-DESC":
            query = " ORDER BY shop_entry.rate DESC, shop_entry.title0 ASC"
        elif order == "S-ASC":
            query = " ORDER BY shop_entry.option2 ASC, shop_entry.title0 ASC"
        elif order == "S-DESC":
            query = " ORDER BY shop_entry.option2 DESC, shop_entry.title0 ASC"
        elif order == "ST-ASC":
            query = " ORDER BY shop_entry.option3 ASC, shop_entry.title0 ASC"
        elif order == "ST-DESC":
            query = " ORDER BY shop_entry.option3 DESC, shop_entry.title0 ASC"
        elif order == "ASC":
            query = " ORDER BY shop_entry.ts ASC, shop_entry.title0 ASC"
        elif order == "DESC":
            query = " ORDER BY shop_entry.ts DESC, shop_entry.title0 ASC"
        else:
            query = ""

        return query


    def db_shops_entrys_list(self, shop_id=None, vendor_id=None, filter=None, search=None, order=None, limit=None, limit_start=None, sync=False, sync_data=True, sync_text=True, sync_images=True):
        db = self.__db_connect()
        dbc = db.cursor()

        if sync:
            if shop_id:
                query = "SELECT * FROM shop_entry WHERE ts_sync = 0 AND shop_id = ?"
                dbc.execute(query, (shop_id,))
            else:
                query = "SELECT * FROM shop_entry WHERE ts_sync = 0"
                dbc.execute(query)
        else:
            query_filter = self.db_shops_entrys_filter(filter)

            query_order = self.db_shops_entrys_order(order)

            if limit == None or limit_start == None:
                query_limit = ""
            else:
                query_limit = " LIMIT "+str(limit)+" OFFSET "+str(limit_start)

            if search == None:
                query = "SELECT * FROM shop_entry WHERE ts > 0 AND shop_id = ? AND enabled = 1"+query_filter+query_order+query_limit
                dbc.execute(query, (shop_id,))
            else:
                search = "%"+search+"%"
                query = "SELECT * FROM shop_entry WHERE ts > 0 AND shop_id = ? AND enabled = 1 AND (title0 LIKE ? COLLATE NOCASE OR title1 LIKE ? COLLATE NOCASE OR title2 LIKE ? COLLATE NOCASE OR text0 LIKE ? COLLATE NOCASE OR text1 LIKE ? COLLATE NOCASE)"+query_filter+query_order+query_limit
                dbc.execute(query, (shop_id, search, search, search, search, search))

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                data_append = {}
                data_append["entry_id"] = entry[0]
                data_append["shop_id"] = entry[1]
                data_append["vendor_id"] = entry[2]
                if sync_data:
                    data_append["category_id"] = entry[3]
                    data_append["type_id"] = entry[4]
                    data_append["enabled"] = entry[5]
                if sync_text:
                    data_append["title0"] = entry[6]
                    data_append["title1"] = entry[7]
                    data_append["title2"] = entry[8]
                    data_append["text0"] = entry[9]
                    data_append["text1"] = entry[10]
                    data_append["text2"] = entry[11]
                    data_append["text3"] = entry[12]
                    data_append["text4"] = entry[13]
                    data_append["text5"] = entry[14]
                if sync_data:
                    data_append["option0"] = entry[15]
                    data_append["option1"] = entry[16]
                    data_append["option2"] = entry[17]
                    data_append["option3"] = entry[18]
                    data_append["option4"] = entry[19]
                    data_append["option5"] = entry[20]
                    data_append["option6"] = entry[21]
                    data_append["option7"] = entry[22]
                    data_append["tag0"] = entry[23]
                    data_append["tag1"] = entry[24]
                    data_append["tag2"] = entry[25]
                    data_append["tag3"] = entry[26]
                    data_append["tag4"] = entry[27]
                    data_append["tag5"] = entry[28]
                    data_append["tags0"] = entry[29]
                    data_append["tags1"] = entry[30]
                if sync_images:
                    data_append["images"] = msgpack.unpackb(entry[31])
                if sync_data:
                    data_append["price"] = entry[32]
                    data_append["currency"] = entry[33]
                    data_append["variants"] = msgpack.unpackb(entry[34])
                    data_append["q_available"] = entry[35]
                    data_append["q_min"] = entry[36]
                    data_append["q_max"] = entry[37]
                    data_append["weight"] = entry[38]
                    data_append["rate"] = entry[39]
                    data_append["location_lat"] = entry[40]
                    data_append["location_lon"] = entry[41]
                data_append["ts"] = entry[42]
                if sync_data:
                    data_append["ts_data"] = entry[43]
                if sync_text:
                    data_append["ts_text"] = entry[44]
                if sync_images:
                    data_append["ts_images"] = entry[45]
                data_append["ts_sync"] = entry[46]

                data.append(data_append)

            return data


    def db_shops_entrys_get(self, shop_id=None, entry_id=None, variant=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if variant == None:
            variant = 0

        query = "SELECT shop_entry.*, shop_cart.variant, shop_cart.quantity, IIF(shop_cart.variant IS NOT NULL, 1, 0), IIF(shop_favorite.shop_id IS NOT NULL, 1, 0), IIF(shop_notify.shop_id IS NOT NULL, 1, 0) FROM shop_entry LEFT JOIN shop_cart ON shop_cart.shop_id = shop_entry.shop_id AND shop_cart.entry_id = shop_entry.entry_id AND shop_cart.variant = ? LEFT JOIN shop_favorite ON shop_favorite.shop_id = shop_entry.shop_id AND shop_favorite.entry_id = shop_entry.entry_id LEFT JOIN shop_notify ON shop_notify.shop_id = shop_entry.shop_id AND shop_notify.entry_id = shop_entry.entry_id WHERE shop_entry.ts > 0 AND shop_entry.shop_id = ? AND shop_entry.entry_id = ?"
        dbc.execute(query, (variant, shop_id, entry_id))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            entry = result[0]
            data = {
                "entry_id": entry[0],
                "shop_id": entry[1],
                "vendor_id": entry[2],
                "category_id": entry[3],
                "type_id": entry[4],
                "enabled": entry[5],
                "title0": entry[6],
                "title1": entry[7],
                "title2": entry[8],
                "text0": entry[9],
                "text1": entry[10],
                "text2": entry[11],
                "text3": entry[12],
                "text4": entry[13],
                "text5": entry[14],
                "option0": entry[15],
                "option1": entry[16],
                "option2": entry[17],
                "option3": entry[18],
                "option4": entry[19],
                "option5": entry[20],
                "option6": entry[21],
                "option7": entry[22],
                "tag0": entry[23],
                "tag1": entry[24],
                "tag2": entry[25],
                "tag3": entry[26],
                "tag4": entry[27],
                "tag5": entry[28],
                "tags0": entry[29],
                "tags1": entry[30],
                "images": msgpack.unpackb(entry[31]),
                "price": entry[32],
                "currency": entry[33],
                "variants": msgpack.unpackb(entry[34]),
                "q_available": entry[35],
                "q_min": entry[36],
                "q_max": entry[37],
                "weight": entry[38],
                "rate": entry[39],
                "location_lat": entry[40],
                "location_lon": entry[41],
                "ts": entry[42],
                "ts_data": entry[43],
                "ts_text": entry[44],
                "ts_images": entry[45],
                "ts_sync": entry[46],

                "variant": entry[47],
                "quantity": entry[48],
                "cart": entry[49],
                "favorites": entry[50],
                "notify": entry[51]
            }

            return data


    def db_shops_entrys_set(self, entry=None):
        try:
            db = self.__db_connect()
            dbc = db.cursor()

            if "ts" in entry and entry["ts"] == 0:
                query = "DELETE FROM shop_entry WHERE entry_id = ? AND shop_id = ?"
                dbc.execute(query, (entry["entry_id"], entry["shop_id"]))

            else:
                query = "SELECT entry_id FROM shop_entry WHERE entry_id = ? AND shop_id = ?"
                dbc.execute(query, (entry["entry_id"], entry["shop_id"]))
                result = dbc.fetchall()
                if len(result) < 1:
                    query = "INSERT OR REPLACE INTO shop_entry (entry_id, shop_id, vendor_id, variants, images, ts) values (?, ?, ?, ?, ?, ?)"
                    dbc.execute(query, (entry["entry_id"], entry["shop_id"], entry["vendor_id"], msgpack.packb(None), msgpack.packb(None), entry["ts"]))

                if "ts_data" in entry:
                    query = "UPDATE shop_entry SET category_id = ?, type_id = ?, enabled = ?, option0 = ?, option1 = ?, option2 = ?, option3 = ?, option4 = ?, option5 = ?, option6 = ?, option7 = ?, tag0 = ?, tag1 = ?, tag2 = ?, tag3 = ?, tag4 = ?, tag5 = ?, tags0 = ?, tags1 = ?, price = ?, currency = ?, variants = ?, q_available = ?, q_min = ?, q_max = ?, weight = ?, rate = ?, location_lat = ?, location_lon = ?, ts_data = ? WHERE entry_id = ? AND shop_id = ? AND ts_data <= ?"
                    dbc.execute(query, (entry["category_id"], entry["type_id"], entry["enabled"], entry["option0"], entry["option1"], entry["option2"], entry["option3"], entry["option4"], entry["option5"], entry["option6"], entry["option7"], entry["tag0"], entry["tag1"], entry["tag2"], entry["tag3"], entry["tag4"], entry["tag5"], entry["tags0"], entry["tags1"], entry["price"], entry["currency"], msgpack.packb(entry["variants"]), entry["q_available"], entry["q_min"], entry["q_max"], entry["weight"], entry["rate"], entry["location_lat"], entry["location_lon"], entry["ts_data"], entry["entry_id"], entry["shop_id"], entry["ts_data"]))

                if "ts_text" in entry:
                    query = "UPDATE shop_entry SET title0 = ?, title1 = ?, title2 = ?, text0 = ?, text1 = ?, text2 = ?, text3 = ?, text4 = ?, text5 = ?, ts_text = ? WHERE entry_id = ? AND shop_id = ? AND ts_text <= ?"
                    dbc.execute(query, (entry["title0"], entry["title1"], entry["title2"], entry["text0"], entry["text1"], entry["text2"], entry["text3"], entry["text4"], entry["text5"], entry["ts_text"], entry["entry_id"], entry["shop_id"], entry["ts_text"]))

                if "ts_images" in entry:
                    query = "UPDATE shop_entry SET images = ?, ts_images = ? WHERE entry_id = ? AND shop_id = ? AND ts_images <= ?"
                    dbc.execute(query, (msgpack.packb(entry["images"]), entry["ts_images"], entry["entry_id"], entry["shop_id"], entry["ts_images"]))

                if "ts_sync" in entry:
                    query = "UPDATE shop_entry SET ts_sync = ? WHERE entry_id = ? AND shop_id = ?"
                    dbc.execute(query, (entry["ts_sync"], entry["entry_id"], entry["shop_id"]))

            self.__db_commit()

        except Exception as e:
            RNS.log("Core - Error while creating shop entry: "+str(e), RNS.LOG_ERROR)
            return False

        return True


    def db_shops_entrys_count(self, shop_id=None, vendor_id=None, filter=None, search=None, sync=False):
        db = self.__db_connect()
        dbc = db.cursor()

        if sync:
            if shop_id:
                query = "SELECT COUNT(*) FROM shop_entry WHERE ts_sync = 0 AND shop_id = ?"
                dbc.execute(query, (shop_id,))
            else:
                query = "SELECT COUNT(*) FROM shop_entry WHERE ts_sync = 0"
                dbc.execute(query)
        else:
            query_filter = self.db_shops_entrys_filter(filter)

            if search == None:
                query = "SELECT COUNT(*) FROM shop_entry WHERE ts > 0 AND shop_id = ? AND enabled = 1"+query_filter
                dbc.execute(query, (shop_id,))
            else:
                search = "%"+search+"%"
                query = "SELECT COUNT(*) FROM shop_entry WHERE ts > 0 AND shop_id = ? AND enabled = 1 AND (shop_entry.title0 LIKE ? COLLATE NOCASE OR shop_entry.title1 LIKE ? COLLATE NOCASE OR shop_entry.title2 LIKE ? COLLATE NOCASE OR shop_entry.text0 LIKE ? COLLATE NOCASE OR shop_entry.text1 LIKE ? COLLATE NOCASE)"+query_filter
                dbc.execute(query, (shop_id, search, search, search, search, search))

        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_shops_get_config(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT config FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            data = msgpack.unpackb(result[0][0])
            return data


    def db_shops_get_config_ts(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT ts_config FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_shops_set_config(self, shop_id, config, ts_config=None, ts_sync=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if ts_config == None:
            ts_config = 0

        if ts_sync == None:
            ts_sync = 0

        query = "UPDATE shop SET config = ?, ts_config = ?, ts_sync = ? WHERE id = ?"
        dbc.execute(query, (msgpack.packb(config), ts_config, ts_sync, shop_id))

        self.__db_commit()


    def db_shops_get_categorys(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT categorys FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            data = msgpack.unpackb(result[0][0])
            return data


    def db_shops_get_categorys_ts(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT ts_categorys FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_shops_set_categorys(self, shop_id, categorys, ts_categorys=None, ts_sync=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if ts_categorys == None:
            ts_categorys = 0

        if ts_sync == None:
            ts_sync = 0

        query = "UPDATE shop SET categorys = ?, ts_categorys = ?, ts_sync = ? WHERE id = ?"
        dbc.execute(query, (msgpack.packb(categorys), ts_categorys, ts_sync, shop_id))

        self.__db_commit()


    def db_shops_get_categorys_count(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT categorys_count FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return {}
        else:
            data = msgpack.unpackb(result[0][0])
            return data


    def db_shops_get_categorys_count_ts(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT ts_categorys_count FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_shops_set_categorys_count(self, shop_id, categorys_count, ts_categorys_count=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if ts_categorys_count == None:
            ts_categorys_count = 0

        query = "UPDATE shop SET categorys_count = ?, ts_categorys_count = ? WHERE id = ?"
        dbc.execute(query, (msgpack.packb(categorys_count), ts_categorys_count, shop_id))

        self.__db_commit()


    def db_shops_update_categorys_count(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT category_id, COUNT(category_id) FROM shop_entry WHERE ts > 0 AND shop_id = ? AND enabled = 1 GROUP BY category_id"
        dbc.execute(query, (shop_id,))

        result = dbc.fetchall()

        data = {}

        if len(result) > 0:
            for entry in result:
                data[entry[0]] = entry[1]

        query = "UPDATE shop SET categorys_count = ?, ts_categorys_count = ? WHERE id = ?"
        dbc.execute(query, (msgpack.packb(data), time.time(), shop_id))

        self.__db_commit()


    def db_shops_get_pages(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT pages FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            data = msgpack.unpackb(result[0][0])
            return data


    def db_shops_get_pages_ts(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT ts_pages FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_shops_set_pages(self, shop_id, pages, ts_pages=None, ts_sync=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if ts_pages == None:
            ts_pages = 0

        if ts_sync == None:
            ts_sync = 0

        query = "UPDATE shop SET pages = ?, ts_pages = ?, ts_sync = ? WHERE id = ?"
        dbc.execute(query, (msgpack.packb(pages), ts_pages, ts_sync, shop_id))

        self.__db_commit()


    def db_shops_get_users(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT users FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            data = msgpack.unpackb(result[0][0])
            return data


    def db_shops_get_users_ts(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT ts_users FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_shops_set_users(self, shop_id, users, ts_users=None, ts_sync=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if ts_users == None:
            ts_users = 0

        if ts_sync == None:
            ts_sync = 0

        query = "UPDATE shop SET users = ?, ts_users = ?, ts_sync = ? WHERE id = ?"
        dbc.execute(query, (msgpack.packb(users), ts_users, ts_sync, shop_id))

        self.__db_commit()


    def db_shops_add(self, shop_id, name=None, name_announce=None, trust=False, storage_duration=None, config=None, categorys=None, categorys_count=None, pages=None, users=None, ts_config=None, ts_categorys=None, ts_categorys_count=None, ts_pages=None, ts_users=None, ts_sync=None):
        try:
            if isinstance(shop_id, str):
                if len(shop_id) != RNS.Reticulum.TRUNCATED_HASHLENGTH//8*2:
                    return False
                shop_id = bytes.fromhex(shop_id)

            if name == None:
                name = ""

            if name_announce == None:
                name_announce = self.display_name_announce(shop_id)

            if storage_duration == None:
                storage_duration = 0

            if config == None:
                config = {}

            if categorys == None:
                categorys = {}

            if categorys_count == None:
                categorys_count = {}

            if pages == None:
                pages = {}

            if users == None:
                users = {}

            if ts_config == None:
                ts_config = 0

            if ts_categorys == None:
                ts_categorys = 0

            if ts_categorys_count == None:
                ts_categorys_count = 0

            if ts_pages == None:
                ts_pages = 0

            if ts_users == None:
                ts_users = 0

            if ts_sync == None:
                ts_sync = 0

            db = self.__db_connect()
            dbc = db.cursor()

            query = "INSERT INTO shop (id, config, categorys, categorys_count, pages, users, ts_config, ts_categorys, ts_categorys_count, ts_pages, ts_users, ts_sync, storage_duration) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            dbc.execute(query, (shop_id, msgpack.packb(config), msgpack.packb(categorys), msgpack.packb(categorys_count), msgpack.packb(pages), msgpack.packb(users), ts_config, ts_categorys, ts_categorys_count, ts_pages, ts_users, ts_sync, storage_duration))

            self.__db_commit()

        except Exception as e:
            RNS.log("Core - Error while creating shop: "+str(e), RNS.LOG_ERROR)
            return False

        return True


##############################################################################################################
# CMDs


def cmd(path=None):
    print("---- Database interface ----")
    print("")

    if path is not None:
        if path.endswith("/"):
            path = path[:-1]
    else:
        path = PATH

    path += "/database.db"

    print("File: "+path)
    print("")

    if not os.path.isfile(path):
        print("Error: No database file")
        return

    db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)

    while True:
        try:
            print("> ", end="")
            cmd = input()
            if cmd.lower() == "exit" or cmd.lower() == "quit":
                exit()

        except KeyboardInterrupt:
            exit()

        except EOFError:
            exit()

        if cmd.strip() == "":
            pass
        elif cmd.lower() == "clear":
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
                db.commit()
            except Exception as e:
                print("Error: "+str(e))


def cmd_status(path=None):
    print("---- Database status ----")
    print("")

    if path is not None:
        if path.endswith("/"):
            path = path[:-1]
    else:
        path = PATH

    path += "/database.db"

    print("File: "+path)

    if not os.path.isfile(path):
        print("Error: No database file")
        return

    print("Size: "+cmd_size_str(os.path.getsize(path)))

    db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
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
    global CORE
    global RNS_CONNECTION
    global RNS_SERVER_SHOP

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

    RNS_CONNECTION = RNS.Reticulum(configdir=PATH_RNS, loglevel=rns_loglevel)

    log("...............................................................................", LOG_INFO)
    log("        Name: " + NAME, LOG_INFO)
    log("Program File: " + __file__, LOG_INFO)
    log("     DB File: " + PATH + "/database.db", LOG_INFO)
    log("     Version: " + VERSION, LOG_INFO)
    log("   Copyright: " + COPYRIGHT, LOG_INFO)
    log("...............................................................................", LOG_INFO)

    log("RNS - Connecting ...", LOG_DEBUG)

    if path is None:
        path = PATH

    CORE = Core(storage_path=path)

    RNS_SERVER_SHOP = ServerShop(
        core=CORE,
        storage_path=path,
        identity_file="identity",
        identity=None,
        destination_name=DESTINATION_NAME,
        destination_type=DESTINATION_TYPE,
        destination_conv_name=DESTINATION_CONV_NAME,
        destination_conv_type=DESTINATION_CONV_TYPE,
        statistic=None,
        default_config=DEFAULT_CONFIG,
        default_title=DEFAULT_TITLE,
        default_categorys=DEFAULT_CATEGORYS,
        default_pages=DEFAULT_PAGES,
        default_users=DEFAULT_USERS,
        default_user=DEFAULT_USER,
        default_right=DEFAULT_RIGHT
        )

    log("RNS - Connected", LOG_DEBUG)

    log("...............................................................................", LOG_FORCE)
    log("RNS - Address: " + RNS.prettyhexrep(RNS_SERVER_SHOP.destination_hash()), LOG_FORCE)
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

        parser.add_argument("--cmd", action="store_true", default=False, help="")
        parser.add_argument("--cmd_status", action="store_true", default=False, help="")

        params = parser.parse_args()

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
# Init


if __name__ == "__main__":
    main()