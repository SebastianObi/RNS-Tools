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
import random

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
VERSION = "0.0.1 (2024-05-31)"
COPYRIGHT = "(c) 2024 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/"+os.path.splitext(os.path.basename(__file__))[0]
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
    "header_color": "",
    "header_enabled": True,
    "header_enabled_entrys": True,
    "template": 10,
    "template_config": "",
    "template_config_enabled": False,
    "announce_hidden": False,
    "announce_startup": True,
    "announce_periodic": True,
    "announce_interval": 1800,
    "maintenance_startup": True,
    "maintenance_periodic": True,
    "maintenance_interval": 86400,
    "telemetry_location_enabled": False,
    "telemetry_location_lat": 0,
    "telemetry_location_lon": 0,
    "telemetry_state_enabled": False,
    "telemetry_state_data": 0,
    "state_first_run": True,
    "limiter_server_enabled": False,
    "limiter_server_calls": 1000,
    "limiter_server_size": 0,
    "limiter_server_duration": 60,
    "limiter_peer_enabled": True,
    "limiter_peer_calls": 30,
    "limiter_peer_size": 0,
    "limiter_peer_duration": 60,
}
DEFAULT_TITLE = None
DEFAULT_CATEGORYS = {0: [0, "Test Category 1"], 1: [0, "Test Category 2"], 2: [4, "Test Subcategory 1"], 3: [4, "Test Subcategory 2"]}
DEFAULT_PAGES = {}
DEFAULT_USERS = {"any": 0}
DEFAULT_USER = None
DEFAULT_USER_INTERFACES = ["AutoInterface", "BZ1Interface", "KISSInterface", "RNodeInterface", "SerialInterface"]
DEFAULT_USER_HOPS = 1
DEFAULT_RIGHT = 2
DEFAULT_RIGHT_BLOCK = 255


#### Global Variables - System (Not changeable) ####
CORE = None
RNS_CONNECTION = None
RNS_SERVER_SHOP = None


##############################################################################################################
# RateLimiter Class


class RateLimiter:
    def __init__(self, calls, size, duration):
        self.calls = calls
        self.size = size
        self.duration = duration
        self.ts = time.time()
        self.data_calls = {}
        self.data_size = {}
        self.lock = threading.Lock()
        threading.Thread(target=self._jobs, daemon=True).start()


    def handle(self, id):
        if self.handle_call(id) and self.handle_size(id, 0):
            return True
        else:
            return False


    def handle_call(self, id):
        with self.lock:
            if self.calls == 0:
                return True
            if id not in self.data_calls:
                self.data_calls[id] = []
            self.data_calls[id] = [t for t in self.data_calls[id] if t > self.ts - self.duration]
            if len(self.data_calls[id]) >= self.calls:
                return False
            else:
                self.data_calls[id].append(self.ts)
                return True


    def handle_size(self, id, size):
        with self.lock:
            if self.size == 0:
                return True
            if id not in self.data_size:
                self.data_size[id] = [0, self.ts]
            if self.data_size[id][1] <= self.ts - self.duration:
                self.data_size[id] = [0, self.ts]
            if self.data_size[id][0] >= self.size:
                return False
            else:
                self.data_size[id][0] += size
                self.data_size[id][1] = self.ts
                return True


    def _jobs(self):
        while True:
            time.sleep(self.duration)
            self.ts = time.time()
            with self.lock:
                if self.calls > 0:
                    for id in list(self.data_calls.keys()):
                        self.data_calls[id] = [t for t in self.data_calls[id] if t > self.ts - self.duration]
                        if not self.data_calls[id]:
                            del self.data_calls[id]

                if self.size > 0:
                    for id in list(self.data_size.keys()):
                        if self.data_size[id][1] <= self.ts - self.duration:
                            del self.data_size[id]


##############################################################################################################
# ServerShop Class


class ServerShop:
    RESULT_ERROR       = 0x00
    RESULT_OK          = 0x01
    RESULT_SYNCRONIZE  = 0x02
    RESULT_NO_IDENTITY = 0x03
    RESULT_NO_USER     = 0x04
    RESULT_NO_RIGHT    = 0x05
    RESULT_NO_DATA     = 0x06
    RESULT_LIMIT_ALL   = 0x07
    RESULT_LIMIT_PEER  = 0x08
    RESULT_PARTIAL     = 0x09
    RESULT_DISABLED    = 0xFE
    RESULT_BLOCKED     = 0xFF


    def __init__(self, core, is_standalone=True, storage_path=None, identity_file="identity", identity=None, destination_name="nomadnetwork", destination_type="shop", destination_conv_name="lxmf", destination_conv_type="delivery", statistic=None, default_config=None, default_title=None, default_categorys=None, default_pages=None, default_users=None, default_user=None, default_user_interfaces=None, default_user_hops=None, default_user_callback=None, default_right=None, default_right_block=None):
        self.core = core
        self.is_standalone = is_standalone

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
        self.default_user_interfaces = default_user_interfaces
        self.default_user_hops = default_user_hops
        self.default_user_callback = default_user_callback
        self.default_right = default_right
        self.default_right_block = default_right_block

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
            now = time.time()
            self.core.db_shops_add(shop_id=self.destination_hash(), name="", name_announce="")
            self.core.db_shops_set_config(self.destination_hash(), config, now, now)
            self.core.db_shops_set_categorys(self.destination_hash(), default_categorys, now, now)
            self.core.db_shops_set_images(self.destination_hash(), {}, now, now)
            self.core.db_shops_set_pages(self.destination_hash(), default_pages, now, now)
            self.core.db_shops_set_users(self.destination_hash(), users, now, now)
            self.core.db_shops_set_statistic(self.destination_hash(), {}, now, now)
            self.core.db_shops_set_cmd(self.destination_hash(), {}, 0, now)

        config = self.core.db_shops_get_config(self.destination_hash())

        self.announce_data = config["title"]
        if config and (config["announce_startup"] or config["announce_periodic"]):
            self.announce(initial=True)

        if config and (config["maintenance_startup"] or config["maintenance_periodic"]):
            self.maintenance(initial=True)

        self.register()

        self.core.db_shops_update_categorys_count(self.destination_hash())

        if config and config["limiter_server_enabled"]:
            self.limiter_server = RateLimiter(config["limiter_server_calls"], config["limiter_server_size"], config["limiter_server_duration"])
        else:
            self.limiter_server = None

        if config and config["limiter_peer_enabled"]:
            self.limiter_peer = RateLimiter(config["limiter_peer_calls"], config["limiter_peer_size"], config["limiter_peer_duration"])
        else:
            self.limiter_peer = None


    def start(self):
        pass


    def stop(self):
        pass


    def statistic_get(self):
        return {
            "ts": self.statistic["ts"],
            "connects": self.statistic["connects"],
            "online": len(self.statistic["online"]),
            "rx_bytes": self.statistic["rx_bytes"],
            "tx_bytes": self.statistic["tx_bytes"],
            "rx_count": self.statistic["rx_count"],
            "tx_count": self.statistic["tx_count"],
            "entrys_add": self.statistic["entrys_add"],
            "entrys_edit": self.statistic["entrys_edit"],
            "entrys_del": self.statistic["entrys_del"]
        }


    def statistic_set(self, statistic):
        self.statistic = statistic


    def statistic_reset(self):
        self.statistic = {"ts": time.time(), "connects": 0, "online": {}, "rx_bytes": 0, "tx_bytes": 0, "rx_count": 0, "tx_count": 0, "entrys_add": 0, "entrys_edit": 0, "entrys_del": 0}


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
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +": " + app_data, RNS.LOG_DEBUG)
            else:
                self.destination.announce(app_data, attached_interface=attached_interface)
                RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()), RNS.LOG_DEBUG)
        elif config:
            self.announce_data = config["title"]
            fields = {}
            if config["telemetry_location_enabled"]:
                fields[self.core.MSG_FIELD_LOCATION] = [config["telemetry_location_lat"], config["telemetry_location_lon"]]
            if config["telemetry_state_enabled"]:
                fields[self.core.MSG_FIELD_STATE] = [config["telemetry_state_data"], int(time.time())]
            if len(fields) > 0:
                self.destination.announce(msgpack.packb({self.core.ANNOUNCE_DATA_CONTENT: config["title"].encode("utf-8"), self.core.ANNOUNCE_DATA_TITLE: None, self.core.ANNOUNCE_DATA_FIELDS: fields}), attached_interface=attached_interface)
            else:
                self.destination.announce(config["title"].encode("utf-8"), attached_interface=attached_interface)
            RNS.log("Server - Announced: " + RNS.prettyhexrep(self.destination_hash()) +": " + config["title"], RNS.LOG_DEBUG)


    def maintenance(self, initial=False, reinit=False):
        config = self.core.db_shops_get_config(self.destination_hash())

        if config and config["maintenance_periodic"] and config["maintenance_interval"] > 0:
            maintenance_timer = threading.Timer(config["maintenance_interval"], self.maintenance)
            maintenance_timer.daemon = True
            maintenance_timer.start()

        if reinit:
            return

        if initial:
            if config and config["maintenance_startup"]:
                self.maintenance_now()
            return

        self.maintenance_now()


    def maintenance_now(self):
        config = self.core.db_shops_get_config(self.destination_hash())

        if config and not config["enabled"]:
            return

        if self.is_standalone:
            RNS.log("Server - Maintenance", RNS.LOG_DEBUG)
            self.core.db_vacuum()


    def register(self):
        RNS.log("Server - Register", RNS.LOG_DEBUG)
        self.destination.register_request_handler("sync_rx", response_generator=self.sync_rx, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("sync_tx", response_generator=self.sync_tx, allow=RNS.Destination.ALLOW_ALL)


    def peer_connected(self, link):
        RNS.log("Server - Peer connected to "+str(self.destination), RNS.LOG_VERBOSE)
        try:
            self.statistic["connects"] += 1
            self.statistic["online"][link.hash] = True
        except:
            pass
        link.set_link_closed_callback(self.peer_disconnected)
        link.set_remote_identified_callback(self.peer_identified)


    def peer_disconnected(self, link):
        RNS.log("Server - Peer disconnected from "+str(self.destination), RNS.LOG_VERBOSE)
        try:
            self.statistic["rx_bytes"] += link.rxbytes
            self.statistic["tx_bytes"] += link.txbytes
            if link.hash in self.statistic["online"]:
                del self.statistic["online"][link.hash]
        except:
            pass


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
                hop_interface = sef.core.reticulum.get_next_hop_if_name(dest)
                if self.default_user_interfaces == None or len(self.default_user_interfaces) == 0 or any(hop_interface.startswith(prefix) for prefix in self.default_user_interfaces):
                    hop_count = RNS.Transport.hops_to(dest)
                    #hop_interface_self = str(RNS.Transport.next_hop_interface(dest))
                    #if hop_interface_self and hop_interface_self.startswith("LocalInterface"):
                    #    hop_count -= 1
                    if self.default_user_hops == None or self.default_user_hops == 0 or hop_count <= self.default_user_hops:
                        RNS.log("Server - Create new user "+RNS.prettyhexrep(dest)+" connected via "+hop_interface+" with "+str(hop_count)+" hops", RNS.LOG_DEBUG)
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

        if "v" in ts:
            data["vendor_id"] = entry["vendor_id"]
            data["ts"] = entry["ts"]

        if "d" in ts and entry["ts_data"] > ts["d"]:
            data["category0"] = entry["category0"]
            data["category1"] = entry["category1"]
            data["enabled"] = entry["enabled"]
            data["num0"] = entry["num0"]
            data["num1"] = entry["num1"]
            data["num2"] = entry["num2"]
            data["num3"] = entry["num3"]
            data["num4"] = entry["num4"]
            data["num5"] = entry["num5"]
            data["option0"] = entry["option0"]
            data["option1"] = entry["option1"]
            data["option2"] = entry["option2"]
            data["option3"] = entry["option3"]
            data["option4"] = entry["option4"]
            data["option5"] = entry["option5"]
            data["option6"] = entry["option6"]
            data["option7"] = entry["option7"]
            data["tags0"] = entry["tags0"]
            data["tags1"] = entry["tags1"]
            data["tags2"] = entry["tags2"]
            data["tags3"] = entry["tags3"]
            data["tags4"] = entry["tags4"]
            data["tags5"] = entry["tags5"]
            data["tags6"] = entry["tags6"]
            data["tags7"] = entry["tags7"]
            data["files"] = entry["files"]
            data["price"] = entry["price"]
            data["currency"] = entry["currency"]
            data["variants"] = entry["variants"]
            data["q_available"] = entry["q_available"]
            data["q_min"] = entry["q_min"]
            data["q_max"] = entry["q_max"]
            data["rate"] = entry["rate"]
            data["location_lat"] = entry["location_lat"]
            data["location_lon"] = entry["location_lon"]
            data["ts_data"] = entry["ts_data"]

        if "t" in ts and entry["ts_title"] > ts["t"]:
            data["title0"] = entry["title0"]
            data["title1"] = entry["title1"]
            data["title2"] = entry["title2"]
            data["ts_title"] = entry["ts_title"]

        if "te" in ts and entry["ts_text"] > ts["te"]:
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
            return data
        else:
            return None


    #################################################
    # CMD                                           #
    #################################################


    def cmd(self, cmd, value, vendor_id=None):
        try:
            if cmd == "announce":
                self.announce()
            elif cmd == "maintenance":
                self.maintenance()
            elif cmd == "entry_disabled":
                self.core.db_shops_entrys_set_enabled(shop_id=self.destination_hash(), entry_id=value, value=False)
                self.core.db_shops_update_categorys_count(self.destination_hash())
            elif cmd == "entrys_disabled":
                self.core.db_shops_entrys_set_enabled(shop_id=self.destination_hash(), vendor_id=value, value=False)
                self.core.db_shops_update_categorys_count(self.destination_hash())
            elif cmd == "entry_delete":
                self.core.db_shops_entrys_delete(shop_id=self.destination_hash(), entry_id=value)
                self.core.db_shops_update_categorys_count(self.destination_hash())
            elif cmd == "entrys_delete":
                self.core.db_shops_entrys_delete(shop_id=self.destination_hash(), vendor_id=value)
                self.core.db_shops_update_categorys_count(self.destination_hash())
            elif cmd == "entry_ownership":
                self.core.db_shops_entrys_set_vendor_id(shop_id=self.destination_hash(), entry_id=value, vendor_id_new=vendor_id)
                self.core.db_shops_update_categorys_count(self.destination_hash())
            elif cmd == "entrys_ownership":
                self.core.db_shops_entrys_set_vendor_id(shop_id=self.destination_hash(), vendor_id_old=value, vendor_id_new=vendor_id)
                self.core.db_shops_update_categorys_count(self.destination_hash())
            elif cmd == "user":
                users = self.core.db_shops_get_users(self.destination_hash())
                if users:
                    users[value["user"]] = value["right"]
                    self.core.db_shops_set_users(self.destination_hash(), users, time.time())
            elif cmd == "user_block":
                users = self.core.db_shops_get_users(self.destination_hash())
                if users and self.default_right_block != None:
                    users[value] = self.default_right_block
                    self.core.db_shops_set_users(self.destination_hash(), users, time.time())
            elif cmd == "user_delete":
                users = self.core.db_shops_get_users(self.destination_hash())
                if users and value in users:
                    del users[value]
                    self.core.db_shops_set_users(self.destination_hash(), users, time.time())
            return True
        except Exception as e:
            RNS.log("Server - CMD: "+str(e), RNS.LOG_ERROR)
            return False


    #################################################
    # Sync RX                                       #
    #################################################


    def sync_rx(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            return msgpack.packb({"result": ServerShop.RESULT_NO_IDENTITY})

        if self.limiter_server and not self.limiter_server.handle("server"):
            return msgpack.packb({"result": ServerShop.RESULT_LIMIT_SERVER})

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return msgpack.packb({"result": ServerShop.RESULT_LIMIT_PEER})

        if not data:
            return msgpack.packb({"result": ServerShop.RESULT_NO_DATA})

        now = time.time()

        data_return = {}

        vendor_id = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)

        if not self.right(vendor_id, [0, 1, 2, 255]):
            data_return["result"] = ServerShop.RESULT_NO_USER
            return msgpack.packb(data_return)

        if self.right(vendor_id, [255]) and not self.right(vendor_id, [0, 1, 2]):
            data_return["result"] = ServerShop.RESULT_BLOCKED
            return msgpack.packb(data_return)

        if not self.enabled() and not self.right(vendor_id, [2]):
            data_return["result"] = ServerShop.RESULT_DISABLED
            if "ts_config" in data:
                if self.core.db_shops_get_config_ts(self.destination_hash()) > data["ts_config"]:
                    data_return["rx_config"] = self.core.db_shops_get_config(self.destination_hash())
                    data_return["rx_ts_config"] = self.core.db_shops_get_config_ts(self.destination_hash())
            return msgpack.packb(data_return)

        try:
            self.statistic["rx_count"] += 1
        except:
            pass

        try:
            if "type" in data:
                data_return["type"] = data["type"]

            if "ts_config" in data:
                if self.core.db_shops_get_config_ts(self.destination_hash()) > data["ts_config"]:
                    data_return["rx_config"] = self.core.db_shops_get_config(self.destination_hash())
                    data_return["rx_ts_config"] = self.core.db_shops_get_config_ts(self.destination_hash())

            if "ts_categorys" in data:
                if self.core.db_shops_get_categorys_ts(self.destination_hash()) > data["ts_categorys"]:
                    data_return["rx_categorys"] = self.core.db_shops_get_categorys(self.destination_hash())
                    data_return["rx_ts_categorys"] = self.core.db_shops_get_categorys_ts(self.destination_hash())

            if "ts_categorys_count" in data:
                if self.core.db_shops_get_categorys_count_ts(self.destination_hash()) > data["ts_categorys_count"]:
                    data_return["rx_categorys_count"] = self.core.db_shops_get_categorys_count(self.destination_hash())
                    data_return["rx_ts_categorys_count"] = self.core.db_shops_get_categorys_count_ts(self.destination_hash())

            if "ts_images" in data:
                if self.core.db_shops_get_images_ts(self.destination_hash()) > data["ts_images"]:
                    data_return["rx_images"] = self.core.db_shops_get_images(self.destination_hash())
                    data_return["rx_ts_images"] = self.core.db_shops_get_images_ts(self.destination_hash())

            if "ts_pages" in data:
                if self.core.db_shops_get_pages_ts(self.destination_hash()) > data["ts_pages"]:
                    data_return["rx_pages"] = self.core.db_shops_get_pages(self.destination_hash())
                    data_return["rx_ts_pages"] = self.core.db_shops_get_pages_ts(self.destination_hash())

            if "ts_users" in data:
                if self.core.db_shops_get_users_ts(self.destination_hash()) > data["ts_users"]:
                    data_return["rx_users"] = self.core.db_shops_get_users(self.destination_hash())
                    data_return["rx_ts_users"] = self.core.db_shops_get_users_ts(self.destination_hash())

            if "ts_statistic" in data:
                data_return["rx_statistic"] = {
                    "server": self.statistic_get(),
                    "db": self.core.db_shops_statistic(self.destination_hash())
                }
                data_return["rx_ts_statistic"] = time.time()

            if "filter_count" in data:
                data_return["rx_filter_count"] = self.core.db_shops_entrys_count(shop_id=self.destination_hash(), filter=data["filter_count"])

            if "entry" in data:
                    entry_id = list(data["entry"].keys())[0]
                    entry = self.core.db_shops_entrys_get(shop_id=self.destination_hash(), entry_id=entry_id)
                    if entry:
                        entry_return = self.entrys_compare_ts(entry, data["entry"][entry_id])
                    else:
                        entry_return = {"entry_id": entry_id, "shop_id": self.destination_hash(), "ts": 0}
                    if entry_return:
                        data_return["rx_entry"] = entry_return

            if "entrys" in data:
                data_return["rx_entrys"] = []
                data_return["rx_entrys_count"] = self.core.db_shops_entrys_count(shop_id=self.destination_hash(), vendor_id=vendor_id, filter=data["filter"], search=data["search"])

                for entry in self.core.db_shops_entrys_list(shop_id=self.destination_hash(), vendor_id=vendor_id, filter=data["filter"], search=data["search"], order=data["order"], limit=data["limit"], limit_start=data["limit_start"], sync_text=data["sync_text"], sync_images=data["sync_images"]):
                    if entry["entry_id"] in data["entrys"]:
                       entry_return = self.entrys_compare_ts(entry, data["entrys"][entry["entry_id"]])
                       del data["entrys"][entry["entry_id"]]
                       if entry_return:
                           data_return["rx_entrys"].append(entry_return)
                    else:
                       data_return["rx_entrys"].append(entry)

                for entry_id in data["entrys"]:
                    entry = self.core.db_shops_entrys_get(shop_id=self.destination_hash(), entry_id=entry_id)
                    if entry:
                        entry_return = self.entrys_compare_ts(entry, data["entrys"][entry_id])
                    else:
                        entry_return = {"entry_id": entry_id, "shop_id": self.destination_hash(), "ts": 0}
                    if entry_return:
                        data_return["rx_entrys"].append(entry_return)

                if len(data_return["rx_entrys"]) == 0:
                    del data_return["rx_entrys"]

            if "file" in data:
                file = self.core.db_shops_entrys_get_file(shop_id=self.destination_hash(), entry_id=data["file"]["entry_id"], file=data["file"]["file"])
                if file:
                    if "name" in data["file"] and data["file"]["name"]:
                        file["name"] = data["file"]["name"]
                    data_return["rx_file"] = file

            data_return["result"] = ServerShop.RESULT_OK
        except Exception as e:
            RNS.log("Server - Sync RX: "+str(e), RNS.LOG_ERROR)
            data_return["result"] = ServerShop.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        self.log_request(request_id=request_id, path=path, size_rx=sys.getsizeof(data), size_tx=sys.getsizeof(data_return))

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(data_return))

        if self.limiter_peer:
             self.limiter_peer.handle_size(str(remote_identity), len(data_return))

        return data_return


    #################################################
    # Sync TX                                       #
    #################################################


    def sync_tx(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            return msgpack.packb({"result": ServerShop.RESULT_NO_IDENTITY})

        if self.limiter_server and not self.limiter_server.handle("server"):
            return msgpack.packb({"result": ServerShop.RESULT_LIMIT_SERVER})

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return msgpack.packb({"result": ServerShop.RESULT_LIMIT_PEER})

        if not data:
            return msgpack.packb({"result": ServerShop.RESULT_NO_DATA})

        now = time.time()

        data_return = {}

        vendor_id = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)

        if not self.right(vendor_id, [0, 1, 2, 255]):
            data_return["result"] = ServerShop.RESULT_NO_USER
            return msgpack.packb(data_return)

        if self.right(vendor_id, [255]) and not self.right(vendor_id, [1, 2]):
            data_return["result"] = ServerShop.RESULT_BLOCKED
            return msgpack.packb(data_return)

        if not self.enabled() and not self.right(vendor_id, [2]):
            data_return["result"] = ServerShop.RESULT_DISABLED
            return msgpack.packb(data_return)

        if not self.right(vendor_id, [1, 2]):
            data_return["result"] = ServerShop.RESULT_NO_RIGHT
            return msgpack.packb(data_return)

        try:
            self.statistic["tx_count"] += 1
        except:
            pass

        try:
            if "type" in data:
                data_return["type"] = data["type"]

            if "config" in data and "ts_config" in data and self.right(vendor_id, [2]):
                self.core.db_shops_set_config(self.destination_hash(), data["config"], data["ts_config"])
                self.announce(reinit=True)
                self.maintenance(reinit=True)
                data_return["tx_shop"] = True

            if "categorys" in data and "ts_categorys" in data and self.right(vendor_id, [2]):
                self.core.db_shops_set_categorys(self.destination_hash(), data["categorys"], data["ts_categorys"])
                data_return["tx_shop"] = True

            if "images" in data and "ts_images" in data and self.right(vendor_id, [2]):
                self.core.db_shops_set_images(self.destination_hash(), data["images"], data["ts_images"])
                data_return["tx_shop"] = True

            if "pages" in data and "ts_pages" in data and self.right(vendor_id, [2]):
                self.core.db_shops_set_pages(self.destination_hash(), data["pages"], data["ts_pages"])
                data_return["tx_shop"] = True

            if "users" in data and "ts_users" in data and self.right(vendor_id, [2]):
                self.core.db_shops_set_users(self.destination_hash(), data["users"], data["ts_users"])
                data_return["tx_shop"] = True

            if "entrys" in data and self.right(vendor_id, [1, 2]):
                data_return["tx_entrys"] = []
                for entry in data["entrys"]:
                    entry["shop_id"] = self.destination_hash()
                    entry["vendor_id"] = vendor_id
                    entry["ts_sync"] = now
                    result, result_files = self.core.db_shops_entrys_set(entry, sync=True)
                    if result != 0x00:
                        if entry["ts"] == 0:
                            if len(result_files) > 0:
                                data_return["tx_entrys"].append({"entry_id": entry["entry_id"], "ts": entry["ts"], "result_files": result_files})
                            else:
                                data_return["tx_entrys"].append({"entry_id": entry["entry_id"], "ts": entry["ts"]})
                        else:
                            if len(result_files) > 0:
                                data_return["tx_entrys"].append({"entry_id": entry["entry_id"], "result_files": result_files})
                            else:
                                data_return["tx_entrys"].append({"entry_id": entry["entry_id"]})
                    if result == 0x01:
                        self.statistic["entrys_add"] += 1
                    elif result == 0x02:
                        self.statistic["entrys_edit"] += 1
                    elif result == 0x03:
                        self.statistic["entrys_del"] += 1
                if len(data_return["tx_entrys"]) == 0:
                    del data_return["tx_entrys"]
                self.core.db_shops_update_categorys_count(self.destination_hash())

            if "entrys_ts" in data and self.right(vendor_id, [1, 2]):
                data_return["tx_entrys_ts"] = {}
                for entry_id in data["entrys_ts"]:
                    entry = self.core.db_shops_entrys_get(shop_id=self.destination_hash(), entry_id=entry_id)
                    if entry:
                        data_return["tx_entrys_ts"][entry_id] = []
                        if "ts" in data["entrys_ts"][entry_id] and data["entrys_ts"][entry_id]["ts"] == 0:
                            data_return["tx_entrys_ts"][entry_id].append("ts")
                        if "d" in data["entrys_ts"][entry_id] and data["entrys_ts"][entry_id]["d"] > entry["ts_data"]:
                            data_return["tx_entrys_ts"][entry_id].append("d")
                        if "t" in data["entrys_ts"][entry_id] and data["entrys_ts"][entry_id]["t"] > entry["ts_title"]:
                            data_return["tx_entrys_ts"][entry_id].append("t")
                        if "te" in data["entrys_ts"][entry_id] and data["entrys_ts"][entry_id]["te"] > entry["ts_text"]:
                            data_return["tx_entrys_ts"][entry_id].append("te")
                        if "i" in data["entrys_ts"][entry_id] and data["entrys_ts"][entry_id]["i"] > entry["ts_images"]:
                            data_return["tx_entrys_ts"][entry_id].append("i")
                        if "f" in data["entrys_ts"][entry_id] and data["entrys_ts"][entry_id]["f"] > entry["ts_files"]:
                            data_return["tx_entrys_ts"][entry_id].append("f")
                        if len(data_return["tx_entrys_ts"][entry_id]) == 0:
                            del data_return["tx_entrys_ts"][entry_id]
                    else:
                        data_return["tx_entrys_ts"][entry_id] = ["d", "t", "te", "i", "f"]

                if len(data_return["tx_entrys_ts"]) == 0:
                    del data_return["tx_entrys_ts"]

            if "cmd" in data and self.right(vendor_id, [2]):
                data_return["cmd"] = []
                for key, value in data["cmd"].items():
                    if self.cmd(cmd=value["cmd"], value=value["value"], vendor_id=vendor_id):
                        data_return["cmd"].append(key)
                if len(data_return["cmd"]) == 0:
                    del data_return["cmd"]

            data_return["result"] = ServerShop.RESULT_OK
        except Exception as e:
            RNS.log("Server - Sync TX: "+str(e), RNS.LOG_ERROR)
            data_return["result"] = ServerShop.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        self.log_request(request_id=request_id, path=path, size_rx=sys.getsizeof(data), size_tx=sys.getsizeof(data_return))

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(data_return))

        if self.limiter_peer:
             self.limiter_peer.handle_size(str(remote_identity), len(data_return))

        return data_return


##############################################################################################################
# Core Class


class Core:
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

        self.reticulum = None


    def __db_connect(self):
        if self.db == None:
            self.db = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)

        return self.db


    def db_connect(self):
        return self.__db_connect()


    def __db_commit(self):
        if self.db != None:
            try:
                self.db.commit()
            except:
                pass


    def db_commit(self):
        self.__db_commit()


    def db_lock(self, value=True):
        if value:
            db = self.__db_connect()
            dbc = db.cursor()
            dbc.execute("BEGIN EXCLUSIVE")
        else:
            self.__db_commit()


    def __db_sanitize(self, value):
        value = str(value)
        value = value.replace('\\', "")
        value = value.replace("\0", "")
        value = value.replace("\n", "")
        value = value.replace("\r", "")
        value = value.replace("'", "")
        value = value.replace('"', "")
        value = value.replace("\x1a", "")
        return value


    def __db_init(self, init=True):
        RNS.log("Core - Initialize database...", RNS.LOG_DEBUG)
        db = self.__db_connect()
        dbc = db.cursor()

        if init:
            dbc.execute("DROP TABLE IF EXISTS shop")
        dbc.execute("CREATE TABLE IF NOT EXISTS shop (id BLOB PRIMARY KEY, config BLOB, categorys BLOB, categorys_count BLOB, images BLOB, pages BLOB, users BLOB, statistic BLOB, cmd BLOB, ts_config INTEGER DEFAULT 0, ts_categorys INTEGER DEFAULT 0, ts_categorys_count INTEGER DEFAULT 0, ts_images INTEGER DEFAULT 0, ts_pages INTEGER DEFAULT 0, ts_users INTEGER DEFAULT 0, ts_statistic INTEGER DEFAULT 0, ts_cmd INTEGER DEFAULT 0, ts_sync INTEGER DEFAULT 0, pin INTEGER DEFAULT 0, storage_duration INTEGER DEFAULT 0, archive INTEGER DEFAULT 0)")

        if init:
            dbc.execute("DROP TABLE IF EXISTS shop_cart")
        dbc.execute("CREATE TABLE IF NOT EXISTS shop_cart (shop_id BLOB, entry_id BLOB, variant INTEGER DEFAULT 0, quantity INTEGER DEFAULT 0, PRIMARY KEY(shop_id, entry_id, variant))")

        if init:
            dbc.execute("DROP TABLE IF EXISTS shop_entry")
        dbc.execute("CREATE TABLE IF NOT EXISTS shop_entry (entry_id BLOB, shop_id BLOB, vendor_id BLOB, category0 INTEGER DEFAULT 0, category1 INTEGER DEFAULT 0, enabled INTEGER DEFAULT 0, title0 TEXT DEFAULT '', title1 TEXT DEFAULT '', title2 TEXT DEFAULT '', text0 TEXT DEFAULT '', text1 TEXT DEFAULT '', text2 TEXT DEFAULT '', text3 TEXT DEFAULT '', text4 TEXT DEFAULT '', text5 TEXT DEFAULT '', num0 INTEGER DEFAULT 0, num1 INTEGER DEFAULT 0, num2 INTEGER DEFAULT 0, num3 INTEGER DEFAULT 0, num4 INTEGER DEFAULT 0, num5 INTEGER DEFAULT 0, option0 INTEGER DEFAULT 0, option1 INTEGER DEFAULT 0, option2 INTEGER DEFAULT 0, option3 INTEGER DEFAULT 0, option4 INTEGER DEFAULT 0, option5 INTEGER DEFAULT 0, option6 INTEGER DEFAULT 0, option7 INTEGER DEFAULT 0, tags0 TEXT DEFAULT '', tags1 TEXT DEFAULT '', tags2 TEXT DEFAULT '', tags3 TEXT DEFAULT '', tags4 TEXT DEFAULT '', tags5 TEXT DEFAULT '', tags6 TEXT DEFAULT '', tags7 TEXT DEFAULT '', images BLOB, files BLOB, files_data BLOB, price REAL DEFAULT 0, currency INTEGER DEFAULT 0, variants BLOB, q_available INTEGER DEFAULT 0, q_min INTEGER DEFAULT 0, q_max INTEGER DEFAULT 0, rate INTEGER DEFAULT 0, location_lat REAL DEFAULT 0, location_lon REAL DEFAULT 0, ts INTEGER DEFAULT 0, ts_data INTEGER DEFAULT 0, ts_title INTEGER DEFAULT 0, ts_text INTEGER DEFAULT 0, ts_images INTEGER DEFAULT 0, ts_files INTEGER DEFAULT 0, ts_sync INTEGER DEFAULT 0, PRIMARY KEY(entry_id, shop_id))")

        if init:
            dbc.execute("DROP TABLE IF EXISTS shop_favorite")
        dbc.execute("CREATE TABLE IF NOT EXISTS shop_favorite (shop_id BLOB, entry_id BLOB, PRIMARY KEY(shop_id, entry_id))")

        if init:
            dbc.execute("DROP TABLE IF EXISTS shop_notify")
        dbc.execute("CREATE TABLE IF NOT EXISTS shop_notify (shop_id BLOB, entry_id BLOB, PRIMARY KEY(shop_id, entry_id))")

        if init:
            dbc.execute("DROP TABLE IF EXISTS shop_order")
        dbc.execute("CREATE TABLE IF NOT EXISTS shop_order (order_id BLOB, shop_id BLOB, entry_id BLOB, vendor_id BLOB, variant INTEGER DEFAULT 0, variant_str TEXT DEFAULT '', quantity INTEGER DEFAULT 0, title0 TEXT DEFAULT '', title1 TEXT DEFAULT '', price REAL DEFAULT 0, currency INTEGER DEFAULT 0, type INTEGER DEFAULT 0, state INTEGER DEFAULT 0, ts INTEGER DEFAULT 0, PRIMARY KEY(order_id, shop_id, entry_id, variant))")

        if init:
            dbc.execute("DROP TABLE IF EXISTS shop_state")
        dbc.execute("CREATE TABLE IF NOT EXISTS shop_state (state_id BLOB PRIMARY KEY, shop_id BLOB, type INTEGER DEFAULT 0, state INTEGER DEFAULT 0, ts INTEGER DEFAULT 0, size_rx INTEGER DEFAULT 0, size_tx INTEGER DEFAULT 0, duration FLOAT DEFAULT 0, count INTEGER DEFAULT 0)")

        self.__db_commit()


    def __db_migrate(self):
        RNS.log("Core - Migrating database...", RNS.LOG_DEBUG)
        self.__db_init(False)

        self.__db_init(False)


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


    def __db_migrate_column_delete(self, table, name):
        db = self.__db_connect()
        dbc = db.cursor()

        dbc.execute("SELECT 1 FROM PRAGMA_TABLE_INFO('"+table+"') WHERE name = '"+name+"'")
        if len(dbc.fetchall()) != 0:
            try:
                dbc.execute("ALTER TABLE "+table+" DROP COLUMN "+name)
            except:
                dbc.execute(f"PRAGMA table_info({table})")
                columns_info = dbc.fetchall()

                primary_key = ""
                primary_keys = []
                for i, column in enumerate(columns_info):
                    if column[5]:
                        primary_keys.append(column[1])
                if len(primary_keys) > 1:
                    primary_key = ", PRIMARY KEY("+", ".join(primary_keys)+")"

                column_position = next(i for i, column in enumerate(columns_info) if column[1] == name)
                del columns_info[column_position]

                dbc.execute(f"DROP TABLE IF EXISTS {table}_old")
                dbc.execute(f"ALTER TABLE {table} RENAME TO {table}_old")
                dbc.execute(f"CREATE TABLE {table} ({', '.join([(f'{col[1]} {col[2]}') + (f' DEFAULT {col[4]}' if col[4] is not None else '') + (' PRIMARY KEY' if col[5] and primary_key == '' else '') for col in columns_info])}"+primary_key+")")
                dbc.execute(f"INSERT INTO {table} ({', '.join([f'{col[1]}' for i, col in enumerate(columns_info)])}) SELECT {', '.join([f'{col[1]}' for i, col in enumerate(columns_info)])} FROM {table}_old")
                dbc.execute(f"DROP TABLE {table}_old")

        self.__db_commit()


    def __db_migrate_column_rename(self, table, name_old, name_new):
        db = self.__db_connect()
        dbc = db.cursor()

        dbc.execute("SELECT 1 FROM PRAGMA_TABLE_INFO('"+table+"') WHERE name = '"+name_old+"'")
        if len(dbc.fetchall()) != 0:
            dbc.execute("ALTER TABLE "+table+" RENAME '"+name_old+"' TO '"+name_new+"'")

        self.__db_commit()


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


    def __db_indices(self):
        pass


    def __db_vacuum(self):
        for i in range(3):
            try:
                db = self.__db_connect()
                dbc = db.cursor()
                dbc.execute("VACUUM")
                self.__db_commit()
                return True

            except Exception as e:
                error = str(e)
                time.sleep(random.uniform(0.05, 0.2))

        RNS.log("Core - An error occurred during vacuum database operation: "+error, RNS.LOG_ERROR)


    def db_vacuum(self):
        self.__db_vacuum()


    def db_load(self):
        RNS.log("Core - Loading database...", RNS.LOG_DEBUG)

        if not os.path.isfile(self.db_path):
            self.__db_init()
        else:
            self.__db_migrate()
            self.__db_indices()


    def db_contacts_set(self, dest, name_announce=None):
        pass


    def db_contacts_add(self, dest, name=None, name_announce=None, trust=False, notify=False, receipt=None, telemetry_receive=None, telemetry_send=None, telemetry_requests=None, commands=None):
        pass


    def db_shops_statistic(self, shop_id):
        try:
            db = self.__db_connect()
            dbc = db.cursor()

            data = {}

            if not os.path.isfile(self.db_path):
                raise
            data["size"] = os.path.getsize(self.db_path)

            query = "SELECT COUNT(*) FROM shop_entry WHERE shop_id = ?"
            dbc.execute(query, (shop_id,))
            result = dbc.fetchall()
            if len(result) < 1:
                data["entrys"] = 0
            else:
                data["entrys"] = result[0][0]

            query = "SELECT COUNT(*) FROM shop_entry WHERE shop_id = ? AND ts = 0"
            dbc.execute(query, (shop_id,))
            result = dbc.fetchall()
            if len(result) < 1:
                data["entrys_del"] = 0
            else:
                data["entrys_del"] = result[0][0]

            query = "SELECT COUNT(*) FROM shop_entry WHERE shop_id = ? AND enabled = 1"
            dbc.execute(query, (shop_id,))
            result = dbc.fetchall()
            if len(result) < 1:
                data["entrys_enabled"] = 0
            else:
                data["entrys_enabled"] = result[0][0]

            query = "SELECT COUNT(*) FROM shop_entry WHERE shop_id = ? AND enabled = 0"
            dbc.execute(query, (shop_id,))
            result = dbc.fetchall()
            if len(result) < 1:
                data["entrys_disabled"] = 0
            else:
                data["entrys_disabled"] = result[0][0]

            return data

        except:
            return None


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

        self.db_contacts_set(dest=shop_id, name_announce=config["title"])


    def db_shops_get_categorys(self, shop_id, category_id=0):
        # TODO
        if category_id > 0:
            return None

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


    def db_shops_get_categorys_count(self, shop_id, category_id=0):
        # TODO
        if category_id > 0:
            return {}

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
        data_old = self.db_shops_get_categorys_count(shop_id)
        data = {}

        db = self.__db_connect()
        dbc = db.cursor()
        query = "SELECT category0, COUNT(category0) FROM shop_entry WHERE ts > 0 AND shop_id = ? AND enabled = 1 GROUP BY category0"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()
        if len(result) > 0:
            for entry in result:
                data[entry[0]] = entry[1]

        if len(data) != len(data_old):
            self.db_shops_set_categorys_count(shop_id, data, time.time())
        else:
            for key, value in data.items():
                if key not in data_old or data_old[key] != value:
                    self.db_shops_set_categorys_count(shop_id, data, time.time())
                    break


    def db_shops_get_images(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT images FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return {}
        else:
            data = msgpack.unpackb(result[0][0])
            return data


    def db_shops_get_images_ts(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT ts_images FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_shops_set_images(self, shop_id, images, ts_images=None, ts_sync=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if ts_images == None:
            ts_images = 0

        query = "UPDATE shop SET images = ?, ts_images = ?, ts_sync = ? WHERE id = ?"
        dbc.execute(query, (msgpack.packb(images), ts_images, ts_sync, shop_id))

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


    def db_shops_get_statistic(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT statistic FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            data = msgpack.unpackb(result[0][0])
            return data


    def db_shops_get_statistic_ts(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT ts_statistic FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_shops_set_statistic(self, shop_id, statistic, ts_statistic=None, ts_sync=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if ts_statistic == None:
            ts_statistic = 0

        if ts_sync == None:
            ts_sync = 0

        query = "UPDATE shop SET statistic = ?, ts_statistic = ?, ts_sync = ? WHERE id = ?"
        dbc.execute(query, (msgpack.packb(statistic), ts_statistic, ts_sync, shop_id))

        self.__db_commit()


    def db_shops_get_cmd(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT cmd FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return {}
        else:
            data = msgpack.unpackb(result[0][0])
            return data


    def db_shops_get_cmd_ts(self, shop_id):
        db = self.__db_connect()
        dbc = db.cursor()

        query = "SELECT ts_cmd FROM shop WHERE id = ?"
        dbc.execute(query, (shop_id,))
        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_shops_set_cmd(self, shop_id, cmd, ts_cmd=None, ts_sync=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if ts_cmd == None:
            ts_cmd = 0

        query = "UPDATE shop SET cmd = ?, ts_cmd = ? WHERE id = ?"
        dbc.execute(query, (msgpack.packb(cmd), ts_cmd, shop_id))

        self.__db_commit()


    def db_shops_get_cmd_count(self, shop_id=None, sync=False):
        db = self.__db_connect()
        dbc = db.cursor()

        if sync:
            if shop_id:
                query = "SELECT COUNT(*) FROM shop WHERE ts_cmd > 0 AND id = ?"
                dbc.execute(query, (shop_id,))
            else:
                query = "SELECT COUNT(*) FROM shop WHERE ts_cmd > 0"
                dbc.execute(query)

            result = dbc.fetchall()
            if len(result) < 1:
                return 0
            else:
                return result[0][0]
        else:
            if shop_id:
                query = "SELECT cmd FROM shop WHERE ts_cmd > 0 AND id = ?"
                dbc.execute(query, (shop_id,))
            else:
                query = "SELECT cmd FROM shop WHERE ts_cmd > 0"
                dbc.execute(query)

            result = dbc.fetchall()

            if len(result) < 1:
                return 0
            else:
                data = msgpack.unpackb(result[0][0])
                return len(data)


    def db_shops_add(self, shop_id, name=None, name_announce=None, trust=False, telemetry_receive=None, storage_duration=None, config=None, categorys=None, categorys_count=None, images=None, pages=None, users=None, statistic=None, cmd=None, ts_config=None, ts_categorys=None, ts_categorys_count=None, ts_images=None, ts_pages=None, ts_users=None, ts_statistic=None, ts_cmd=None, ts_sync=None):
        if isinstance(shop_id, str):
            if len(shop_id) != RNS.Reticulum.TRUNCATED_HASHLENGTH//8*2:
                return False
            shop_id = bytes.fromhex(shop_id)

        if name == None:
            name = ""

        if name_announce == None:
            name_announce = self.display_name_announce(shop_id)

        if telemetry_receive == None:
            telemetry_receive = False

        if storage_duration == None:
            storage_duration = 0

        if config == None:
            config = {}

        if categorys == None:
            categorys = {}

        if categorys_count == None:
            categorys_count = {}

        if images == None:
            images = {}

        if pages == None:
            pages = {}

        if users == None:
            users = {}

        if statistic == None:
            statistic = {}

        if cmd == None:
            cmd = {}

        if ts_config == None:
            ts_config = 0

        if ts_categorys == None:
            ts_categorys = 0

        if ts_categorys_count == None:
            ts_categorys_count = 0

        if ts_images == None:
            ts_images = 0

        if ts_pages == None:
            ts_pages = 0

        if ts_users == None:
            ts_users = 0

        if ts_statistic == None:
            ts_statistic = 0

        if ts_cmd == None:
            ts_cmd = 0

        if ts_sync == None:
            ts_sync = 0

        db = self.__db_connect()
        dbc = db.cursor()

        query = "INSERT INTO shop (id, config, categorys, categorys_count, images, pages, users, statistic, cmd, ts_config, ts_categorys, ts_categorys_count, ts_images, ts_pages, ts_users, ts_statistic, ts_cmd, ts_sync, storage_duration) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        dbc.execute(query, (shop_id, msgpack.packb(config), msgpack.packb(categorys), msgpack.packb(categorys_count), msgpack.packb(images), msgpack.packb(pages), msgpack.packb(users), msgpack.packb(statistic), msgpack.packb(cmd), ts_config, ts_categorys, ts_categorys_count, ts_images, ts_pages, ts_users, ts_statistic, ts_cmd, ts_sync, storage_duration))

        self.__db_commit()

        self.db_contacts_add(dest=shop_id, name=name, name_announce=name_announce, trust=trust, telemetry_receive=telemetry_receive)

        return True


    def db_shops_entrys_filter(self, filter):
        if filter == None:
            return ""

        querys = []

        if "category0" in filter and filter["category0"] != None:
            if isinstance(filter["category0"], list):
                querys.append("category0 IN ("+",".join(self.__db_sanitize(x) for x in filter["category0"])+")")
            else:
                querys.append("category0 = "+self.__db_sanitize(filter["category0"]))

        if "category1" in filter and filter["category1"] != None:
            if isinstance(filter["category1"], list):
                querys.append("category1 IN ("+",".join(self.__db_sanitize(x) for x in filter["category1"])+")")
            else:
                querys.append("category1 = "+self.__db_sanitize(filter["category1"]))

        if "enabled" in filter:
            if filter["enabled"]:
                querys.append("enabled = 1")
            else:
                querys.append("enabled = 0")

        if "vendor_id" in filter:
            querys.append("vendor_id = X'"+self.__db_sanitize(filter["vendor_id"])+"'")

        if "title0" in filter:
            querys.append("title0 LIKE '%"+self.__db_sanitize(filter["title0"])+"%' COLLATE NOCASE")

        if "title1" in filter:
            querys.append("title1 LIKE '%"+self.__db_sanitize(filter["title1"])+"%' COLLATE NOCASE")

        if "title2" in filter:
            querys.append("title2 LIKE '%"+self.__db_sanitize(filter["title2"])+"%' COLLATE NOCASE")

        if "text0" in filter:
            querys.append("text0 LIKE '%"+self.__db_sanitize(filter["text0"])+"%' COLLATE NOCASE")

        if "text1" in filter:
            querys.append("text1 LIKE '%"+self.__db_sanitize(filter["text1"])+"%' COLLATE NOCASE")

        if "text2" in filter:
            querys.append("text2 LIKE '%"+self.__db_sanitize(filter["text2"])+"%' COLLATE NOCASE")

        if "text3" in filter:
            querys.append("text3 LIKE '%"+self.__db_sanitize(filter["text3"])+"%' COLLATE NOCASE")

        if "text4" in filter:
            querys.append("text4 LIKE '%"+self.__db_sanitize(filter["text4"])+"%' COLLATE NOCASE")

        if "text5" in filter:
            querys.append("text5 LIKE '%"+self.__db_sanitize(filter["text5"])+"%' COLLATE NOCASE")

        if "num0_min" in filter:
            querys.append("num0 >= "+self.__db_sanitize(filter["num0_min"]))

        if "num0_max" in filter:
            querys.append("num0 <= "+self.__db_sanitize(filter["num0_max"]))

        if "num1_min" in filter:
            querys.append("num1 >= "+self.__db_sanitize(filter["num1_min"]))

        if "num1_max" in filter:
            querys.append("num1 <= "+self.__db_sanitize(filter["num1_max"]))

        if "num2_min" in filter:
            querys.append("num2 >= "+self.__db_sanitize(filter["num2_min"]))

        if "num2_max" in filter:
            querys.append("num2 <= "+self.__db_sanitize(filter["num2_max"]))

        if "num3_min" in filter:
            querys.append("num3 >= "+self.__db_sanitize(filter["num3_min"]))

        if "num3_max" in filter:
            querys.append("num3 <= "+self.__db_sanitize(filter["num3_max"]))

        if "num4_min" in filter:
            querys.append("num4 >= "+self.__db_sanitize(filter["num4_min"]))

        if "num4_max" in filter:
            querys.append("num4 <= "+self.__db_sanitize(filter["num4_max"]))

        if "num5_min" in filter:
            querys.append("num5 >= "+self.__db_sanitize(filter["num5_min"]))

        if "num5_max" in filter:
            querys.append("num5 <= "+self.__db_sanitize(filter["num5_max"]))

        if "option0" in filter:
            querys.append("option0 = "+self.__db_sanitize(filter["option0"]))

        if "option1" in filter:
            querys.append("option1 = "+self.__db_sanitize(filter["option1"]))

        if "option2" in filter:
            querys.append("option2 = "+self.__db_sanitize(filter["option2"]))

        if "option3" in filter:
            querys.append("option3 = "+self.__db_sanitize(filter["option3"]))

        if "option4" in filter:
            querys.append("option4 = "+self.__db_sanitize(filter["option4"]))

        if "option5" in filter:
            querys.append("option5 = "+self.__db_sanitize(filter["option5"]))

        if "option6" in filter:
            querys.append("option6 = "+self.__db_sanitize(filter["option6"]))

        if "option7" in filter:
            querys.append("option7 = "+self.__db_sanitize(filter["option7"]))

        if "tags0" in filter:
            tags = []
            if "tags0_mode" in filter and filter["tags0_mode"] == 0x02:
                mode = " NOT LIKE "
            else:
                mode = " LIKE "
            for key in filter["tags0"]:
                tags.append("tags0"+mode+"'%"+self.__db_sanitize(key)+"%'")
            if "tags0_mode" in filter and filter["tags0_mode"] == 0x00:
                mode = " OR "
            else:
                mode = " AND "
            querys.append("("+mode.join(tags)+")")

        if "tags1" in filter:
            tags = []
            if "tags1_mode" in filter and filter["tags1_mode"] == 0x02:
                mode = " NOT LIKE "
            else:
                mode = " LIKE "
            for key in filter["tags1"]:
                tags.append("tags1"+mode+"'%"+self.__db_sanitize(key)+"%'")
            if "tags1_mode" in filter and filter["tags1_mode"] == 0x00:
                mode = " OR "
            else:
                mode = " AND "
            querys.append("("+mode.join(tags)+")")

        if "tags2" in filter:
            tags = []
            if "tags2_mode" in filter and filter["tags2_mode"] == 0x02:
                mode = " NOT LIKE "
            else:
                mode = " LIKE "
            for key in filter["tags2"]:
                tags.append("tags2"+mode+"'%"+self.__db_sanitize(key)+"%'")
            if "tags2_mode" in filter and filter["tags2_mode"] == 0x00:
                mode = " OR "
            else:
                mode = " AND "
            querys.append("("+mode.join(tags)+")")

        if "tags3" in filter:
            tags = []
            if "tags3_mode" in filter and filter["tags3_mode"] == 0x02:
                mode = " NOT LIKE "
            else:
                mode = " LIKE "
            for key in filter["tags3"]:
                tags.append("tags3"+mode+"'%"+self.__db_sanitize(key)+"%'")
            if "tags3_mode" in filter and filter["tags3_mode"] == 0x00:
                mode = " OR "
            else:
                mode = " AND "
            querys.append("("+mode.join(tags)+")")

        if "tags4" in filter:
            tags = []
            if "tags4_mode" in filter and filter["tags4_mode"] == 0x02:
                mode = " NOT LIKE "
            else:
                mode = " LIKE "
            for key in filter["tags4"]:
                tags.append("tags4"+mode+"'%"+self.__db_sanitize(key)+"%'")
            if "tags4_mode" in filter and filter["tags4_mode"] == 0x00:
                mode = " OR "
            else:
                mode = " AND "
            querys.append("("+mode.join(tags)+")")

        if "tags5" in filter:
            tags = []
            if "tags5_mode" in filter and filter["tags5_mode"] == 0x02:
                mode = " NOT LIKE "
            else:
                mode = " LIKE "
            for key in filter["tags5"]:
                tags.append("tags5"+mode+"'%"+self.__db_sanitize(key)+"%'")
            if "tags5_mode" in filter and filter["tags5_mode"] == 0x00:
                mode = " OR "
            else:
                mode = " AND "
            querys.append("("+mode.join(tags)+")")

        if "tags6" in filter:
            tags = []
            if "tags6_mode" in filter and filter["tags6_mode"] == 0x02:
                mode = " NOT LIKE "
            else:
                mode = " LIKE "
            for key in filter["tags6"]:
                tags.append("tags6"+mode+"'%"+self.__db_sanitize(key)+"%'")
            if "tags6_mode" in filter and filter["tags6_mode"] == 0x00:
                mode = " OR "
            else:
                mode = " AND "
            querys.append("("+mode.join(tags)+")")

        if "tags7" in filter:
            tags = []
            if "tags7_mode" in filter and filter["tags7_mode"] == 0x02:
                mode = " NOT LIKE "
            else:
                mode = " LIKE "
            for key in filter["tags7"]:
                tags.append("tags7"+mode+"'%"+self.__db_sanitize(key)+"%'")
            if "tags7_mode" in filter and filter["tags7_mode"] == 0x00:
                mode = " OR "
            else:
                mode = " AND "
            querys.append("("+mode.join(tags)+")")

        if "price_min" in filter:
            querys.append("price >= "+self.__db_sanitize(filter["price_min"]))

        if "price_max" in filter:
            querys.append("price <= "+self.__db_sanitize(filter["price_max"]))

        if "currency" in filter:
            querys.append("currency = "+self.__db_sanitize(filter["currency"]))

        if "ts_min" in filter:
            querys.append("ts >= "+self.__db_sanitize(filter["ts_min"]))

        if "ts_max" in filter:
            querys.append("ts <= "+self.__db_sanitize(filter["ts_max"]))

        if len(querys) > 0:
            query = " AND "+" AND ".join(querys)
        else:
            query = ""

        return query


    def db_shops_entrys_order(self, order):
        if order == None:
            return ""

        querys = []

        for key, value in order.items():
            querys.append("shop_entry."+self.__db_sanitize(key)+" "+self.__db_sanitize(value))

        if len(querys) > 0:
            query = " ORDER BY "+", ".join(querys)
        else:
            query = ""

        return query


    def db_shops_entrys_list(self, shop_id=None, vendor_id=None, filter=None, search=None, order=None, limit=None, limit_start=None, sync=False, sync_data=True, sync_title=True, sync_text=True, sync_images=True, sync_files=True):
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
                query_limit = " LIMIT "+self.__db_sanitize(limit)+" OFFSET "+self.__db_sanitize(limit_start)

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
                if not sync or not shop_id:
                    data_append["shop_id"] = entry[1]
                if not sync:
                    data_append["vendor_id"] = entry[2]
                if sync_data:
                    data_append["category0"] = entry[3]
                    data_append["category1"] = entry[4]
                    data_append["enabled"] = entry[5]
                if sync_title:
                    data_append["title0"] = entry[6]
                    data_append["title1"] = entry[7]
                    data_append["title2"] = entry[8]
                if sync_text:
                    data_append["text0"] = entry[9]
                    data_append["text1"] = entry[10]
                    data_append["text2"] = entry[11]
                    data_append["text3"] = entry[12]
                    data_append["text4"] = entry[13]
                    data_append["text5"] = entry[14]
                if sync_data:
                    data_append["num0"] = entry[15]
                    data_append["num1"] = entry[16]
                    data_append["num2"] = entry[17]
                    data_append["num3"] = entry[18]
                    data_append["num4"] = entry[19]
                    data_append["num5"] = entry[20]
                    data_append["option0"] = entry[21]
                    data_append["option1"] = entry[22]
                    data_append["option2"] = entry[23]
                    data_append["option3"] = entry[24]
                    data_append["option4"] = entry[25]
                    data_append["option5"] = entry[26]
                    data_append["option6"] = entry[27]
                    data_append["option7"] = entry[28]
                    data_append["tags0"] = entry[29]
                    data_append["tags1"] = entry[30]
                    data_append["tags2"] = entry[31]
                    data_append["tags3"] = entry[32]
                    data_append["tags4"] = entry[33]
                    data_append["tags5"] = entry[34]
                    data_append["tags6"] = entry[35]
                    data_append["tags7"] = entry[36]
                if sync_images:
                    data_append["images"] = msgpack.unpackb(entry[37])
                if sync_data:
                    data_append["files"] = msgpack.unpackb(entry[38])
                    data_append["price"] = entry[40]
                    data_append["currency"] = entry[41]
                    data_append["variants"] = msgpack.unpackb(entry[42])
                    data_append["q_available"] = entry[43]
                    data_append["q_min"] = entry[44]
                    data_append["q_max"] = entry[45]
                    data_append["rate"] = entry[46]
                    data_append["location_lat"] = entry[47]
                    data_append["location_lon"] = entry[48]
                data_append["ts"] = entry[49]
                if sync_data:
                    data_append["ts_data"] = entry[50]
                if sync_title:
                    data_append["ts_title"] = entry[51]
                if sync_text:
                    data_append["ts_text"] = entry[52]
                if sync_images:
                    data_append["ts_images"] = entry[53]
                if sync_files:
                    data_append["ts_files"] = entry[54]
                if not sync:
                    data_append["ts_sync"] = entry[55]

                data.append(data_append)

            return data


    def db_shops_entrys_get(self, shop_id=None, entry_id=None, variant=None, sync=False, sync_data=True, sync_title=True, sync_text=True, sync_images=True, sync_files=True):
        db = self.__db_connect()
        dbc = db.cursor()

        if variant == None:
            variant = 0

        query = "SELECT shop_entry.*, shop_cart.variant, shop_cart.quantity, IIF(shop_cart.variant IS NOT NULL, 1, 0), IIF(shop_favorite.shop_id IS NOT NULL, 1, 0), IIF(shop_notify.shop_id IS NOT NULL, 1, 0) FROM shop_entry LEFT JOIN shop_cart ON shop_cart.shop_id = shop_entry.shop_id AND shop_cart.entry_id = shop_entry.entry_id AND shop_cart.variant = ? LEFT JOIN shop_favorite ON shop_favorite.shop_id = shop_entry.shop_id AND shop_favorite.entry_id = shop_entry.entry_id LEFT JOIN shop_notify ON shop_notify.shop_id = shop_entry.shop_id AND shop_notify.entry_id = shop_entry.entry_id WHERE shop_entry.shop_id = ? AND shop_entry.entry_id = ?"
        dbc.execute(query, (variant, shop_id, entry_id))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            entry = result[0]
            data = {}
            data["entry_id"] = entry[0]
            if not sync:
                data["shop_id"] = entry[1]
                data["vendor_id"] = entry[2]
            if sync_data:
                data["category0"] = entry[3]
                data["category1"] = entry[4]
                data["enabled"] = entry[5]
            if sync_title:
                data["title0"] = entry[6]
                data["title1"] = entry[7]
                data["title2"] = entry[8]
            if sync_text:
                data["text0"] = entry[9]
                data["text1"] = entry[10]
                data["text2"] = entry[11]
                data["text3"] = entry[12]
                data["text4"] = entry[13]
                data["text5"] = entry[14]
            if sync_data:
                data["num0"] = entry[15]
                data["num1"] = entry[16]
                data["num2"] = entry[17]
                data["num3"] = entry[18]
                data["num4"] = entry[19]
                data["num5"] = entry[20]
                data["option0"] = entry[21]
                data["option1"] = entry[22]
                data["option2"] = entry[23]
                data["option3"] = entry[24]
                data["option4"] = entry[25]
                data["option5"] = entry[26]
                data["option6"] = entry[27]
                data["option7"] = entry[28]
                data["tags0"] = entry[29]
                data["tags1"] = entry[30]
                data["tags2"] = entry[31]
                data["tags3"] = entry[32]
                data["tags4"] = entry[33]
                data["tags5"] = entry[34]
                data["tags6"] = entry[35]
                data["tags7"] = entry[36]
            if sync_images:
                data["images"] = msgpack.unpackb(entry[37])
            if sync_data or sync_files:
                data["files"] = msgpack.unpackb(entry[38])
            if sync:
                if sync_files:
                    files = msgpack.unpackb(entry[38])
                    if files and len(files) > 0:
                        files_data = msgpack.unpackb(entry[39])
                        if files_data and len(files_data) > 0:
                            data["files_data"] = {}
                            for key, value in files.items():
                                if value["ts"] == 0:
                                    if key in files_data:
                                        data["files_data"][key] = files_data[key]
                            if len(data["files_data"]) == 0:
                                del data["files_data"]
            else:
                data["files_data"] = msgpack.unpackb(entry[39])
            if sync_data:
                data["price"] = entry[40]
                data["currency"] = entry[41]
                data["variants"] = msgpack.unpackb(entry[42])
                data["q_available"] = entry[43]
                data["q_min"] = entry[44]
                data["q_max"] = entry[45]
                data["rate"] = entry[46]
                data["location_lat"] = entry[47]
                data["location_lon"] = entry[48]
            data["ts"] = entry[49]
            if sync_data:
                data["ts_data"] = entry[50]
            if sync_title:
                data["ts_title"] = entry[51]
            if sync_text:
                data["ts_text"] = entry[52]
            if sync_images:
                data["ts_images"] = entry[53]
            if sync_files:
                data["ts_files"] = entry[54]

            if not sync:
                data["ts_sync"] = entry[55]
                data["variant"] = entry[56]
                data["quantity"] = entry[57]
                data["cart"] = entry[58]
                data["favorites"] = entry[59]
                data["notify"] =entry[60]

            return data


    def db_shops_entrys_get_file(self, shop_id=None, entry_id=None, file=None):
        db = self.__db_connect()
        dbc = db.cursor()

        data = {}
        data[entry_id] = {}

        query = "SELECT files, files_data FROM shop_entry WHERE shop_id = ? AND entry_id = ? AND enabled = 1"
        dbc.execute(query, (shop_id, entry_id))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            files = msgpack.unpackb(result[0][0])
            files_data = msgpack.unpackb(result[0][1])

            if file in files and file in files_data and files[file]["type"] != 0x00:
                return {"name": files[file]["name"], "size": files[file]["size"], "data": files_data[file]}
            else:
                return None


    def db_shops_entrys_set(self, entry=None, vendor_id=None, sync=False):
        now = time.time()
        result = 0x00
        result_files = []

        try:
            db = self.__db_connect()
            dbc = db.cursor()

            if "ts" in entry and entry["ts"] == 0:
                result = 0x03
                if vendor_id:
                    query = "DELETE FROM shop_entry WHERE entry_id = ? AND shop_id = ? AND vendor_id <> ?"
                    dbc.execute(query, (entry["entry_id"], entry["shop_id"], vendor_id))
                else:
                    query = "DELETE FROM shop_entry WHERE entry_id = ? AND shop_id = ?"
                    dbc.execute(query, (entry["entry_id"], entry["shop_id"]))

            else:
                query = "SELECT entry_id FROM shop_entry WHERE entry_id = ? AND shop_id = ?"
                dbc.execute(query, (entry["entry_id"], entry["shop_id"]))
                result = dbc.fetchall()
                if len(result) < 1:
                    result = 0x01
                    query = "INSERT OR REPLACE INTO shop_entry (entry_id, shop_id, vendor_id, variants, images, files, files_data, ts) values (?, ?, ?, ?, ?, ?, ?, ?)"
                    dbc.execute(query, (entry["entry_id"], entry["shop_id"], entry["vendor_id"], msgpack.packb(None), msgpack.packb(None), msgpack.packb(None), msgpack.packb(None), entry["ts"]))
                else:
                    result = 0x02

                if "ts_data" in entry:
                    query = "UPDATE shop_entry SET category0 = ?, category1 = ?, enabled = ?, num0 = ?, num1 = ?, num2 = ?, num3 = ?, num4 = ?, num5 = ?, option0 = ?, option1 = ?, option2 = ?, option3 = ?, option4 = ?, option5 = ?, option6 = ?, option7 = ?, tags0 = ?, tags1 = ?, tags2 = ?, tags3 = ?, tags4 = ?, tags5 = ?, tags6 = ?, tags7 = ?, files = ?, price = ?, currency = ?, variants = ?, q_available = ?, q_min = ?, q_max = ?, rate = ?, location_lat = ?, location_lon = ?, ts_data = ? WHERE entry_id = ? AND shop_id = ? AND ts_data <= ?"
                    dbc.execute(query, (entry["category0"], entry["category1"], entry["enabled"], entry["num0"], entry["num1"], entry["num2"], entry["num3"], entry["num4"], entry["num5"], entry["option0"], entry["option1"], entry["option2"], entry["option3"], entry["option4"], entry["option5"], entry["option6"], entry["option7"], entry["tags0"], entry["tags1"], entry["tags2"], entry["tags3"], entry["tags4"], entry["tags5"], entry["tags6"], entry["tags7"], msgpack.packb(entry["files"]), entry["price"], entry["currency"], msgpack.packb(entry["variants"]), entry["q_available"], entry["q_min"], entry["q_max"], entry["rate"], entry["location_lat"], entry["location_lon"], entry["ts_data"], entry["entry_id"], entry["shop_id"], entry["ts_data"]))

                if "ts_title" in entry:
                    query = "UPDATE shop_entry SET title0 = ?, title1 = ?, title2 = ?, ts_title = ? WHERE entry_id = ? AND shop_id = ? AND ts_title <= ?"
                    dbc.execute(query, (entry["title0"], entry["title1"], entry["title2"], entry["ts_title"], entry["entry_id"], entry["shop_id"], entry["ts_title"]))

                if "ts_text" in entry:
                    query = "UPDATE shop_entry SET text0 = ?, text1 = ?, text2 = ?, text3 = ?, text4 = ?, text5 = ?, ts_text = ? WHERE entry_id = ? AND shop_id = ? AND ts_text <= ?"
                    dbc.execute(query, (entry["text0"], entry["text1"], entry["text2"], entry["text3"], entry["text4"], entry["text5"], entry["ts_text"], entry["entry_id"], entry["shop_id"], entry["ts_text"]))

                if "ts_images" in entry:
                    query = "UPDATE shop_entry SET images = ?, ts_images = ? WHERE entry_id = ? AND shop_id = ? AND ts_images <= ?"
                    dbc.execute(query, (msgpack.packb(entry["images"]), entry["ts_images"], entry["entry_id"], entry["shop_id"], entry["ts_images"]))

                if "ts_files" in entry:
                    if not "files" in entry or not entry["files"] or len(entry["files"]) == 0:
                        files = None
                        files_data = None
                    else:
                        files = entry["files"]
                        query = "SELECT files_data FROM shop_entry WHERE entry_id = ? AND shop_id = ?"
                        dbc.execute(query, (entry["entry_id"], entry["shop_id"]))
                        result = dbc.fetchall()
                        if len(result) < 1:
                            files_data = {}
                        else:
                            files_data = msgpack.unpackb(result[0][0])
                            if files_data:
                                for key in list(files_data):
                                    if key not in files:
                                        del files_data[key]
                            else:
                                files_data = {}
                        if "files_data" in entry and entry["files_data"]:
                            files_data.update(entry["files_data"])
                            if sync:
                                for key in list(entry["files_data"]):
                                    result_files.append(key)
                    if files and len(files) == 0:
                        files = None
                    if files_data and len(files_data) == 0:
                        files_data = None
                    query = "UPDATE shop_entry SET files = ?, files_data = ?, ts_files = ? WHERE entry_id = ? AND shop_id = ?"
                    dbc.execute(query, (msgpack.packb(files), msgpack.packb(files_data), entry["ts_files"], entry["entry_id"], entry["shop_id"]))

                if "ts_sync" in entry:
                    query = "UPDATE shop_entry SET ts_sync = ? WHERE entry_id = ? AND shop_id = ?"
                    dbc.execute(query, (entry["ts_sync"], entry["entry_id"], entry["shop_id"]))

            self.__db_commit()

        except Exception as e:
            RNS.log("Core - DB - Error: "+str(e), RNS.LOG_ERROR)
            result = 0x00
            result_files = []

        if sync:
            return result, result_files
        else:
            return result


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


    def db_shops_entrys_delete(self, entry=None, loopback=False, shop_id=None, entry_id=None, vendor_id=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if entry != None:
            query = "DELETE FROM shop_cart WHERE shop_id = ? AND entry_id = ?"
            dbc.execute(query, (entry["shop_id"], entry["entry_id"]))

            query = "DELETE FROM shop_entry WHERE shop_id = ? AND entry_id = ?"
            dbc.execute(query, (entry["shop_id"], entry["entry_id"]))

            if not loopback:
                query = "INSERT OR REPLACE INTO shop_entry (entry_id, shop_id, vendor_id, images, variants, files, files_data) values (?, ?, ?, ?, ?, ?, ?)"
                dbc.execute(query, (entry["entry_id"], entry["shop_id"], entry["vendor_id"], msgpack.packb(None), msgpack.packb(None), msgpack.packb(None), msgpack.packb(None)))

            query = "DELETE FROM shop_favorite WHERE shop_id = ? AND entry_id = ?"
            dbc.execute(query, (entry["shop_id"], entry["entry_id"]))

            query = "DELETE FROM shop_notify WHERE shop_id = ? AND entry_id = ?"
            dbc.execute(query, (entry["shop_id"], entry["entry_id"]))

        elif shop_id != None and entry_id != None:
            query = "DELETE FROM shop_entry WHERE shop_id = ? AND entry_id = ?"
            dbc.execute(query, (shop_id, entry_id))

        elif shop_id != None and vendor_id != None:
            query = "DELETE FROM shop_entry WHERE shop_id = ? AND vendor_id = ?"
            dbc.execute(query, (shop_id, vendor_id))

        self.__db_commit()


    def db_shops_entrys_set_vendor_id(self, shop_id=None, entry_id=None, loopback=False, vendor_id_old=None, vendor_id_new=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if loopback:
            ts_sync = time.time()
        else:
            ts_sync = 0

        if entry_id != None and vendor_id_old == None:
            query = "UPDATE shop_entry SET entry_id = ?, vendor_id = ?, enabled = ?, ts_sync = ? WHERE shop_id = ? AND entry_id = ?"
            dbc.execute(query, (self.uid_bytes(), vendor_id_new, True, ts_sync, shop_id, entry_id))
        else:
            query = "SELECT entry_id FROM shop_entry WHERE shop_id = ? AND vendor_id = ?"
            dbc.execute(query, (shop_id, vendor_id_old))
            result = dbc.fetchall()
            if len(result) >= 1:
                for entry in result:
                    query = "UPDATE shop_entry SET entry_id = ?, vendor_id = ?, enabled = ?, ts_sync = ? WHERE shop_id = ? AND entry_id = ?"
                    dbc.execute(query, (self.uid_bytes(), vendor_id_new, True, ts_sync, shop_id, entry[0]))

        self.__db_commit()


    def db_shops_entrys_set_enabled(self, shop_id=None, entry_id=None, value=False, loopback=False, vendor_id=None):
        db = self.__db_connect()
        dbc = db.cursor()

        if loopback:
            ts_sync = time.time()
        else:
            ts_sync = 0

        if entry_id != None and vendor_id == None:
            query = "UPDATE shop_entry SET enabled = ?, ts_data = ?, ts_sync = ? WHERE shop_id = ? AND entry_id = ?"
            dbc.execute(query, (value, time.time(), ts_sync, shop_id, entry_id))
        else:
            query = "UPDATE shop_entry SET enabled = ?, ts_data = ?, ts_sync = ? WHERE shop_id = ? AND vendor_id = ?"
            dbc.execute(query, (value, time.time(), ts_sync, shop_id, vendor_id))

        self.__db_commit()


    def uid_bytes(self):
        return RNS.Identity().hash


    def uid_str(self):
        return str(uuid.uuid4())


##############################################################################################################
# CMDs


def cmd(cmd):
    db = CORE.db_connect()
    dbc = db.cursor()
    query = "SELECT id FROM shop LIMIT 1"
    dbc.execute("SELECT id FROM shop LIMIT 1")
    result = dbc.fetchall()
    if len(result) < 1:
        print("Error: No configuration exists")
        panic()
    else:
        shop_id = result[0][0]

    config = CORE.db_shops_get_config(shop_id)
    if not config:
        print("Error: No configuration exists")
        panic()

    cmd = cmd.strip()
    cmd = cmd.split()

    if len(cmd) < 1:
        print("Error: Command format wrong")
        panic()

    if cmd[0] == "enable" and len(cmd) == 1:
        config["enabled"] = True
        CORE.db_shops_set_config(shop_id, config, time.time())

    elif cmd[0] == "disable" and len(cmd) == 1:
        config["enabled"] = False
        CORE.db_shops_set_config(shop_id, config, time.time())

    elif cmd[0] in config and len(cmd) == 2:
        value = cmd[1]
        if value.isdigit():
            value = int(value)
        elif value.isnumeric():
            value = float(value)
        elif value.lower() == "true":
            value = True
        elif value.lower() == "false":
            value = False
        elif value.startswith("0x") or value.startswith("0X"):
            try:
                value_int = int(value, 16)
                value = val_int
            except:
                pass

    else:
        print("Error: Wrong/Unknown command")
        panic()


def cmd_val_to_val(val):
    if val.isdigit():
        return int(val)
    elif val.isnumeric():
        return float(val)
    elif val.lower() == "true":
        return True
    elif val.lower() == "false":
        return False
    elif val.startswith("0x") or val.startswith("0X"):
        try:
            val_int = int(val, 16)
            return val_int
        except:
            pass
    return val

def cmd_db():
    try:
        import readline
    except ImportError:
        pass

    print("---- Database interface ----")
    print("")

    print("File: "+CORE.db_path)
    print("")

    db = CORE.db_connect()

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
                CORE.db_commit()
            except Exception as e:
                print("Error: "+str(e))


def cmd_status():
    print("---- Database status ----")
    print("")

    print("File: "+CORE.db_path)
    print("Size: "+cmd_size_str(os.path.getsize(CORE.db_path)))

    db = CORE.db_connect()
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


def cmd_user(cmd):
    db = CORE.db_connect()
    dbc = db.cursor()
    query = "SELECT id FROM shop LIMIT 1"
    dbc.execute("SELECT id FROM shop LIMIT 1")
    result = dbc.fetchall()
    if len(result) < 1:
        print("Error: No configuration exists")
        panic()
    else:
        shop_id = result[0][0]

    config = CORE.db_shops_get_config(shop_id)
    if not config:
        print("Error: No configuration exists")
        panic()

    users = CORE.db_shops_get_users(shop_id)
    if not users:
        print("Error: No users exists")
        panic()

    cmd = cmd.strip()
    cmd = cmd.split()

    if len(cmd) < 1:
        print("Error: Command format wrong")
        panic()

    if cmd[0] == "list" and len(cmd) == 1:
        print("User/Address\tRight")
        for key, value in users.items():
            try:
                print(RNS.prettyhexrep(key)+"\t"+str(value))
            except:
                print(str(key)+"\t"+str(value))

    elif cmd[0] == "get" and len(cmd) == 2:
        try:
            if cmd[1] == "any":
                dest = cmd[1]
            else:
                dest = bytes.fromhex(cmd[1])
                if len(dest) != RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
                    raise ValueError("Wrong format")
        except Exception as e:
            print("Error: Destination address: "+str(e))
            panic()
        print("User/Address\tRight")
        if dest in users:
            try:
                print(RNS.prettyhexrep(dest)+"\t"+str(users[dest]))
            except:
                print(str(dest)+"\t"+str(users[dest]))

    elif cmd[0] == "add" and len(cmd) == 2:
        if "state_first_run" in config:
            del config["state_first_run"]
            CORE.db_shops_set_config(shop_id, config, time.time())
        try:
            if cmd[1] == "any":
                dest = cmd[1]
            else:
                dest = bytes.fromhex(cmd[1])
                if len(dest) != RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
                    raise ValueError("Wrong format")
        except Exception as e:
            print("Error: Destination address: "+str(e))
            panic()
        users[dest] = DEFAULT_RIGHT
        CORE.db_shops_set_users(shop_id, users, time.time())

    elif cmd[0] == "add" and len(cmd) == 3:
        if "state_first_run" in config:
            del config["state_first_run"]
            CORE.db_shops_set_config(shop_id, config, time.time())
        try:
            if cmd[1] == "any":
                dest = cmd[1]
            else:
                dest = bytes.fromhex(cmd[1])
                if len(dest) != RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
                    raise ValueError("Wrong format")
        except Exception as e:
            print("Error: Destination address: "+str(e))
            panic()
        users[dest] = int(cmd[2])
        CORE.db_shops_set_users(shop_id, users, time.time())

    elif cmd[0] == "del" and len(cmd) == 2:
        try:
            if cmd[1] == "any":
                dest = cmd[1]
            else:
                dest = bytes.fromhex(cmd[1])
                if len(dest) != RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
                    raise ValueError("Wrong format")
        except Exception as e:
            print("Error: Destination address: "+str(e))
            panic()
        if dest in users:
            del users[dest]
            CORE.db_shops_set_users(shop_id, users, time.time())

    elif cmd[0] == "set" and len(cmd) == 3:
        try:
            if cmd[1] == "any":
                dest = cmd[1]
            else:
                dest = bytes.fromhex(cmd[1])
                if len(dest) != RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
                    raise ValueError("Wrong format")
        except Exception as e:
            print("Error: Destination address: "+str(e))
            panic()
        if dest in users:
            users[dest] = int(cmd[2])
            CORE.db_shops_set_users(shop_id, users, time.time())
        else:
            print("Error: User does not exist")
            panic()

    elif cmd[0] == "check" and len(cmd) == 3:
        try:
            if cmd[1] == "any":
                dest = cmd[1]
            else:
                dest = bytes.fromhex(cmd[1])
                if len(dest) != RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
                    raise ValueError("Wrong format")
        except Exception as e:
            print("Error: Destination address: "+str(e))
            panic()
        if dest in users and users[dest] == int(cmd[2]):
            print("1")
        else:
            print("0")

    else:
        print("Error: Wrong/Unknown command")
        panic()


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
def setup_core(path=None):
    global PATH
    global CORE

    if path is not None:
        if path.endswith("/"):
            path = path[:-1]
        PATH = path

    if path is None:
        path = PATH

    CORE = Core(storage_path=path)


#### Setup #####
def setup(path=None, path_rns=None, path_log=None, loglevel=None, service=False):
    global PATH
    global PATH_RNS
    global LOG_LEVEL
    global LOG_FILE
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

    CORE.reticulum = RNS_CONNECTION

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
        default_user_interfaces=DEFAULT_USER_INTERFACES,
        default_user_hops=DEFAULT_USER_HOPS,
        default_right=DEFAULT_RIGHT,
        default_right_block=DEFAULT_RIGHT_BLOCK
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

        parser.add_argument("--cmd", action="store", type=str, default=None, help="Manage server")
        parser.add_argument("--cmd_db", action="store_true", default=False, help="Database command interface (Execute any sql database command)")
        parser.add_argument("--cmd_status", action="store_true", default=False, help="Database status interface (Shows the current status)")
        parser.add_argument("--cmd_user", action="store", type=str, default=None, help="Manage users")

        params = parser.parse_args()

        setup_core(path=params.path)

        if params.cmd:
            cmd(params.cmd)
            exit()

        if params.cmd_db:
            cmd_db()
            exit()

        if params.cmd_status:
            cmd_status()
            exit()

        if params.cmd_user:
            cmd_user(params.cmd_user)
            exit()

        setup(path=params.path, path_rns=params.path_rns, path_log=params.path_log, loglevel=params.loglevel, service=params.service)

    except KeyboardInterrupt:
        print("Terminated by CTRL-C")
        exit()


##############################################################################################################
# Init


if __name__ == "__main__":
    main()