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
from datetime import datetime, timezone
import argparse
import random

#### Config ####
import configparser

#### JSON ####
import json
import pickle

#### String ####
import string

#### Regex ####
import re

#### UID ####
import uuid

#### ####
import base64

#### Process ####
import signal
import threading
import subprocess

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack

#### PostgreSQL ####
# Install: pip3 install psycopg2
# Install: pip3 install psycopg2-binary
# Source: https://pypi.org/project/psycopg2/
import psycopg2


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "RNS Server Provisioning"
DESCRIPTION = "Provisioning for RNS based apps"
VERSION = "0.0.1 (2024-05-31)"
COPYRIGHT = "(c) 2024 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/"+os.path.splitext(os.path.basename(__file__))[0]
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
# ServerProvisioning Class


class ServerProvisioning:
    RESULT_ERROR       = 0x00
    RESULT_OK          = 0x01
    RESULT_SYNCRONIZE  = 0x02
    RESULT_NO_IDENTITY = 0x03
    RESULT_NO_RIGHT    = 0x04
    RESULT_DISABLED    = 0xFE
    RESULT_BLOCKED     = 0xFF


    def __init__(self, storage_path=None, identity_file="identity", identity=None, destination_name="nomadnetwork", destination_type="provisioning", destination_conv_name="lxmf", destination_conv_type="delivery", announce_startup=False, announce_startup_delay=0, announce_periodic=False, announce_periodic_interval=360, announce_data="", announce_hidden=False, register_startup=True, register_startup_delay=0, register_periodic=True, register_periodic_interval=30, config=None, admins=[]):
        self.storage_path = storage_path

        self.identity_file = identity_file
        self.identity = identity

        self.destination_name = destination_name
        self.destination_type = destination_type
        self.aspect_filter = self.destination_name + "." + self.destination_type
        self.destination_conv_name = destination_conv_name
        self.destination_conv_type = destination_conv_type
        self.aspect_filter_conv = self.destination_conv_name + "." + self.destination_conv_type

        self.announce_startup = announce_startup
        self.announce_startup_delay = int(announce_startup_delay)
        if self.announce_startup_delay == 0:
            self.announce_startup_delay = random.randint(5, 30)

        self.announce_periodic = announce_periodic
        self.announce_periodic_interval = int(announce_periodic_interval)

        self.announce_data = announce_data
        self.announce_hidden = announce_hidden

        self.config = config

        self.admins = admins

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

        self.db = None


    def start(self):
        pass


    def stop(self):
        pass


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
        self.destination.register_request_handler("execute", response_generator=self.execute, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("directory_member", response_generator=self.directory_member, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("directory_service", response_generator=self.directory_service, allow=RNS.Destination.ALLOW_ALL)


    def peer_connected(self, link):
        RNS.log("Server - Peer connected to "+str(self.destination), RNS.LOG_VERBOSE)

        link.set_link_closed_callback(self.peer_disconnected)
        link.set_remote_identified_callback(self.peer_identified)


    def peer_disconnected(self, link):
        RNS.log("Server - Peer disconnected from "+str(self.destination), RNS.LOG_VERBOSE)


    def peer_identified(self, link, identity):
        if not identity:
            link.teardown()


    def db_connect(self):
        try:
            if self.db == None:
                self.db = psycopg2.connect(user=self.config["database"]["user"], password=self.config["database"]["password"], host=self.config["database"]["host"], port=self.config["database"]["port"], database=self.config["database"]["database"], client_encoding=self.config["database"]["encoding"])
        except:
            self.db = None

        return self.db


    def db_commit(self):
        if self.db != None:
            try:
                self.db.commit()
            except:
                self.db.rollback()


    def db_sanitize(self, value):
        value = str(value)
        value = value.replace('\\', "")
        value = value.replace("\0", "")
        value = value.replace("\n", "")
        value = value.replace("\r", "")
        value = value.replace("'", "")
        value = value.replace('"', "")
        value = value.replace("\x1a", "")
        return value


    def db_init(self, init=True):
       pass


    def db_migrate(self):
        pass


    def db_indices(self):
        pass


    def db_load(self,):
        pass


    def db_member_filter(self, filter):
        if filter == None:
            return ""

        querys = []

        if "display_name" in filter and filter["display_name"] != None:
            querys.append("devices.device_display_name ILIKE '%"+self.db_sanitize(filter["display_name"])+"%'")

        if "city" in filter and filter["city"] != None:
            querys.append("members.member_city ILIKE '%"+self.db_sanitize(filter["city"])+"%'")

        if "country" in filter and filter["country"] != None:
            querys.append("members.member_country = '"+self.db_sanitize(filter["country"])+"'")

        if "state" in filter and filter["state"] != None:
            querys.append("members.member_state = '"+self.db_sanitize(filter["state"])+"'")

        if "occupation" in filter and filter["occupation"] != None:
            querys.append("members.member_occupation ILIKE '%"+self.db_sanitize(filter["occupation"])+"%'")

        if "skills" in filter and filter["skills"] != None:
            querys.append("members.member_skills ILIKE '%"+self.db_sanitize(filter["skills"])+"%'")

        if "tasks" in filter and filter["tasks"] != None:
            querys.append("members.member_tasks ILIKE '%"+self.db_sanitize(filter["tasks"])+"%'")

        if "wallet_address" in filter and filter["wallet_address"] != None:
            querys.append("members.member_wallet_address ILIKE '%"+self.db_sanitize(filter["wallet_address"])+"%'")

        if "type" in filter and filter["type"] != None:
            if isinstance(filter["type"], int):
                querys.append("members.member_type = '"+self.db_sanitize(filter["type"])+"'")
            else:
                array = [self.db_sanitize(key) for key in filter["type"]]
                querys.append("(members.member_type = '"+"' OR members.member_type = '".join(array)+"')")

        if "auth_role" in filter and filter["auth_role"] != None:
            querys.append("members.member_auth_role = '"+self.db_sanitize(filter["auth_role"])+"'")

        if "ts_min" in filter and filter["ts_min"] != None:
            querys.append("members.member_ts_add >= "+datetime.datetime.fromtimestamp(filter["ts_min"]).strftime('%Y-%m-%d %H:%M:%S'))

        if "ts_max" in filter and filter["ts_max"] != None:
            querys.append("members.member_ts_add <= "+datetime.datetime.fromtimestamp(filter["ts_max"]).strftime('%Y-%m-%d %H:%M:%S'))

        if len(querys) > 0:
            query = " AND "+" AND ".join(querys)
        else:
            query = ""

        return query


    def db_member_order(self, order):
        if order == "A-ASC":
            query = " ORDER BY devices.device_display_name ASC"
        elif order == "A-DESC":
            query = " ORDER BY devices.device_display_name DESC"
        elif order == "ASC":
            query = " ORDER BY members.member_ts_add ASC, devices.device_display_name ASC"
        elif order == "DESC":
            query = " ORDER BY members.member_ts_add DESC, devices.device_display_name ASC"
        else:
            query = ""

        return query


    def db_member_list(self, filter=None, search=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_member_filter(filter)

        query_order = self.db_member_order(order)

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT members.member_city, members.member_state, members.member_country, members.member_occupation, members.member_skills, members.member_tasks, members.member_wallet_address, members.member_auth_role, members.member_ts_add, members.member_ts_edit, devices.device_rns_id, devices.device_display_name FROM members LEFT JOIN devices ON devices.device_user_id = members.member_user_id WHERE members.member_user_id != '' AND (devices.device_display_name ILIKE %s OR members.member_city ILIKE %s OR members.member_occupation ILIKE %s OR members.member_skills ILIKE %s OR members.member_tasks ILIKE %s)"+query_filter+query_order+query_limit
            dbc.execute(query, (search, search, search, search, search))
        else:
            query = "SELECT members.member_city, members.member_state, members.member_country, members.member_occupation, members.member_skills, members.member_tasks, members.member_wallet_address, members.member_auth_role, members.member_ts_add, members.member_ts_edit, devices.device_rns_id, devices.device_display_name FROM members LEFT JOIN devices ON devices.device_user_id = members.member_user_id WHERE members.member_user_id != ''"+query_filter+query_order+query_limit
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                if entry[10]:
                    data.append({
                        "city": entry[0].strip(),
                        "state": entry[1].strip(),
                        "country": entry[2].strip(),
                        "occupation": entry[3].strip(),
                        "skills": entry[4].strip(),
                        "tasks": entry[5].strip(),
                        "wallet_address": entry[6].strip(),
                        "auth_role": int(entry[7].strip()),
                        "ts_add": entry[8].timestamp(),
                        "ts_edit": entry[9].timestamp(),
                        "dest": bytes.fromhex(entry[10].strip()),
                        "display_name": entry[11].strip()
                    })

            return data


    def db_member_count(self, filter=None, search=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_member_filter(filter)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(*) FROM members LEFT JOIN devices ON devices.device_user_id = members.member_user_id WHERE members.member_user_id != '' AND (devices.device_display_name ILIKE %s OR members.member_city ILIKE %s OR members.member_occupation ILIKE %s OR members.member_skills ILIKE %s OR members.member_tasks ILIKE %s)"+query_filter
            dbc.execute(query, (search, search, search, search, search))
        else:
            query = "SELECT COUNT(*) FROM members WHERE member_user_id != ''"+query_filter
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_member_get(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "SELECT members.member_city, members.member_state, members.member_country, members.member_occupation, members.member_skills, members.member_tasks, members.member_wallet_address, members.member_auth_role, members.member_ts_add, members.member_ts_edit, devices.device_rns_id, devices.device_display_name FROM members LEFT JOIN devices ON devices.device_user_id = members.member_user_id WHERE devices.device_rns_id = %s"
        dbc.execute(query, (RNS.hexrep(dest, False),))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            entry = result[0]
            data = {
                "city": entry[0].strip(),
                "state": entry[1].strip(),
                "country": entry[2].strip(),
                "occupation": entry[3].strip(),
                "skills": entry[4].strip(),
                "tasks": entry[5].strip(),
                "wallet_address": entry[6].strip(),
                "auth_role": int(entry[7].strip()),
                "ts_add": entry[8].timestamp(),
                "ts_edit": entry[9].timestamp(),
                "dest": bytes.fromhex(entry[10].strip()),
                "display_name": entry[11].strip()
            }
            return data


    def db_member_set(self, dest, role=None, state=None):
        db = self.db_connect()
        dbc = db.cursor()

        if role != None:
            query = "UPDATE members SET member_ts_edit = %s, member_auth_role = %s, member_update = '1' WHERE member_user_id = (SELECT device_user_id FROM devices WHERE device_rns_id = %s)"
            dbc.execute(query, (datetime.datetime.now(datetime.timezone.utc), str(role), RNS.hexrep(dest, False)))

        if state != None:
            query = "UPDATE members SET member_ts_edit = %s, member_auth_state = %s, member_update = '1' WHERE member_user_id = (SELECT device_user_id FROM devices WHERE device_rns_id = %s)"
            dbc.execute(query, (datetime.datetime.now(datetime.timezone.utc), str(state), RNS.hexrep(dest, False)))

        self.db_commit()


    def db_member_delete(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "SELECT device_user_id FROM devices WHERE device_rns_id = %s"
        dbc.execute(query, (RNS.hexrep(dest, False),))
        result = dbc.fetchall()

        if len(result) == 1:
            query = "DELETE FROM devices WHERE device_user_id = %s"
            dbc.execute(query, (result[0][0],))

            query = "DELETE FROM members WHERE member_user_id = %s"
            dbc.execute(query, (result[0][0],))

        self.db_commit()


    def db_service_filter(self, filter):
        if filter == None:
            return ""

        querys = []

        if "display_name" in filter and filter["display_name"] != None:
            querys.append("services.service_display_name ILIKE '%"+self.db_sanitize(filter["display_name"])+"%'")

        if "city" in filter and filter["city"] != None:
            querys.append("services.service_city ILIKE '%"+self.db_sanitize(filter["city"])+"%'")

        if "country" in filter and filter["country"] != None:
            querys.append("services.service_country = '"+self.db_sanitize(filter["country"])+"'")

        if "state" in filter and filter["state"] != None:
            querys.append("services.service_state = '"+self.db_sanitize(filter["state"])+"'")

        if "type" in filter and filter["type"] != None:
            if isinstance(filter["type"], int):
                querys.append("services.service_type = '"+self.db_sanitize(filter["type"])+"'")
            else:
                array = [self.db_sanitize(key) for key in filter["type"]]
                querys.append("(services.service_type = '"+"' OR services.service_type = '".join(array)+"')")

        if "auth_role" in filter and filter["auth_role"] != None:
            querys.append("services.service_auth_role = '"+self.db_sanitize(filter["auth_role"])+"'")

        if "ts_min" in filter and filter["ts_min"] != None:
            querys.append("services.service_ts_add >= "+datetime.datetime.fromtimestamp(filter["ts_min"]).strftime('%Y-%m-%d %H:%M:%S'))

        if "ts_max" in filter and filter["ts_max"] != None:
            querys.append("services.service_ts_add <= "+datetime.datetime.fromtimestamp(filter["ts_max"]).strftime('%Y-%m-%d %H:%M:%S'))

        if len(querys) > 0:
            query = " AND "+" AND ".join(querys)
        else:
            query = ""

        return query


    def db_service_order(self, order):
        if order == "A-ASC":
            query = " ORDER BY services.service_display_name ASC"
        elif order == "A-DESC":
            query = " ORDER BY services.service_display_name DESC"
        elif order == "ASC":
            query = " ORDER BY services.service_ts_add ASC, services.service_display_name ASC"
        elif order == "DESC":
            query = " ORDER BY services.service_ts_add DESC, services.service_display_name ASC"
        else:
            query = ""

        return query


    def db_service_list(self, filter=None, search=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_service_filter(filter)

        query_order = self.db_service_order(order)

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT services.service_rns_id, services.service_display_name, services.service_country, services.service_state, services.service_city, services.service_type, services.service_auth_role, services.service_ts_add, services.service_ts_edit FROM services WHERE services.service_rns_id != '' AND (services.service_display_name ILIKE %s OR services.service_city ILIKE %s)"+query_filter+query_order+query_limit
            dbc.execute(query, (search, search))
        else:
            query = "SELECT services.service_rns_id, services.service_display_name, services.service_country, services.service_state, services.service_city, services.service_type, services.service_auth_role, services.service_ts_add, services.service_ts_edit FROM services WHERE services.service_rns_id != ''"+query_filter+query_order+query_limit
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                data.append({
                    "dest": bytes.fromhex(entry[0].strip()),
                    "display_name": entry[1].strip(),
                    "country": entry[2].strip(),
                    "state": entry[3].strip(),
                    "city": entry[4].strip(),
                    "type": entry[5].strip(),
                    "auth_role": int(entry[6].strip()),
                    "ts_add": entry[7].timestamp(),
                    "ts_edit": entry[8].timestamp(),
                })

            return data


    def db_service_count(self, filter=None, search=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_service_filter(filter)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(*) FROM services WHERE services.service_rns_id != '' AND (services.service_display_name ILIKE %s OR services.service_city ILIKE %s)"+query_filter
            dbc.execute(query, (search, search))
        else:
            query = "SELECT COUNT(*) FROM services WHERE services.service_rns_id != ''"+query_filter
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_service_get(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "SELECT services.service_rns_id, services.service_display_name, services.service_country, services.service_state, services.service_city, services.service_type, services.service_auth_role, services.service_ts_add, services.service_ts_edit FROM services WHERE services.service_rns_id = %s"
        dbc.execute(query, (RNS.hexrep(dest, False),))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            entry = result[0]
            data = {
                "dest": bytes.fromhex(entry[0].strip()),
                "display_name": entry[1].strip(),
                "country": entry[2].strip(),
                "state": entry[3].strip(),
                "city": entry[4].strip(),
                "type": entry[5].strip(),
                "auth_role": int(entry[6].strip()),
                "ts_add": entry[7].timestamp(),
                "ts_edit": entry[8].timestamp(),
            }
            return data


    def db_service_delete(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "DELETE FROM services WHERE service_rns_id = %s"
        dbc.execute(query, (RNS.hexrep(dest, False),))

        self.db_commit()


    def execute(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return None

        # Temporary debug output
        print("---- execute ----")
        print("Dict received: "+str(data))

        data_return = {}

        if remote_identity:
            hash_destination = RNS.hexrep(RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity), delimit=False)
            hash_identity = ""
        else:
            data_return["result"] = Provisioning.RESULT_NO_IDENTITY
            return msgpack.packb(data_return)

        db = None
        try:
            db = psycopg2.connect(user=self.config["database"]["user"], password=self.config["database"]["password"], host=self.config["database"]["host"], port=self.config["database"]["port"], database=self.config["database"]["database"], client_encoding=self.config["database"]["encoding"])
            dbc = db.cursor()

            data_return["result"] = ServerProvisioning.RESULT_OK
            data_return["result_uids"] = []

            for data_uid, data in data.items():
                try:
                    if "type" not in data:
                        continue
                    if data["type"] == "":
                        continue

                    data["hash_destination"] = hash_destination
                    data["hash_identity"] = hash_identity
                    data["timestamp_client"] = time.time()
                    data["timestamp_server"] = time.time()

                    if "password" in data:
                        data["password"] = str(base64.b32encode(data["password"]))

                    RNS.log("-> Execute", LOG_EXTREME)
                    RNS.log(data, LOG_EXTREME)

                    if data["type"] == "account":
                        # members
                        dbc.execute("SELECT member_user_id FROM members WHERE member_email = %s AND member_password = %s", (data["email"], data["password"]))
                        result = dbc.fetchall()
                        if len(result) == 0:
                            if not self.config["features"].getboolean("account_add"):
                                continue
                            user_id = str(uuid.uuid4())
                            dbc.execute("INSERT INTO members (member_user_id, member_email, member_password, member_dob, member_sex, member_introduction, member_country, member_state, member_city, member_occupation, member_skills, member_tasks, member_wallet_address, member_accept_rules, member_language, member_locale, member_ts_add, member_ts_edit, member_auth_state, member_auth_role, member_update) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, '0', '0', '0')", (
                                user_id,
                                data["email"],
                                data["password"],
                                data["dob"],
                                data["sex"],
                                data["introduction"],
                                data["country"],
                                data["state"],
                                data["city"],
                                data["occupation"],
                                data["skills"],
                                data["tasks"],
                                data["wallet_address"],
                                data["accept_rules"],
                                data["language"],
                                data["language"],
                                datetime.now(timezone.utc),
                                datetime.now(timezone.utc)
                                )
                            )
                            if self.config["features"].getboolean("account_add_auth"):
                                data_return["auth_state"] = self.config["features"].getint("account_add_auth_state")
                                data_return["auth_role"] = self.config["features"].getint("account_add_auth_role")
                        elif len(result) == 1:
                            if not self.config["features"].getboolean("account_edit"):
                                continue
                            user_id = result[0][0]
                            dbc.execute("UPDATE members SET member_email = %s, member_password = %s, member_dob = %s, member_sex = %s, member_introduction = %s, member_country = %s, member_state = %s, member_city = %s, member_occupation = %s, member_skills = %s, member_tasks = %s, member_wallet_address = %s, member_accept_rules = %s, member_language = %s, member_locale = %s, member_ts_edit = %s WHERE member_user_id = %s", (
                                data["email"],
                                data["password"],
                                data["dob"],
                                data["sex"],
                                data["introduction"],
                                data["country"],
                                data["state"],
                                data["city"],
                                data["occupation"],
                                data["skills"],
                                data["tasks"],
                                data["wallet_address"],
                                data["accept_rules"],
                                data["language"],
                                data["language"],
                                datetime.now(timezone.utc),
                                user_id
                                )
                            )
                            if self.config["features"].getboolean("account_edit_auth"):
                                data_return["auth_state"] = self.config["features"].getint("account_edit_auth_state")
                                data_return["auth_role"] = self.config["features"].getint("account_edit_auth_role")
                        else:
                            continue

                        # devices
                        dbc.execute("DELETE FROM devices WHERE device_id = %s OR device_rns_id = %s", (data["device_id"], data["hash_destination"]))
                        dbc.execute("INSERT INTO devices (device_id, device_user_id, device_name, device_display_name, device_rns_id) VALUES (%s, %s, %s, %s, %s)", (
                            data["device_id"],
                            user_id,
                            data["device_name"],
                            data["device_display_name"],
                            data["hash_destination"]
                            )
                        )

                        db.commit()
                        data_return["result_uids"].append(data_uid)

                    if data["type"] == "prove" and self.config["features"].getboolean("account_prove"):
                        dbc.execute("SELECT device_user_id FROM devices LEFT JOIN members ON members.member_user_id = devices.device_user_id WHERE devices.device_rns_id = %s and members.member_auth_state = '1'", (data["hash_destination"], ))
                        result = dbc.fetchall()
                        if len(result) == 1:
                            source_user_id = result[0][0]
                            dbc.execute("SELECT device_user_id FROM devices WHERE device_rns_id = %s", (data["prove"], ))
                            result = dbc.fetchall()
                            if len(result) == 1:
                                destination_user_id = result[0][0]
                                dbc.execute("INSERT INTO proves (prove_source_user_id, prove_destination_user_id) VALUES (%s, %s)", (source_user_id, destination_user_id))
                                dbc.execute("SELECT member_auth_state FROM members WHERE member_user_id = %s AND member_auth_state = '0'", (destination_user_id, ))
                                result = dbc.fetchall()
                                if len(result) == 1:
                                    dbc.execute("SELECT * FROM proves WHERE prove_destination_user_id = %s", (destination_user_id,))
                                    result = dbc.fetchall()
                                    if len(result) >= 2:
                                        dbc.execute("UPDATE members SET member_auth_state = '1' WHERE member_user_id = %s AND member_auth_state = '0'", (destination_user_id,))

                                db.commit()
                                data_return["result_uids"].append(data_uid)

                except psycopg2.DatabaseError as e:
                    RNS.log("Loop - DB - Error: "+str(e), LOG_ERROR)
                    db.rollback()
                    data_return["result"] = ServerProvisioning.RESULT_ERROR

        except psycopg2.DatabaseError as e:
            RNS.log("DB - Error: "+str(e), LOG_ERROR)
            db.rollback()
            data_return["result"] = ServerProvisioning.RESULT_ERROR

        if db:
            dbc.close()
            db.close()
            db = None

        # Temporary debug output
        print("Dict send: "+str(data_return))

        data_return = msgpack.packb(data_return)

        return data_return


    def directory_member(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return None

        # Temporary debug output
        print("---- directory_member ----")
        print("Dict received: "+str(data))

        data_return = {}

        if remote_identity:
            hash_destination = RNS.hexrep(RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity), delimit=False)
            hash_identity = ""
        else:
            data_return["result"] = Provisioning.RESULT_NO_IDENTITY
            return msgpack.packb(data_return)

        if "cmd" in data:
            if hash_destination in self.admins:
                if cmd[0] == "role_0":
                    self.db_member_set(cmd[1], role=0)
                if cmd[0] == "role_1":
                    self.db_member_set(cmd[1], role=1)
                if cmd[0] == "role_2":
                    self.db_member_set(cmd[1], role=2)
                if cmd[0] == "role_3":
                    self.db_member_set(cmd[1], role=3)
                if cmd[0] == "state_0":
                    self.db_member_set(cmd[1], state=0)
                if cmd[0] == "state_1":
                    self.db_member_set(cmd[1], state=1)
                if cmd[0] == "state_2":
                    self.db_member_set(cmd[1], state=2)
                if cmd[0] == "delete":
                    self.db_member_delete(cmd[1])
                entry = self.db_member_get(cmd[1])
                if entry:
                    return data_return.update({"cmd_result": ServerProvisioning.RESULT_OK, "rx_entrys": [entry]})
                else:
                    return data_return.update({"cmd_result": ServerProvisioning.RESULT_OK, "rx_entrys": [{"dest": cmd[1], "ts_edit": 0}]})
        else:
            data_return["rx_entrys"] = []
            data_return["rx_entrys_count"] = self.db_member_count(filter=data["filter"], search=data["search"])

            for entry in self.db_member_list(filter=data["filter"], search=data["search"], order=data["order"], limit=data["limit"], limit_start=data["limit_start"]):
                if entry["dest"] in data["entrys"]:
                    if entry["ts_edit"] > data["entrys"][entry["dest"]]:
                        data_return["rx_entrys"].append(entry)
                    del data["entrys"][entry["dest"]]
                else:
                   data_return["rx_entrys"].append(entry)

            for dest in data["entrys"]:
                entry = self.db_member_get(dest=dest)
                if entry:
                    if entry["ts_edit"] > data["entrys"][dest]:
                        data_return["rx_entrys"].append(entry)
                else:
                    data_return["rx_entrys"].append({"dest": dest, "ts_edit": 0})

            if len(data_return["rx_entrys"]) == 0:
                del data_return["rx_entrys"]

            if hash_destination in self.admins:
                data_return["cmd"] = []
                data_return["cmd_entry"] = ["role_0", "role_1", "role_2", "role_3", "state_0", "state_1", "state_2", "delete"]

        # Temporary debug output
        print("Dict send: "+str(data_return))

        data_return = msgpack.packb(data_return)

        return data_return


    def directory_service(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return None

        # Temporary debug output
        print("---- directory_service ----")
        print("Dict received: "+str(data))

        data_return = {}

        if remote_identity:
            hash_destination = RNS.hexrep(RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity), delimit=False)
            hash_identity = ""
        else:
            data_return["result"] = Provisioning.RESULT_NO_IDENTITY
            return msgpack.packb(data_return)

        if "cmd" in data:
            if hash_destination in self.admins:
                if cmd[0] == "delete":
                    self.db_service_delete(cmd[1])
                entry = self.db_service_get(cmd[1])
                if entry:
                    data_return.update({"cmd_result": ServerProvisioning.RESULT_OK, "rx_entrys": [entry]})
                else:
                    data_return.update({"cmd_result": ServerProvisioning.RESULT_OK, "rx_entrys": [{"dest": cmd[1], "ts_edit": 0}]})
        else:
            data_return["rx_entrys"] = []
            data_return["rx_entrys_count"] = self.db_service_count(filter=data["filter"], search=data["search"])

            for entry in self.db_service_list(filter=data["filter"], search=data["search"], order=data["order"], limit=data["limit"], limit_start=data["limit_start"]):
                if entry["dest"] in data["entrys"]:
                    if entry["ts_edit"] > data["entrys"][entry["dest"]]:
                        data_return["rx_entrys"].append(entry)
                    del data["entrys"][entry["dest"]]
                else:
                   data_return["rx_entrys"].append(entry)

            for dest in data["entrys"]:
                entry = self.db_service_get(dest=dest)
                if entry:
                    if entry["ts_edit"] > data["entrys"][dest]:
                        data_return["rx_entrys"].append(entry)
                else:
                    data_return["rx_entrys"].append({"dest": dest, "ts_edit": 0})

            if len(data_return["rx_entrys"]) == 0:
                del data_return["rx_entrys"]

            if hash_destination in self.admins:
                data_return["cmd"] = []
                data_return["cmd_entry"] = []

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

    display_name = CONFIG["rns_server"]["display_name"]
    announce_data = None
    if CONFIG["features"].getboolean("announce_data"):
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
                announce_data = {ANNOUNCE_DATA_CONTENT: CONFIG["rns_server"]["display_name"].encode("utf-8"), ANNOUNCE_DATA_TITLE: None, ANNOUNCE_DATA_FIELDS: {MSG_FIELD_TYPE_FIELDS: type_fields}}
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
        config=CONFIG,
        admins=admins
    )

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


[features]
announce_data = True

account_add = True
account_add_auth = True
account_add_auth_state = 1
account_add_auth_role = 3

account_edit = True
account_edit_auth = False
account_edit_auth_state = 1
account_edit_auth_role = 3

account_del = False

account_prove = False
account_prove_auth = True
account_prove_auth_state = 1
account_prove_auth_role = 3

telemetry = False


[admins]


[data]
v_s = 0.0.0 #Version software
u_s = #URL Software
i_s = #Info Software
cmd = #CMD
config = #Config
config_lxm = #Config as lxm string
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


#### Database connection settings ####
[database]

host = 127.0.0.1
port = 5432
user = postgres
password = password
database = database
encoding = utf8


#### Features enabled/disabled ####
[features]

announce_data = True

account_add = True
account_add_auth = False
account_add_auth_state = 1
account_add_auth_role = 3

account_edit = True
account_edit_auth = False
account_edit_auth_state = 1
account_edit_auth_role = 3

account_del = True

account_prove = False
account_prove_auth = False
account_prove_auth_state = 1
account_prove_auth_role = 3

telemetry = False


#### Admin users ####
# Source addresses/hashs
[admins]
#2858b7a096899116cd529559cc679ffe


#### Data settings ####
[data]

v_s = 0.0.0 #Version software
u_s = #URL Software
i_s = #Info Software
cmd = #CMD
config = #Config
config_lxm = #Config as lxm string
'''


##############################################################################################################
# Init


if __name__ == "__main__":
    main()