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

#### Database - PostgreSQL ####
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
# ServerProvisioning Class


class ServerProvisioning:
    CONNECTION_TIMEOUT = 10 # Seconds

    JOBS_PERIODIC_DELAY    = 10 # Seconds
    JOBS_PERIODIC_INTERVAL = 60 # Seconds

    KEY_RESULT        = 0x0A # Result
    KEY_RESULT_REASON = 0x0B # Result - Reason
    KEY_A             = 0x0C # Account
    KEY_D             = 0x0D # Directory
    KEY_S             = 0x0E # Service
    KEY_T             = 0x0F # Transaction
    KEY_TA            = 0x10 # Task

    KEY_A_DATA         = 0x00

    KEY_A_MAPPING = {
        "data": KEY_A_DATA,
    }

    KEY_D_CMD                    = 0x00
    KEY_D_CMD_ENTRY              = 0x01
    KEY_D_CMD_RESULT             = 0x02
    KEY_D_ENTRYS                 = 0x03
    KEY_D_FILTER                 = 0x04
    KEY_D_GROUP                  = 0x05
    KEY_D_LIMIT                  = 0x06
    KEY_D_LIMIT_START            = 0x07
    KEY_D_ORDER                  = 0x08
    KEY_D_RX_ENTRYS              = 0x09
    KEY_D_RX_ENTRYS_COUNT        = 0x0A
    KEY_D_RX_GROUP_ENTRYS        = 0x0B
    KEY_D_RX_GROUP_ENTRYS_COUNT  = 0x0C
    KEY_D_SEARCH                 = 0x0D

    KEY_D_MAPPING = {
    }

    KEY_D_ENTRYS_AUTH_ROLE      = 0x00
    KEY_D_ENTRYS_CITY           = 0x01
    KEY_D_ENTRYS_COUNT          = 0x02
    KEY_D_ENTRYS_COUNTRY        = 0x03
    KEY_D_ENTRYS_DATA           = 0x04
    KEY_D_ENTRYS_DEST           = 0x05
    KEY_D_ENTRYS_DISPLAY_NAME   = 0x06
    KEY_D_ENTRYS_HOP_COUNT      = 0x07
    KEY_D_ENTRYS_LOCATION_LAT   = 0x08
    KEY_D_ENTRYS_LOCATION_LON   = 0x09
    KEY_D_ENTRYS_OCCUPATION     = 0x0A
    KEY_D_ENTRYS_OWNER          = 0x0B
    KEY_D_ENTRYS_SHOP_GOODS     = 0x0C
    KEY_D_ENTRYS_SHOP_SERVICES  = 0x0D
    KEY_D_ENTRYS_SKILLS         = 0x0E
    KEY_D_ENTRYS_STATE          = 0x0F
    KEY_D_ENTRYS_STATE_TS       = 0x10
    KEY_D_ENTRYS_TS             = 0x11
    KEY_D_ENTRYS_TS_ADD         = 0x12
    KEY_D_ENTRYS_TS_EDIT        = 0x13
    KEY_D_ENTRYS_TYPE           = 0x14

    KEY_D_ENTRYS_MAPPING = {
        "auth_role":     KEY_D_ENTRYS_AUTH_ROLE,
        "city":          KEY_D_ENTRYS_CITY,
        "count":         KEY_D_ENTRYS_COUNT,
        "country":       KEY_D_ENTRYS_COUNTRY,
        "data":          KEY_D_ENTRYS_DATA,
        "dest":          KEY_D_ENTRYS_DEST,
        "display_name":  KEY_D_ENTRYS_DISPLAY_NAME,
        "hop_count":     KEY_D_ENTRYS_HOP_COUNT,
        "location_lat":  KEY_D_ENTRYS_LOCATION_LAT,
        "location_lon":  KEY_D_ENTRYS_LOCATION_LON,
        "occupation":    KEY_D_ENTRYS_OCCUPATION,
        "owner":         KEY_D_ENTRYS_OWNER,
        "shop_goods":    KEY_D_ENTRYS_SHOP_GOODS,
        "shop_services": KEY_D_ENTRYS_SHOP_SERVICES,
        "skills":        KEY_D_ENTRYS_SKILLS,
        "state":         KEY_D_ENTRYS_STATE,
        "state_ts":      KEY_D_ENTRYS_STATE_TS,
        "ts":            KEY_D_ENTRYS_TS,
        "ts_add":        KEY_D_ENTRYS_TS_ADD,
        "ts_edit":       KEY_D_ENTRYS_TS_EDIT,
        "type":          KEY_D_ENTRYS_TYPE,
    }

    KEY_S_MAPPING = {
    }

    KEY_T_DATA         = 0x00
    KEY_T_ID           = 0x01
    KEY_T_STATE        = 0x02
    KEY_T_STATE_REASON = 0x03
    KEY_T_TS           = 0x04
    KEY_T_TYPE         = 0x05

    KEY_T_MAPPING = {
        "data":         KEY_T_DATA,
        "id":           KEY_T_ID,
        "state":        KEY_T_STATE,
        "state_reason": KEY_T_STATE_REASON,
        "ts":           KEY_T_TS,
        "type":         KEY_T_TYPE,
    }

    KEY_TA_MAPPING = {
    }

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

    SERVICE_STATE_FAILED      = 0x00 # Failed
    SERVICE_STATE_SUCCESSFULL = 0x01 # Successfull
    SERVICE_STATE_WAITING     = 0x02 # Waiting in local cache
    SERVICE_STATE_SYNCING     = 0x03 # Syncing/Transfering to server
    SERVICE_STATE_PROCESSING  = 0x04 # Processing/Execution on the server
    SERVICE_STATE_FAILED_TMP  = 0x05 # Temporary failed

    STATE_NO_PATH            = 0x00
    STATE_PATH_REQUESTED     = 0x01
    STATE_ESTABLISHING_LINK  = 0x02
    STATE_LINK_TIMEOUT       = 0x03
    STATE_LINK_ESTABLISHED   = 0x04
    STATE_REQUESTING         = 0x05
    STATE_REQUEST_SENT       = 0x06
    STATE_REQUEST_FAILED     = 0x07
    STATE_REQUEST_TIMEOUT    = 0x08
    STATE_RECEIVING_RESPONSE = 0x09
    STATE_TRANSFERRING       = 0x0A
    STATE_DISCONECTED        = 0xFD
    STATE_DONE               = 0xFF

    TRANSACTION_STATE_FAILED      = 0x00 # Failed
    TRANSACTION_STATE_SUCCESSFULL = 0x01 # Successfull
    TRANSACTION_STATE_WAITING     = 0x02 # Waiting in local cache
    TRANSACTION_STATE_SYNCING     = 0x03 # Syncing/Transfering to server
    TRANSACTION_STATE_PROCESSING  = 0x04 # Processing/Execution on the server
    TRANSACTION_STATE_FAILED_TMP  = 0x05 # Temporary failed

    TRANSACTION_TYPE_ACCOUNT_CREATE  = 0x00
    TRANSACTION_TYPE_ACCOUNT_EDIT    = 0x01
    TRANSACTION_TYPE_ACCOUNT_PROVE   = 0x02
    TRANSACTION_TYPE_ACCOUNT_RESTORE = 0x03
    TRANSACTION_TYPE_SERVICE_CREATE  = 0x04
    TRANSACTION_TYPE_SERVICE_EDIT    = 0x05
    TRANSACTION_TYPE_SERVICE_DELETE  = 0x06

    TYPE_DIRECTORY_ANNOUNCE = 0x00
    TYPE_DIRECTORY_MEMBER   = 0x01
    TYPE_DIRECTORY_SERVICE  = 0x02
    TYPE_SYNC               = 0x03
    TYPE_UNKNOWN            = 0xFF


    def __init__(self, storage_path=None, identity_file="identity", identity=None, destination_name="nomadnetwork", destination_type="provisioning", destination_conv_name="lxmf", destination_conv_type="delivery", destination_mode=True, announce_startup=False, announce_startup_delay=0, announce_periodic=False, announce_periodic_interval=360, announce_data="", announce_hidden=False, register_startup=True, register_startup_delay=0, register_periodic=True, register_periodic_interval=30, config=None, admins=[], limiter_server_enabled=False, limiter_server_calls=1000, limiter_server_size=0, limiter_server_duration=60, limiter_peer_enabled=True, limiter_peer_calls=30, limiter_peer_size=0, limiter_peer_duration=60):
        self.storage_path = storage_path

        self.identity_file = identity_file
        self.identity = identity

        self.destination_name = destination_name
        self.destination_type = destination_type
        self.aspect_filter = self.destination_name + "." + self.destination_type
        self.destination_conv_name = destination_conv_name
        self.destination_conv_type = destination_conv_type
        self.aspect_filter_conv = self.destination_conv_name + "." + self.destination_conv_type
        self.destination_mode = destination_mode

        self.announce_startup = announce_startup
        self.announce_startup_delay = int(announce_startup_delay)
        if self.announce_startup_delay == 0:
            self.announce_startup_delay = random.randint(5, 30)

        self.announce_periodic = announce_periodic
        self.announce_periodic_interval = int(announce_periodic_interval)

        self.announce_data = announce_data
        self.announce_hidden = announce_hidden

        self.register_startup = register_startup
        self.register_startup_delay = int(register_startup_delay)

        self.register_periodic = register_periodic
        self.register_periodic_interval = int(register_periodic_interval)

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

        self.db = None
        self.db_load()

        if limiter_server_enabled:
            self.limiter_server = RateLimiter(int(limiter_server_calls), int(limiter_server_size), int(limiter_server_duration))
        else:
            self.limiter_server = None

        if limiter_peer_enabled:
            self.limiter_peer = RateLimiter(int(limiter_peer_calls), int(limiter_peer_size), int(limiter_peer_duration))
        else:
            self.limiter_peer = None


    def files_config(self, enabled=True, path="files", ext_allow=[], ext_deny=[], allow_all=True, allow=[], deny=[]):
        self.files = []
        self.files_enabled = enabled
        self.files_path = path
        self.files_ext_allow = ext_allow
        self.files_ext_deny = ext_deny
        self.files_ext_deny.append("allowed")
        self.files_allow_all = allow_all
        self.files_allow = allow
        self.files_deny = deny


    def start(self):
        if self.announce_startup or self.announce_periodic:
            self.announce(initial=True)

        if self.files_enabled:
            if not self.files_path.startswith("/") and self.storage_path:
                self.files_path = self.storage_path + "/" + self.files_path
            if not os.path.isdir(self.files_path):
                os.makedirs(selffiles_path)
                RNS.log("Server - Files: Path was created", RNS.LOG_NOTICE)
            RNS.log("Server - Files: Path: " + self.files_path, RNS.LOG_INFO)

        if self.register_startup or self.register_periodic:
            self.register(True)


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


    def register(self, initial=False):
        if self.register_periodic and self.register_periodic_interval > 0:
            register_timer = threading.Timer(self.register_periodic_interval*60, self.register)
            register_timer.daemon = True
            register_timer.start()

        if initial:
            if self.register_startup:
                if self.register_startup_delay > 0:
                    register_timer.cancel()
                    register_timer = threading.Timer(self.register_startup_delay, self.register)
                    register_timer.daemon = True
                    register_timer.start()
                else:
                    self.register_now()
            return

        self.register_now()


    def register_now(self):
        RNS.log("Server - Register", RNS.LOG_DEBUG)

        self.destination.register_request_handler("directory_announce", response_generator=self.response_directory_announce, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("directory_member", response_generator=self.response_directory_member, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("directory_service", response_generator=self.response_directory_service, allow=RNS.Destination.ALLOW_ALL)
        self.destination.register_request_handler("sync", response_generator=self.response_sync, allow=RNS.Destination.ALLOW_ALL)

        if self.files_enabled:
            self.files_register()


    def peer_connected(self, link):
        RNS.log("Server - Peer connected to "+str(self.destination), RNS.LOG_VERBOSE)

        link.set_link_closed_callback(self.peer_disconnected)
        link.set_remote_identified_callback(self.peer_identified)


    def peer_disconnected(self, link):
        RNS.log("Server - Peer disconnected from "+str(self.destination), RNS.LOG_VERBOSE)


    def peer_identified(self, link, identity):
        if not identity:
            link.teardown()


    #################################################
    # Database                                      #
    #################################################


    def db_connect(self):
        try:
            if self.db == None:
                self.db = psycopg2.connect(user=self.config["database"]["user"], password=self.config["database"]["password"], host=self.config["database"]["host"], port=self.config["database"]["port"], database=self.config["database"]["database"], client_encoding=self.config["database"]["encoding"], connect_timeout=5)
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
        db = self.db_connect()
        dbc = db.cursor()

        if init:
            dbc.execute("DROP TABLE IF EXISTS public.announces")
        dbc.execute("""CREATE TABLE IF NOT EXISTS public.announces(dest character(32) COLLATE pg_catalog."default" NOT NULL, type integer NOT NULL DEFAULT 0, data text COLLATE pg_catalog."default" DEFAULT ''::text, location_lat double precision DEFAULT 0, location_lon double precision DEFAULT 0, owner character(32) COLLATE pg_catalog."default", state integer DEFAULT 0, state_ts timestamp with time zone, hop_count integer DEFAULT 0, hop_interface text COLLATE pg_catalog."default" DEFAULT ''::text, hop_dest character(32) COLLATE pg_catalog."default", ts_add timestamp with time zone, ts_edit timestamp with time zone, CONSTRAINT announces_pkey PRIMARY KEY (dest, type))""")

        if init:
            dbc.execute("DROP TABLE IF EXISTS public.devices")
        dbc.execute("""CREATE TABLE IF NOT EXISTS public.devices(device_id character(100) COLLATE pg_catalog."default" NOT NULL, device_user_id character(100) COLLATE pg_catalog."default", device_name character(256) COLLATE pg_catalog."default", device_display_name character(256) COLLATE pg_catalog."default", device_rns_id character(100) COLLATE pg_catalog."default", device_did_hash character(100) COLLATE pg_catalog."default", device_status character(1) COLLATE pg_catalog."default", CONSTRAINT devices_pkey PRIMARY KEY (device_id), CONSTRAINT devices_device_user_id_fkey FOREIGN KEY (device_user_id) REFERENCES public.members (member_user_id) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION)""")

        if init:
            dbc.execute("DROP TABLE IF EXISTS public.members")
        dbc.execute("""CREATE TABLE IF NOT EXISTS public.members(member_user_id character(100) COLLATE pg_catalog."default" NOT NULL, member_user_name character(100) COLLATE pg_catalog."default", member_first_name character(100) COLLATE pg_catalog."default", member_last_name character(100) COLLATE pg_catalog."default", member_address_1 character(100) COLLATE pg_catalog."default", member_address_2 character(100) COLLATE pg_catalog."default", member_city character(100) COLLATE pg_catalog."default", member_state character(5) COLLATE pg_catalog."default", member_zip_code character(10) COLLATE pg_catalog."default", member_country character(2) COLLATE pg_catalog."default", member_language character(2) COLLATE pg_catalog."default", member_locale character(2) COLLATE pg_catalog."default", member_email character(100) COLLATE pg_catalog."default", member_password character(100) COLLATE pg_catalog."default", member_display_name character(256) COLLATE pg_catalog."default", member_dob date, member_sex character(1) COLLATE pg_catalog."default", member_occupation text COLLATE pg_catalog."default", member_skills text COLLATE pg_catalog."default", member_shop_goods character(256) COLLATE pg_catalog."default", member_shop_services character(256) COLLATE pg_catalog."default", member_accept_rules boolean, member_ts_add timestamp with time zone, member_ts_edit timestamp with time zone, member_ts_acpt timestamp with time zone, member_did_hash character(100) COLLATE pg_catalog."default", member_auth_state character(1) COLLATE pg_catalog."default", member_auth_role character(1) COLLATE pg_catalog."default", member_update character(1) COLLATE pg_catalog."default", CONSTRAINT members_pkey PRIMARY KEY (member_user_id))""")

        if init:
            dbc.execute("DROP TABLE IF EXISTS public.proves")
        dbc.execute("""CREATE TABLE IF NOT EXISTS public.proves(prove_source_user_id character(100) COLLATE pg_catalog."default" NOT NULL, prove_destination_user_id character(100) COLLATE pg_catalog."default" NOT NULL, prove_timestamp timestamp with time zone, prove_did_hash character(100) COLLATE pg_catalog."default", CONSTRAINT proves_pkey PRIMARY KEY (prove_source_user_id, prove_destination_user_id), CONSTRAINT proves_prove_destination_user_id_fkey FOREIGN KEY (prove_destination_user_id) REFERENCES public.members (member_user_id) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT proves_prove_source_user_id_fkey FOREIGN KEY (prove_source_user_id) REFERENCES public.members (member_user_id) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION)""")

        if init:
            dbc.execute("DROP TABLE IF EXISTS public.services")
        dbc.execute("""CREATE TABLE IF NOT EXISTS public.services(service_rns_id character(32) COLLATE pg_catalog."default" NOT NULL, service_display_name character(256) COLLATE pg_catalog."default", service_city character(100) COLLATE pg_catalog."default", service_state character(5) COLLATE pg_catalog."default", service_country character(2) COLLATE pg_catalog."default", service_type character(1) COLLATE pg_catalog."default", service_owner character(32) COLLATE pg_catalog."default", service_ts_add timestamp with time zone, service_ts_edit timestamp with time zone, service_auth_state character(1) COLLATE pg_catalog."default", service_auth_role character(1) COLLATE pg_catalog."default", CONSTRAINT services_pkey PRIMARY KEY (service_rns_id))""")

        self.db_commit()


    def db_migrate(self):
        self.db_init(False)

        db = self.db_connect()
        dbc = db.cursor()

        self.db_commit()

        self.db_init(False)


    def db_indices(self):
        pass


    def db_load(self):
        self.db_init(False)


    #################################################
    # Database - Announce                           #
    #################################################


    def db_announce_filter(self, filter):
        if filter == None:
            return ""

        querys = []

        if "type" in filter and filter["type"] != None:
            if isinstance(filter["type"], int):
                querys.append("type = '"+self.db_sanitize(filter["type"])+"'")
            else:
                array = [self.db_sanitize(key) for key in filter["type"]]
                querys.append("(type = '"+"' OR type = '".join(array)+"')")

        if "hop_min" in filter and filter["hop_min"] != None:
            querys.append("hop_count >= "+self.db_sanitize(filter["hop_min"]))

        if "hop_max" in filter and filter["hop_max"] != None:
            querys.append("hop_count <= "+self.db_sanitize(filter["hop_max"]))

        if "interface" in filter and filter["interface"] != None:
            if isinstance(filter["interface"], str):
                querys.append("hop_interface ILIKE '%"+self.db_sanitize(filter["interface"])+"%'")
            else:
                querys.append("(hop_interface ILIKE '%"+"%' OR hop_interface ILIKE '%".join(filter["interface"])+"%')")

        if "owner" in filter:
            querys.append("owner = '"+self.db_sanitize(RNS.hexrep(filter["owner"], delimit=False))+"'")

        if "state" in filter:
            querys.append("state = '"+self.db_sanitize(filter["state"])+"'")

        if "state_ts_min" in filter and filter["state_ts_min"] != None:
            querys.append("state_ts >= '"+datetime.datetime.fromtimestamp(filter["state_ts_min"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if "state_ts_max" in filter and filter["state_ts_max"] != None:
            querys.append("state_ts <= '"+datetime.datetime.fromtimestamp(filter["state_ts_max"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if "ts_add_min" in filter and filter["ts_add_min"] != None:
            querys.append("ts_add >= '"+datetime.datetime.fromtimestamp(filter["ts_add_min"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if "ts_add_max" in filter and filter["ts_add_max"] != None:
            querys.append("ts_add <= '"+datetime.datetime.fromtimestamp(filter["ts_add_max"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if "ts_edit_min" in filter and filter["ts_edit_min"] != None:
            querys.append("ts_edit >= '"+datetime.datetime.fromtimestamp(filter["ts_edit_min"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if "ts_edit_max" in filter and filter["ts_edit_max"] != None:
            querys.append("ts_edit <= '"+datetime.datetime.fromtimestamp(filter["ts_edit_max"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

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


    def db_announce_group(self, group):
        if group == None:
            return ""

        querys = []

        for key in group:
            querys.append(self.db_sanitize(key))

        if len(querys) > 0:
            query = " GROUP BY "+", ".join(querys)
        else:
            query = ""

        return query


    def db_announce_order(self, order):
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


    def db_announce_list(self, filter=None, search=None, group=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_announce_filter(filter)

        query_group = self.db_announce_group(group)

        query_order = self.db_announce_order(order)

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT * FROM announces WHERE type >= 0 AND data ILIKE %s"+query_filter+query_group+query_order+query_limit
            dbc.execute(query, (search,))
        else:
            query = "SELECT * FROM announces WHERE type >= 0"+query_filter+query_group+query_order+query_limit
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                owner = entry[5].strip()
                owner = bytes.fromhex(owner) if owner else None
                data.append({
                    "dest": bytes.fromhex(entry[0].strip()),
                    "type": entry[1],
                    "data": entry[2].strip(),
                    "location_lat": entry[3],
                    "location_lon": entry[4],
                    "owner": owner,
                    "state": entry[6],
                    "state_ts": int(entry[7].timestamp()),
                    "hop_count": entry[8],
                    "ts_add": int(entry[11].timestamp()),
                    "ts_edit": int(entry[12].timestamp()),
                })

            return data


    def db_announce_count(self, filter=None, search=None, group=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_announce_filter(filter)

        query_group = self.db_announce_group(group)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(*) FROM announces WHERE type >= 0 AND data ILIKE %s"+query_filter+query_group
            dbc.execute(query, (search,))
        else:
            query = "SELECT COUNT(*) FROM announces WHERE type >= 0"+query_filter+query_group
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_announce_get(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "SELECT * FROM announces WHERE dest = %s"
        dbc.execute(query, (RNS.hexrep(dest, False),))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            entry = result[0]
            owner = entry[5].strip()
            owner = bytes.fromhex(owner) if owner else None
            data = {
                "dest": bytes.fromhex(entry[0].strip()),
                "type": entry[1],
                "data": entry[2].strip(),
                "location_lat": entry[3],
                "location_lon": entry[4],
                "owner": owner,
                "state": entry[6],
                "state_ts": int(entry[7].timestamp()),
                "hop_count": entry[8],
                "ts_add": int(entry[11].timestamp()),
                "ts_edit": int(entry[12].timestamp()),
            }
            return data


    def db_announce_delete(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "DELETE FROM announces WHERE dest = %s"
        dbc.execute(query, (RNS.hexrep(dest, False),))

        self.db_commit()


    #################################################
    # Database - Member                             #
    #################################################


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

        if "shop_goods" in filter and filter["shop_goods"] != None:
            querys.append("members.member_shop_goods ILIKE '%"+self.db_sanitize(filter["shop_goods"])+"%'")

        if "shop_services" in filter and filter["shop_services"] != None:
            querys.append("members.member_shop_services ILIKE '%"+self.db_sanitize(filter["shop_services"])+"%'")

        if "type" in filter and filter["type"] != None:
            if isinstance(filter["type"], int):
                querys.append("members.member_type = '"+self.db_sanitize(filter["type"])+"'")
            else:
                array = [self.db_sanitize(key) for key in filter["type"]]
                querys.append("(members.member_type = '"+"' OR members.member_type = '".join(array)+"')")

        if "auth_role" in filter and filter["auth_role"] != None:
            querys.append("members.member_auth_role = '"+self.db_sanitize(filter["auth_role"])+"'")

        if "ts_add_min" in filter and filter["ts_add_min"] != None:
            querys.append("members.member_ts_add >= '"+datetime.datetime.fromtimestamp(filter["ts_add_min"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if "ts_add_max" in filter and filter["ts_add_max"] != None:
            querys.append("members.member_ts_add <= '"+datetime.datetime.fromtimestamp(filter["ts_add_max"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if "ts_edit_min" in filter and filter["ts_edit_min"] != None:
            querys.append("members.member_ts_edit >= '"+datetime.datetime.fromtimestamp(filter["ts_edit_min"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if "ts_edit_max" in filter and filter["ts_edit_max"] != None:
            querys.append("members.member_ts_edit <= '"+datetime.datetime.fromtimestamp(filter["ts_edit_max"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if len(querys) > 0:
            query = " AND "+" AND ".join(querys)
        else:
            query = ""

        return query


    def db_member_group(self, group):
        if group == None:
            return ""

        querys = []

        for key in group:
            querys.append("members.member_"+self.db_sanitize(key))

        if len(querys) > 0:
            query = " GROUP BY "+", ".join(querys)
        else:
            query = ""

        return query


    def db_member_order(self, order):
        if order == "A-ASC":
            query = " ORDER BY devices.device_display_name ASC"
        elif order == "A-DESC":
            query = " ORDER BY devices.device_display_name DESC"
        elif order == "R-ASC":
            query = " ORDER BY members.member_auth_role ASC, devices.device_display_name ASC"
        elif order == "R-DESC":
            query = " ORDER BY members.member_auth_role DESC, devices.device_display_name ASC"
        elif order == "C-ASC":
            query = " ORDER BY members.member_country ASC, devices.device_display_name ASC"
        elif order == "C-DESC":
            query = " ORDER BY members.member_country DESC, devices.device_display_name ASC"
        elif order == "S-ASC":
            query = " ORDER BY members.member_country ASC, members.member_state ASC, devices.device_display_name ASC"
        elif order == "S-DESC":
            query = " ORDER BY members.member_country DESC, members.member_state DESC, devices.device_display_name ASC"
        elif order == "CITY-ASC":
            query = " ORDER BY members.member_country ASC, members.member_city ASC, devices.device_display_name ASC"
        elif order == "CITY-DESC":
            query = " ORDER BY members.member_country DESC, members.member_city DESC, devices.device_display_name ASC"
        elif order == "TSA-ASC":
            query = " ORDER BY members.member_ts_add ASC, devices.device_display_name ASC"
        elif order == "TSA-DESC":
            query = " ORDER BY members.member_ts_add DESC, devices.device_display_name ASC"
        elif order == "TSE-ASC":
            query = " ORDER BY members.member_ts_edit ASC, devices.device_display_name ASC"
        elif order == "TSE-DESC":
            query = " ORDER BY members.member_ts_edit DESC, devices.device_display_name ASC"
        else:
            query = ""

        return query


    def db_member_list(self, filter=None, search=None, group=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_member_filter(filter)

        query_group = self.db_member_group(group)

        query_order = self.db_member_order(order)

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT members.member_city, members.member_state, members.member_country, members.member_occupation, members.member_skills, members.member_shop_goods, members.member_shop_services, members.member_auth_role, members.member_ts_add, members.member_ts_edit, devices.device_rns_id, devices.device_display_name FROM members LEFT JOIN devices ON devices.device_user_id = members.member_user_id WHERE members.member_user_id != '' AND (devices.device_display_name ILIKE %s OR members.member_city ILIKE %s OR members.member_occupation ILIKE %s OR members.member_skills ILIKE %s OR members.member_shop_goods ILIKE %s OR members.member_shop_services ILIKE %s)"+query_filter+query_group+query_order+query_limit
            dbc.execute(query, (search, search, search, search, search, search))
        else:
            query = "SELECT members.member_city, members.member_state, members.member_country, members.member_occupation, members.member_skills, members.member_shop_goods, members.member_shop_services, members.member_auth_role, members.member_ts_add, members.member_ts_edit, devices.device_rns_id, devices.device_display_name FROM members LEFT JOIN devices ON devices.device_user_id = members.member_user_id WHERE members.member_user_id != ''"+query_filter+query_group+query_order+query_limit
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
                        "shop_goods": entry[5].strip(),
                        "shop_services": entry[6].strip(),
                        "auth_role": int(entry[7].strip()),
                        "ts_add": int(entry[8].timestamp()),
                        "ts_edit": int(entry[9].timestamp()),
                        "dest": bytes.fromhex(entry[10].strip()),
                        "display_name": entry[11].strip(),
                    })
            return data


    def db_member_count(self, filter=None, search=None, group=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_member_filter(filter)

        query_group = self.db_member_group(group)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(*) FROM members LEFT JOIN devices ON devices.device_user_id = members.member_user_id WHERE members.member_user_id != '' AND (devices.device_display_name ILIKE %s OR members.member_city ILIKE %s OR members.member_occupation ILIKE %s OR members.member_skills ILIKE %s OR members.member_shop_goods ILIKE %s OR members.member_shop_services ILIKE %s)"+query_filter+query_group
            dbc.execute(query, (search, search, search, search, search, search))
        else:
            query = "SELECT COUNT(*) FROM members WHERE member_user_id != ''"+query_filter+query_group
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_member_count_list(self, filter=None, search=None, group=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_member_filter(filter)

        query_group = self.db_member_group(group)

        query_order = self.db_member_order(order)
        query_order = query_order.replace(" ORDER BY devices.device_display_name ASC", "")
        query_order = query_order.replace(" ORDER BY devices.device_display_name DESC", "")
        query_order = query_order.replace(", devices.device_display_name ASC", "")

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(members.member_ts_add), MAX(members.member_country), MAX(members.member_state), MAX(members.member_city), MAX(members.member_auth_role) FROM members LEFT JOIN devices ON devices.device_user_id = members.member_user_id WHERE members.member_user_id != '' AND (devices.device_display_name ILIKE %s OR members.member_city ILIKE %s OR members.member_occupation ILIKE %s OR members.member_skills ILIKE %s OR members.member_shop_goods ILIKE %s OR members.member_shop_services ILIKE %s)"+query_filter+query_group+query_order+query_limit
            dbc.execute(query, (search, search, search, search, search, search))
        else:
            query = "SELECT COUNT(members.member_ts_add), MAX(members.member_country), MAX(members.member_state), MAX(members.member_city), MAX(members.member_auth_role) FROM members LEFT JOIN devices ON devices.device_user_id = members.member_user_id WHERE member_user_id != ''"+query_filter+query_group+query_order+query_limit
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                data.append({
                    "count": entry[0],
                    "country": entry[1].strip(),
                    "state": entry[2].strip(),
                    "city": entry[3].strip(),
                    "auth_role": int(entry[4].strip())
                })
            return data


    def db_member_get(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "SELECT members.member_city, members.member_state, members.member_country, members.member_occupation, members.member_skills, members.member_shop_goods, members.member_shop_services, members.member_auth_role, members.member_ts_add, members.member_ts_edit, devices.device_rns_id, devices.device_display_name FROM members LEFT JOIN devices ON devices.device_user_id = members.member_user_id WHERE devices.device_rns_id = %s"
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
                "shop_goods": entry[5].strip(),
                "shop_services": entry[6].strip(),
                "auth_role": int(entry[7].strip()),
                "ts_add": int(entry[8].timestamp()),
                "ts_edit": int(entry[9].timestamp()),
                "dest": bytes.fromhex(entry[10].strip()),
                "display_name": entry[11].strip(),
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


    #################################################
    # Database - Service                            #
    #################################################


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

        if "owner" in filter:
            querys.append("services.service_owner = '"+self.db_sanitize(RNS.hexrep(filter["owner"], delimit=False))+"'")

        if "auth_role" in filter and filter["auth_role"] != None:
            querys.append("services.service_auth_role = '"+self.db_sanitize(filter["auth_role"])+"'")

        if "ts_add_min" in filter and filter["ts_add_min"] != None:
            querys.append("services.service_ts_add >= '"+datetime.datetime.fromtimestamp(filter["ts_add_min"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if "ts_add_max" in filter and filter["ts_add_max"] != None:
            querys.append("services.service_ts_add <= '"+datetime.datetime.fromtimestamp(filter["ts_add_max"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if "ts_edit_min" in filter and filter["ts_edit_min"] != None:
            querys.append("services.service_ts_edit >= '"+datetime.datetime.fromtimestamp(filter["ts_edit_min"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if "ts_edit_max" in filter and filter["ts_edit_max"] != None:
            querys.append("services.service_ts_edit <= '"+datetime.datetime.fromtimestamp(filter["ts_edit_max"]).strftime("%Y-%m-%d %H:%M:%S")+"'")

        if len(querys) > 0:
            query = " AND "+" AND ".join(querys)
        else:
            query = ""

        return query


    def db_service_group(self, group):
        if group == None:
            return ""

        querys = []

        for key in group:
            querys.append("services.service_"+self.db_sanitize(key))

        if len(querys) > 0:
            query = " GROUP BY "+", ".join(querys)
        else:
            query = ""

        return query


    def db_service_order(self, order):
        if order == "A-ASC":
            query = " ORDER BY services.service_display_name ASC"
        elif order == "A-DESC":
            query = " ORDER BY services.service_display_name DESC"
        elif order == "R-ASC":
            query = " ORDER BY services.service_auth_role ASC, services.service_display_name ASC"
        elif order == "R-DESC":
            query = " ORDER BY services.service_auth_role DESC, services.service_display_name ASC"
        elif order == "C-ASC":
            query = " ORDER BY services.service_country ASC, services.service_display_name ASC"
        elif order == "C-DESC":
            query = " ORDER BY services.service_country DESC, services.service_display_name ASC"
        elif order == "S-ASC":
            query = " ORDER BY services.service_country ASC, services.service_state ASC, services.service_display_name ASC"
        elif order == "S-DESC":
            query = " ORDER BY services.service_country DESC, services.service_state DESC, services.service_display_name ASC"
        elif order == "CITY-ASC":
            query = " ORDER BY services.service_country ASC, services.service_city ASC, services.service_display_name ASC"
        elif order == "CITY-DESC":
            query = " ORDER BY services.service_country DESC, services.service_city DESC, services.service_display_name ASC"
        elif order == "TSA-ASC":
            query = " ORDER BY services.service_ts_add ASC, services.service_display_name ASC"
        elif order == "TSA-DESC":
            query = " ORDER BY services.service_ts_add DESC, services.service_display_name ASC"
        elif order == "TSE-ASC":
            query = " ORDER BY services.service_ts_edit ASC, services.service_display_name ASC"
        elif order == "TSE-DESC":
            query = " ORDER BY services.service_ts_edit DESC, services.service_display_name ASC"
        else:
            query = ""

        return query


    def db_service_list(self, filter=None, search=None, group=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_service_filter(filter)

        query_group = self.db_service_group(group)

        query_order = self.db_service_order(order)

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT services.service_rns_id, services.service_display_name, services.service_country, services.service_state, services.service_city, services.service_type, services.service_owner, services.service_auth_role, services.service_ts_add, services.service_ts_edit FROM services WHERE services.service_rns_id != '' AND (services.service_display_name ILIKE %s OR services.service_city ILIKE %s)"+query_filter+query_group+query_order+query_limit
            dbc.execute(query, (search, search))
        else:
            query = "SELECT services.service_rns_id, services.service_display_name, services.service_country, services.service_state, services.service_city, services.service_type, services.service_owner, services.service_auth_role, services.service_ts_add, services.service_ts_edit FROM services WHERE services.service_rns_id != ''"+query_filter+query_group+query_order+query_limit
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                owner = entry[6].strip()
                owner = bytes.fromhex(owner) if owner else None
                data.append({
                    "dest": bytes.fromhex(entry[0].strip()),
                    "display_name": entry[1].strip(),
                    "country": entry[2].strip(),
                    "state": entry[3].strip(),
                    "city": entry[4].strip(),
                    "type": entry[5].strip(),
                    "owner": owner,
                    "auth_role": int(entry[7].strip()),
                    "ts_add": int(entry[8].timestamp()),
                    "ts_edit": int(entry[9].timestamp()),
                })

            return data


    def db_service_count(self, filter=None, search=None, group=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_service_filter(filter)

        query_group = self.db_service_group(group)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(*) FROM services WHERE services.service_rns_id != '' AND (services.service_display_name ILIKE %s OR services.service_city ILIKE %s)"+query_filter+query_group
            dbc.execute(query, (search, search))
        else:
            query = "SELECT COUNT(*) FROM services WHERE services.service_rns_id != ''"+query_filter+query_group
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return 0
        else:
            return result[0][0]


    def db_service_count_list(self, filter=None, search=None, group=None, order=None, limit=None, limit_start=None):
        db = self.db_connect()
        dbc = db.cursor()

        query_filter = self.db_service_filter(filter)

        query_group = self.db_service_group(group)

        query_order = self.db_service_order(order)
        query_order = query_order.replace(" ORDER BY services.service_display_name ASC", "")
        query_order = query_order.replace(" ORDER BY services.service_display_name DESC", "")
        query_order = query_order.replace(", services.service_display_name ASC", "")

        if limit == None or limit_start == None:
            query_limit = ""
        else:
            query_limit = " LIMIT "+self.db_sanitize(limit)+" OFFSET "+self.db_sanitize(limit_start)

        if search:
            search = "%"+search+"%"
            query = "SELECT COUNT(services.service_ts_add), MAX(services.service_country), MAX(services.service_state), MAX(services.service_city), MAX(services.service_auth_role) FROM services WHERE services.service_rns_id != '' AND (services.service_display_name ILIKE %s OR services.service_city ILIKE %s)"+query_filter+query_group+query_order+query_limit
            dbc.execute(query, (search, search))
        else:
            query = "SELECT COUNT(services.service_ts_add), MAX(services.service_country), MAX(services.service_state), MAX(services.service_city), MAX(services.service_auth_role) FROM services WHERE services.service_rns_id != ''"+query_filter+query_group+query_order+query_limit
            dbc.execute(query)

        result = dbc.fetchall()

        if len(result) < 1:
            return []
        else:
            data = []
            for entry in result:
                data.append({
                    "count": entry[0],
                    "country": entry[1].strip(),
                    "state": entry[2].strip(),
                    "city": entry[3].strip(),
                    "auth_role": int(entry[4].strip())
                })
            return data


    def db_service_get(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "SELECT services.service_rns_id, services.service_display_name, services.service_country, services.service_state, services.service_city, services.service_type, services.service_owner, services.service_auth_role, services.service_ts_add, services.service_ts_edit FROM services WHERE services.service_rns_id = %s"
        dbc.execute(query, (RNS.hexrep(dest, False),))
        result = dbc.fetchall()

        if len(result) < 1:
            return None
        else:
            entry = result[0]
            owner = entry[6].strip()
            owner = bytes.fromhex(owner) if owner else None
            data = {
                "dest": bytes.fromhex(entry[0].strip()),
                "display_name": entry[1].strip(),
                "country": entry[2].strip(),
                "state": entry[3].strip(),
                "city": entry[4].strip(),
                "type": entry[5].strip(),
                "owner": owner,
                "auth_role": int(entry[7].strip()),
                "ts_add": int(entry[8].timestamp()),
                "ts_edit": int(entry[9].timestamp()),
            }
            return data


    def db_service_delete(self, dest):
        db = self.db_connect()
        dbc = db.cursor()

        query = "DELETE FROM services WHERE service_rns_id = %s"
        dbc.execute(query, (RNS.hexrep(dest, False),))

        self.db_commit()


    #################################################
    # Directory                                     #
    #################################################


    def response_directory_announce(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_NO_IDENTITY})

        if self.limiter_server and not self.limiter_server.handle("server"):
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_LIMIT_SERVER})

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_LIMIT_PEER})

        if not data:
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_NO_DATA})

        RNS.log("Server - Response - Directory announce", RNS.LOG_DEBUG)
        RNS.log(data, RNS.LOG_EXTREME)

        data_return = {}

        data_return[ServerProvisioning.KEY_RESULT] = ServerProvisioning.RESULT_OK

        try:
            directory = {}
            entrys = []

            hash_destination = RNS.hexrep(RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity), delimit=False)
            hash_identity = ""

            if ServerProvisioning.KEY_D_CMD in data:
                if hash_destination in self.admins:
                    cmd = data[ServerProvisioning.KEY_D_CMD]
                    if cmd[0] == "delete":
                        self.db_announce_delete(cmd[1])
                    entry = self.db_announce_get(cmd[1])
                    if entry:
                        directory.update({ServerProvisioning.KEY_D_CMD_RESULT: ServerProvisioning.RESULT_OK})
                        entrys = [entry]
                    else:
                        directory.update({ServerProvisioning.KEY_D_CMD_RESULT: ServerProvisioning.RESULT_OK})
                        entrys = [{"dest": cmd[1], "type": 0, "data": "", "location_lat": 0, "location_lon": 0, "owner": None, "state": 0, "state_ts": 0, "hop_count": 0, "ts_add": 0, "ts_edit": 0}]
            else:
                directory[ServerProvisioning.KEY_D_RX_ENTRYS_COUNT] = self.db_announce_count(filter=data[ServerProvisioning.KEY_D_FILTER], search=data[ServerProvisioning.KEY_D_SEARCH], group=data[ServerProvisioning.KEY_D_GROUP])
                entrys = self.db_announce_list(filter=data[ServerProvisioning.KEY_D_FILTER], search=data[ServerProvisioning.KEY_D_SEARCH], group=data[ServerProvisioning.KEY_D_GROUP], order=data[ServerProvisioning.KEY_D_ORDER], limit=data[ServerProvisioning.KEY_D_LIMIT], limit_start=data[ServerProvisioning.KEY_D_LIMIT_START])

            if len(entrys) > 0:
                directory[ServerProvisioning.KEY_D_RX_ENTRYS] = []
                entrys_return = []
                for entry in entrys:
                    entry_return = {}
                    for key, value in entry.items():
                        if key in ServerProvisioning.KEY_D_ENTRYS_MAPPING:
                            entry_return[ServerProvisioning.KEY_D_ENTRYS_MAPPING[key]] = value
                    directory[ServerProvisioning.KEY_D_RX_ENTRYS].append(entry_return)

            if hash_destination in self.admins:
                directory[ServerProvisioning.KEY_D_CMD] = []
                directory[ServerProvisioning.KEY_D_CMD_ENTRY] = ["delete"]

            data_return[ServerProvisioning.KEY_D] = directory

        except Exception as e:
            RNS.log("Server - Response - Directory announce", RNS.LOG_ERROR)
            RNS.trace_exception(e)
            data_return[ServerProvisioning.KEY_RESULT] = ServerProvisioning.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(data_return))

        if self.limiter_peer:
             self.limiter_peer.handle_size(str(remote_identity), len(data_return))

        return data_return


    def response_directory_member(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_NO_IDENTITY})

        if self.limiter_server and not self.limiter_server.handle("server"):
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_LIMIT_SERVER})

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_LIMIT_PEER})

        if not data:
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_NO_DATA})

        RNS.log("Server - Response - Directory member", RNS.LOG_DEBUG)
        RNS.log(data, RNS.LOG_EXTREME)

        data_return = {}

        data_return[ServerProvisioning.KEY_RESULT] = ServerProvisioning.RESULT_OK

        try:
            directory = {}
            entrys = []
            group_entrys = []

            hash_destination = RNS.hexrep(RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity), delimit=False)
            hash_identity = ""

            if ServerProvisioning.KEY_D_CMD in data:
                if hash_destination in self.admins:
                    cmd = data[ServerProvisioning.KEY_D_CMD]
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
                        directory.update({ServerProvisioning.KEY_D_CMD_RESULT: ServerProvisioning.RESULT_OK})
                        entrys = [entry]
                    else:
                        directory.update({ServerProvisioning.KEY_D_CMD_RESULT: ServerProvisioning.RESULT_OK})
                        entrys = [{"dest": cmd[1], "ts_edit": 0}]
            elif ServerProvisioning.KEY_D_GROUP in data and data[ServerProvisioning.KEY_D_GROUP] != None:
                group_entrys = self.db_member_count_list(filter=data[ServerProvisioning.KEY_D_FILTER], search=data[ServerProvisioning.KEY_D_SEARCH], group=data[ServerProvisioning.KEY_D_GROUP], order=data[ServerProvisioning.KEY_D_ORDER], limit=data[ServerProvisioning.KEY_D_LIMIT], limit_start=data[ServerProvisioning.KEY_D_LIMIT_START])
                directory[ServerProvisioning.KEY_D_RX_GROUP_ENTRYS_COUNT] = len(group_entrys)
            else:
                directory[ServerProvisioning.KEY_D_RX_ENTRYS_COUNT] = self.db_member_count(filter=data[ServerProvisioning.KEY_D_FILTER], search=data[ServerProvisioning.KEY_D_SEARCH], group=data[ServerProvisioning.KEY_D_GROUP])

                for entry in self.db_member_list(filter=data[ServerProvisioning.KEY_D_FILTER], search=data[ServerProvisioning.KEY_D_SEARCH], group=data[ServerProvisioning.KEY_D_GROUP], order=data[ServerProvisioning.KEY_D_ORDER], limit=data[ServerProvisioning.KEY_D_LIMIT], limit_start=data[ServerProvisioning.KEY_D_LIMIT_START]):
                    if entry["dest"] in data[ServerProvisioning.KEY_D_ENTRYS]:
                        if entry["ts_edit"] > data[ServerProvisioning.KEY_D_ENTRYS][entry["dest"]]:
                            entrys.append(entry)
                        del data[ServerProvisioning.KEY_D_ENTRYS][entry["dest"]]
                    else:
                        entrys.append(entry)

                for dest in data[ServerProvisioning.KEY_D_ENTRYS]:
                    entry = self.db_member_get(dest=dest)
                    if entry:
                        if entry["ts_edit"] > data[ServerProvisioning.KEY_D_ENTRYS][dest]:
                            entrys.append(entry)
                    else:
                        entrys.append({"dest": dest, "ts_edit": 0})

            if len(entrys) > 0:
                directory[ServerProvisioning.KEY_D_RX_ENTRYS] = []
                entrys_return = []
                for entry in entrys:
                    entry_return = {}
                    for key, value in entry.items():
                        if key in ServerProvisioning.KEY_D_ENTRYS_MAPPING:
                            entry_return[ServerProvisioning.KEY_D_ENTRYS_MAPPING[key]] = value
                    directory[ServerProvisioning.KEY_D_RX_ENTRYS].append(entry_return)

            if len(group_entrys) > 0:
                directory[ServerProvisioning.KEY_D_RX_GROUP_ENTRYS] = []
                entrys_return = []
                for entry in group_entrys:
                    entry_return = {}
                    for key, value in entry.items():
                        if key in ServerProvisioning.KEY_D_ENTRYS_MAPPING:
                            entry_return[ServerProvisioning.KEY_D_ENTRYS_MAPPING[key]] = value
                    directory[ServerProvisioning.KEY_D_RX_GROUP_ENTRYS].append(entry_return)

            if hash_destination in self.admins:
                directory[ServerProvisioning.KEY_D_CMD] = []
                directory[ServerProvisioning.KEY_D_CMD_ENTRY] = ["role_0", "role_1", "role_2", "role_3", "state_0", "state_1", "state_2", "delete"]

            data_return[ServerProvisioning.KEY_D] = directory

        except Exception as e:
            RNS.log("Server - Response - Directory member", RNS.LOG_ERROR)
            RNS.trace_exception(e)
            data_return[ServerProvisioning.KEY_RESULT] = ServerProvisioning.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(data_return))

        if self.limiter_peer:
             self.limiter_peer.handle_size(str(remote_identity), len(data_return))

        return data_return


    def response_directory_service(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_NO_IDENTITY})

        if self.limiter_server and not self.limiter_server.handle("server"):
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_LIMIT_SERVER})

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_LIMIT_PEER})

        if not data:
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_NO_DATA})

        RNS.log("Server - Response - Directory service", RNS.LOG_DEBUG)
        RNS.log(data, RNS.LOG_EXTREME)

        data_return = {}

        data_return[ServerProvisioning.KEY_RESULT] = ServerProvisioning.RESULT_OK

        try:
            directory = {}
            entrys = []
            group_entrys = []

            hash_destination = RNS.hexrep(RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity), delimit=False)
            hash_identity = ""

            if ServerProvisioning.KEY_D_CMD in data:
                if hash_destination in self.admins:
                    cmd = data[ServerProvisioning.KEY_D_CMD]
                    if cmd[0] == "delete":
                        self.db_service_delete(cmd[1])
                    entry = self.db_service_get(cmd[1])
                    if entry:
                        directory.update({ServerProvisioning.KEY_D_CMD_RESULT: ServerProvisioning.RESULT_OK})
                        entrys = [entry]
                    else:
                        directory.update({ServerProvisioning.KEY_D_CMD_RESULT: ServerProvisioning.RESULT_OK})
                        entrys = [{"dest": cmd[1], "ts_edit": 0}]
            elif ServerProvisioning.KEY_D_GROUP in data and data[ServerProvisioning.KEY_D_GROUP] != None:
                group_entrys = self.db_service_count_list(filter=data[ServerProvisioning.KEY_D_FILTER], search=data[ServerProvisioning.KEY_D_SEARCH], group=data[ServerProvisioning.KEY_D_GROUP], order=data[ServerProvisioning.KEY_D_ORDER], limit=data[ServerProvisioning.KEY_D_LIMIT], limit_start=data[ServerProvisioning.KEY_D_LIMIT_START])
                directory[ServerProvisioning.KEY_D_RX_GROUP_ENTRYS_COUNT] = len(group_entrys)
            else:
                directory[ServerProvisioning.KEY_D_RX_ENTRYS_COUNT] = self.db_service_count(filter=data[ServerProvisioning.KEY_D_FILTER], search=data[ServerProvisioning.KEY_D_SEARCH], group=data[ServerProvisioning.KEY_D_GROUP])

                for entry in self.db_service_list(filter=data[ServerProvisioning.KEY_D_FILTER], search=data[ServerProvisioning.KEY_D_SEARCH], group=data[ServerProvisioning.KEY_D_GROUP], order=data[ServerProvisioning.KEY_D_ORDER], limit=data[ServerProvisioning.KEY_D_LIMIT], limit_start=data[ServerProvisioning.KEY_D_LIMIT_START]):
                    if entry["dest"] in data[ServerProvisioning.KEY_D_ENTRYS]:
                        if entry["ts_edit"] > data[ServerProvisioning.KEY_D_ENTRYS][entry["dest"]]:
                            entrys.append(entry)
                        del data[ServerProvisioning.KEY_D_ENTRYS][entry["dest"]]
                    else:
                        entrys.append(entry)

                for dest in data[ServerProvisioning.KEY_D_ENTRYS]:
                    entry = self.db_service_get(dest=dest)
                    if entry:
                        if entry["ts_edit"] > data[ServerProvisioning.KEY_D_ENTRYS][dest]:
                            entrys.append(entry)
                    else:
                        entrys.append({"dest": dest, "ts_edit": 0})

            if len(entrys) > 0:
                directory[ServerProvisioning.KEY_D_RX_ENTRYS] = []
                entrys_return = []
                for entry in entrys:
                    entry_return = {}
                    for key, value in entry.items():
                        if key in ServerProvisioning.KEY_D_ENTRYS_MAPPING:
                            entry_return[ServerProvisioning.KEY_D_ENTRYS_MAPPING[key]] = value
                    directory[ServerProvisioning.KEY_D_RX_ENTRYS].append(entry_return)

            if len(group_entrys) > 0:
                directory[ServerProvisioning.KEY_D_RX_GROUP_ENTRYS] = []
                entrys_return = []
                for entry in group_entrys:
                    entry_return = {}
                    for key, value in entry.items():
                        if key in ServerProvisioning.KEY_D_ENTRYS_MAPPING:
                            entry_return[ServerProvisioning.KEY_D_ENTRYS_MAPPING[key]] = value
                    directory[ServerProvisioning.KEY_D_RX_GROUP_ENTRYS].append(entry_return)

            if hash_destination in self.admins:
                directory[ServerProvisioning.KEY_D_CMD] = []
                directory[ServerProvisioning.KEY_D_CMD_ENTRY] = []

            data_return[ServerProvisioning.KEY_D] = directory

        except Exception as e:
            RNS.log("Server - Response - Directory service", RNS.LOG_ERROR)
            RNS.trace_exception(e)
            data_return[ServerProvisioning.KEY_RESULT] = ServerProvisioning.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(data_return))

        if self.limiter_peer:
             self.limiter_peer.handle_size(str(remote_identity), len(data_return))

        return data_return


    #################################################
    # Files                                         #
    #################################################


    def files_register(self):
        array = self.files.copy()

        self.files = []
        self.files_scan(self.files_path)
        self.files.sort()

        for file in array:
            if file not in self.files:
                self.destination.deregister_request_handler(file)

        for file in self.files:
            if file not in array:
                self.destination.register_request_handler(file, response_generator=self.files_download, allow=RNS.Destination.ALLOW_ALL)


    def files_scan(self, base_path):
        files = [file for file in os.listdir(base_path) if os.path.isfile(os.path.join(base_path, file)) and file[:1] != "."]
        directories = [file for file in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, file)) and file[:1] != "."]

        for file in files:
            ext = os.path.splitext(file)[1][1:]
            if ext in self.files_ext_allow or ext not in self.files_ext_deny:
                file = base_path+"/"+file
                self.files.append(file.replace(self.files_path, "").lstrip('/'))

        for directory in directories:
            self.files_scan(base_path+"/"+directory)


    def files_download(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            return None

        if self.limiter_server and not self.limiter_server.handle("server"):
            return None

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return None

        if request_id:
            RNS.log("Server - Files: Request "+RNS.prettyhexrep(request_id)+" for: "+str(path), RNS.LOG_VERBOSE)
        else:
            RNS.log("Server - Files: Request <local> for: "+str(path), RNS.LOG_VERBOSE)

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)

        if data:
            RNS.log("Server - Files: Data: "+str(data), RNS.LOG_DEBUG)

        file_path = self.files_path+"/"+path

        allowed_path = file_path+".allowed"
        allowed = False

        if os.path.isfile(allowed_path):
            allowed_list = []

            try:
                if os.access(allowed_path, os.X_OK):
                    allowed_result = subprocess.run([allowed_path], stdout=subprocess.PIPE)
                    allowed_input = allowed_result.stdout
                else:
                    fh = open(allowed_path, "rb")
                    allowed_input = fh.read()
                    fh.close()

                allowed_hash_strs = allowed_input.splitlines()

                for hash_str in allowed_hash_strs:
                    if len(hash_str) == RNS.Identity.TRUNCATED_HASHLENGTH//8*2:
                        try:
                            allowed_hash = bytes.fromhex(hash_str.decode("utf-8"))
                            allowed_list.append(allowed_hash)
                        except Exception as e:
                            RNS.log("Server - Files: Could not decode RNS Identity hash from: "+str(hash_str), RNS.LOG_DEBUG)
                            RNS.log("Server - Files: The contained exception was: "+str(e), RNS.LOG_DEBUG)

            except Exception as e:
                RNS.log("Server - Files: Error while fetching list of allowed identities for request: "+str(e), RNS.LOG_ERROR)

            if hasattr(remote_identity, "hash"):
                if self.destination_mode == False and remote_identity.hash in allowed_list:
                    allowed = True
                elif self.destination_mode == True and dest in allowed_list:
                    allowed = True

        elif self.files_allow_all:
            allowed = True

        elif hasattr(remote_identity, "hash"):
            if self.destination_mode == False and remote_identity.hash in self.files_allow:
                allowed = True
            elif self.destination_mode == True and dest in self.files_allow:
                allowed = True

        if hasattr(remote_identity, "hash"):
            if self.destination_mode == False and remote_identity.hash in self.files_deny:
                allowed = False
            elif self.destination_mode == True and dest in self.files_deny:
                allowed = False

        if request_id == None:
            allowed = True

        try:
            if allowed:
                RNS.log("Server - Files: Serving "+file_path, RNS.LOG_VERBOSE)
                if os.access(file_path, os.X_OK):
                    env_map = {}
                    if "PATH" in os.environ:
                        env_map["PATH"] = os.environ["PATH"]
                    if link_id != None:
                        env_map["link_id"] = RNS.hexrep(link_id, delimit=False)
                    if remote_identity != None:
                        env_map["remote_identity"] = RNS.hexrep(remote_identity.hash, delimit=False)
                    if dest != None:
                        env_map["dest"] = RNS.hexrep(dest, delimit=False)

                    if data != None and isinstance(data, dict):
                        for e in data:
                            if isinstance(e, str) and (e.startswith("field_") or e.startswith("var_")):
                                env_map[e] = data[e]

                    generated = subprocess.run([file_path], stdout=subprocess.PIPE, env=env_map)
                    generated = generated.stdout
                    if self.limiter_server:
                        self.limiter_server.handle_size("server", len(generated))
                    if self.limiter_peer:
                        self.limiter_peer.handle_size(str(remote_identity), len(generated))
                    return generated
                else:
                    fh = open(file_path, "rb")
                    response_data = fh.read()
                    fh.close()
                    if self.limiter_server:
                        self.limiter_server.handle_size("server", len(response_data))
                    if self.limiter_peer:
                        self.limiter_peer.handle_size(str(remote_identity), len(response_data))
                    return response_data
            else:
                RNS.log("Server - Files: Request denied", RNS.LOG_VERBOSE)
                return None

        except Exception as e:
            RNS.log("Server - Files: Error occurred while handling request for: "+str(path), RNS.LOG_ERROR)
            RNS.log("Server - Files: The contained exception was: "+str(e), RNS.LOG_ERROR)
            return None


    #################################################
    # Sync                                          #
    #################################################


    def response_sync(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_NO_IDENTITY})

        if self.limiter_server and not self.limiter_server.handle("server"):
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_LIMIT_SERVER})

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_LIMIT_PEER})

        if not data:
            return msgpack.packb({ServerProvisioning.KEY_RESULT: ServerProvisioning.RESULT_NO_DATA})

        RNS.log("Server - Response - Sync", RNS.LOG_DEBUG)
        RNS.log(data, RNS.LOG_EXTREME)

        data_return = {}

        if remote_identity:
            hash_destination = RNS.hexrep(RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity), delimit=False)
            hash_identity = ""
        else:
            data_return[ServerProvisioning.KEY_RESULT] = Provisioning.RESULT_NO_IDENTITY
            return msgpack.packb(data_return)

        db = None
        try:
            db = psycopg2.connect(user=self.config["database"]["user"], password=self.config["database"]["password"], host=self.config["database"]["host"], port=self.config["database"]["port"], database=self.config["database"]["database"], client_encoding=self.config["database"]["encoding"], connect_timeout=5)
            dbc = db.cursor()

            data_return[ServerProvisioning.KEY_RESULT] = ServerProvisioning.RESULT_OK
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
                            dbc.execute("INSERT INTO members (member_user_id, member_email, member_password, member_dob, member_sex, member_country, member_state, member_city, member_occupation, member_skills, member_shop_goods, member_shop_services, member_accept_rules, member_language, member_locale, member_ts_add, member_ts_edit, member_auth_state, member_auth_role, member_update) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, '0', '0', '0')", (
                                user_id,
                                data["email"],
                                data["password"],
                                data["dob"],
                                data["sex"],
                                data["country"],
                                data["state"],
                                data["city"],
                                data["occupation"],
                                data["skills"],
                                data["shop_goods"],
                                data["shop_services"],
                                data["accept_rules"],
                                data["language"],
                                data["language"],
                                datetime.datetime.now(datetime.timezone.utc),
                                datetime.datetime.now(datetime.timezone.utc)
                                )
                            )
                            if self.config["features"].getboolean("account_add_auth"):
                                data_return["auth_state"] = self.config["features"].getint("account_add_auth_state")
                                data_return["auth_role"] = self.config["features"].getint("account_add_auth_role")
                        elif len(result) == 1:
                            if not self.config["features"].getboolean("account_edit"):
                                continue
                            user_id = result[0][0]
                            dbc.execute("UPDATE members SET member_email = %s, member_password = %s, member_dob = %s, member_sex = %s, member_country = %s, member_state = %s, member_city = %s, member_occupation = %s, member_skills = %s, member_shop_goods = %s, member_shop_services = %s, member_accept_rules = %s, member_language = %s, member_locale = %s, member_ts_edit = %s WHERE member_user_id = %s", (
                                data["email"],
                                data["password"],
                                data["dob"],
                                data["sex"],
                                data["country"],
                                data["state"],
                                data["city"],
                                data["occupation"],
                                data["skills"],
                                data["shop_goods"],
                                data["shop_services"],
                                data["accept_rules"],
                                data["language"],
                                data["language"],
                                datetime.datetime.now(datetime.timezone.utc),
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
                    data_return[ServerProvisioning.KEY_RESULT] = ServerProvisioning.RESULT_ERROR

        except psycopg2.DatabaseError as e:
            RNS.log("DB - Error: "+str(e), LOG_ERROR)
            db.rollback()
            data_return[ServerProvisioning.KEY_RESULT] = ServerProvisioning.RESULT_ERROR

        if db:
            dbc.close()
            db.close()
            db = None

        data_return = msgpack.packb(data_return)

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(data_return))

        if self.limiter_peer:
             self.limiter_peer.handle_size(str(remote_identity), len(data_return))

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

    RNS_SERVER_PROVISIONING.files_config(
        enabled=CONFIG["rns_server"].getboolean("files_enabled"),
        path=CONFIG["rns_server"]["files_path"],
        ext_allow=CONFIG["rns_server"]["files_ext_allow"].split(","),
        ext_deny=CONFIG["rns_server"]["files_ext_deny"].split(",")
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


[admins]


[data]
v_s = 0.0.0 #Version software
u_s = #URL Software
i_s = #Info Software
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


# Files
files_enabled = True
files_path = files
files_ext_allow = #,-separated list
files_ext_deny = py,sh #,-separated list


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