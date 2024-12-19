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

#### Process ####
import signal
import threading
import subprocess

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "RNS Server Page/File"
DESCRIPTION = "Page/File hosting functions for RNS based apps"
VERSION = "0.0.1 (2024-05-31)"
COPYRIGHT = "(c) 2024 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/"+os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None


#### Global Variables - System (Not changeable) ####
CONFIG = None
RNS_CONNECTION = None
RNS_SERVER_PAGE = None

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
# ServerPage Class


class ServerPage:
    def __init__(self, storage_path=None, identity_file="identity", identity=None, ratchets=False, destination_name="nomadnetwork", destination_type="node", destination_conv_name="lxmf", destination_conv_type="delivery", destination_mode=True, announce_startup=False, announce_startup_delay=0, announce_periodic=False, announce_periodic_interval=360, announce_data="", announce_hidden=False, register_startup=True, register_startup_delay=0, register_periodic=True, register_periodic_interval=30, statistic=None, limiter_server_enabled=False, limiter_server_calls=1000, limiter_server_size=0, limiter_server_duration=60, limiter_peer_enabled=True, limiter_peer_calls=30, limiter_peer_size=0, limiter_peer_duration=60):
        self.storage_path = storage_path

        self.identity_file = identity_file
        self.identity = identity
        self.ratchets = ratchets

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

        if statistic:
            self.statistic = statistic
        else:
            self.statistic_reset()

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

        if self.ratchets:
            self.destination.enable_ratchets(self.identity_path+"."+RNS.hexrep(self.destination.hash, delimit=False)+".ratchets")

        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)

        self.destination.set_link_established_callback(self.peer_connected)

        self.pages_enabled = False
        self.files_enabled = False
        self.upload_enabled = False

        if limiter_server_enabled:
            self.limiter_server = RateLimiter(int(limiter_server_calls), int(limiter_server_size), int(limiter_server_duration))
        else:
            self.limiter_server = None

        if limiter_peer_enabled:
            self.limiter_peer = RateLimiter(int(limiter_peer_calls), int(limiter_peer_size), int(limiter_peer_duration))
        else:
            self.limiter_peer = None


    def pages_config(self, enabled=True, path="pages", execute=True, ext_allow=[], ext_deny=[], allow_all=True, allow=[], deny=[], index="", pages_index_depth=255, files_index_depth=255, content_index_header="", content_index_footer="", content_index_pages_header=">>Index - Pages!n!!n!", content_index_pages_entry="`[{name}`:{url}]`!n!!n!", content_index_files_header=">>Index - Files!n!!n!", content_index_files_entry="`[{name}`:{url}]`!n!!n!", content_index="Default Home Page\n\nThis server is serving pages, but the home page file (index.mu) was not found in the page storage directory.", content_auth="Request not allowed!\n\nYou are not authorised to carry out the request."):
        self.pages = []
        self.pages_root = []
        self.pages_path = path
        self.pages_enabled = enabled
        self.pages_execute = execute
        self.pages_ext_allow = ext_allow
        self.pages_ext_deny = ext_deny
        self.pages_ext_deny.append("allowed")
        self.pages_allow_all = allow_all
        self.pages_allow = allow
        self.pages_deny = deny

        self.pages_index = index
        self.pages_index_depth = int(pages_index_depth)
        self.files_index_depth = int(files_index_depth)

        self.pages_content_index_header = content_index_header.replace("!n!", "\n")
        self.pages_content_index_footer = content_index_footer.replace("!n!", "\n")
        self.pages_content_index_pages_header = content_index_pages_header.replace("!n!", "\n")
        self.pages_content_index_pages_entry = content_index_pages_entry.replace("!n!", "\n")
        self.pages_content_index_files_header = content_index_files_header.replace("!n!", "\n")
        self.pages_content_index_files_entry = content_index_files_entry.replace("!n!", "\n")
        self.pages_content_index = content_index.replace("!n!", "\n")
        self.pages_content_auth = content_auth.replace("!n!", "\n")


    def files_config(self, enabled=True, path="files", execute=True, ext_allow=[], ext_deny=[], allow_all=True, allow=[], deny=[]):
        self.files = []
        self.files_index = []
        self.files_enabled = enabled
        self.files_path = path
        self.files_execute = execute
        self.files_ext_allow = ext_allow
        self.files_ext_deny = ext_deny
        self.files_ext_deny.append("allowed")
        self.files_allow_all = allow_all
        self.files_allow = allow
        self.files_deny = deny


    def upload_config(self, enabled=False, path="files", ext_allow=[], ext_deny=[], allow_all=False, allow=[], deny=[], register=True):
        self.upload_enabled = enabled
        self.upload_path = path
        self.upload_ext_allow = ext_allow
        self.upload_ext_deny = ext_deny
        self.upload_ext_deny.append("allowed")
        self.upload_allow_all = allow_all
        self.upload_allow = allow
        self.upload_deny = deny
        self.upload_register = register


    def start(self):
        if self.announce_startup or self.announce_periodic:
            self.announce(initial=True)

        if self.pages_enabled:
            if not self.pages_path.startswith("/") and self.storage_path:
                self.pages_path = self.storage_path + "/" + self.pages_path
            if not os.path.isdir(self.pages_path):
                os.makedirs(self.pages_path)
                RNS.log("Server - Pages: Path was created", RNS.LOG_NOTICE)
            RNS.log("Server - Pages: Path: " + self.pages_path, RNS.LOG_INFO)

        if self.files_enabled:
            if not self.files_path.startswith("/") and self.storage_path:
                self.files_path = self.storage_path + "/" + self.files_path
            if not os.path.isdir(self.files_path):
                os.makedirs(self.files_path)
                RNS.log("Server - Files: Path was created", RNS.LOG_NOTICE)
            RNS.log("Server - Files: Path: " + self.files_path, RNS.LOG_INFO)

        if self.upload_enabled:
            if not self.upload_path.startswith("/") and self.storage_path:
                self.upload_path = self.storage_path + "/" + self.upload_path
            if not os.path.isdir(self.upload_path):
                os.makedirs(self.upload_path)
                RNS.log("Server - Upload: Path was created", RNS.LOG_NOTICE)
            RNS.log("Server - Upload: Path: " + self.upload_path, RNS.LOG_INFO)

        if self.register_startup or self.register_periodic:
            self.register(True)


    def stop(self):
        pass


    def statistic_get(self):
        return {
            "ts": self.statistic["ts"],
            "connects": self.statistic["connects"],
            "online": len(self.statistic["online"]),
            "rx_bytes": self.statistic["rx_bytes"],
            "tx_bytes": self.statistic["tx_bytes"],
            "pages": self.statistic["pages"],
            "files": self.statistic["files"],
            "uploads": self.statistic["uploads"]
        }


    def statistic_set(self, statistic):
        self.statistic = statistic


    def statistic_reset(self):
        self.statistic = {"ts": time.time(), "connects": 0, "online": {}, "rx_bytes": 0, "tx_bytes": 0, "pages": 0, "files": 0, "uploads": 0}


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
                    self.register_now(initial)
            return

        self.register_now(initial)


    def register_now(self, initial=False):
        RNS.log("Server - Register", RNS.LOG_DEBUG)

        if self.pages_enabled:
            self.pages_register()

        if self.files_enabled:
            self.files_register()


    def peer_connected(self, link):
        RNS.log("Server - Peer connected to "+str(self.destination), RNS.LOG_VERBOSE)
        try:
            self.statistic["connects"] += 1
            self.statistic["online"][link.hash] = True
        except:
            pass
        link.set_link_closed_callback(self.peer_disconnected)

        if self.upload_enabled:
            link.set_remote_identified_callback(self.upload_remote_identified)
            link.set_resource_strategy(RNS.Link.ACCEPT_APP)
            link.set_resource_callback(self.upload_resource_callback)
            link.set_resource_started_callback(self.upload_resource_started)
            link.set_resource_concluded_callback(self.upload_resource_concluded)


    def peer_disconnected(self, link):
        RNS.log("Server - Peer disconnected from "+str(self.destination), RNS.LOG_VERBOSE)
        try:
            self.statistic["rx_bytes"] += link.rxbytes
            self.statistic["tx_bytes"] += link.txbytes
            if link.hash in self.statistic["online"]:
                del self.statistic["online"][link.hash]
        except:
            pass


    def pages_register(self):
        array = self.pages.copy()

        self.pages = []
        self.pages_scan(self.pages_path)
        self.pages.sort()

        self.pages_root = []
        self.pages_root_scan(self.pages_path)
        self.pages_root.sort()

        for page in array:
            if page not in self.pages:
                self.destination.deregister_request_handler(page)

        for page in self.pages:
            if page not in array:
                self.destination.register_request_handler(page, response_generator=self.pages_download, allow=RNS.Destination.ALLOW_ALL)

        if not "/page/index.mu" in self.pages:
            self.destination.deregister_request_handler("/page/index.mu")
            self.destination.register_request_handler("/page/index.mu", response_generator=self.pages_download_index, allow=RNS.Destination.ALLOW_ALL)


    def pages_scan(self, base_path):
        files = [file for file in os.listdir(base_path) if os.path.isfile(os.path.join(base_path, file)) and file[:1] != "."]
        directories = [file for file in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, file)) and file[:1] != "."]

        for file in files:
            ext = os.path.splitext(file)[1][1:]
            if ext in self.pages_ext_allow or ext not in self.pages_ext_deny:
                file = base_path+"/"+file
                self.pages.append("/page"+file.replace(self.pages_path, ""))

        for directory in directories:
            self.pages_scan(base_path+"/"+directory)


    def pages_root_scan(self, base_path):
        files = [file for file in os.listdir(base_path) if os.path.isfile(os.path.join(base_path, file)) and file[:1] != "."]

        for file in files:
            ext = os.path.splitext(file)[1][1:]
            if ext in self.pages_ext_allow or ext not in self.pages_ext_deny:
                file = base_path+"/"+file
                self.pages_root.append("/page"+file.replace(self.pages_path, ""))


    def pages_local(self, path, data):
        if not self.pages_enabled:
            return "".encode("utf-8")

        if path in self.pages:
            return self.pages_download(path, data, request_id=None, link_id=None, remote_identity=None, requested_at=None)
        elif path == "/page/index.mu":
            return self.pages_download_index(path, data, request_id=None, link_id=None, remote_identity=None, requested_at=None)
        else:
            return "".encode("utf-8")


    def pages_download(self, path, data, request_id, link_id, remote_identity, requested_at):
        if self.limiter_server and not self.limiter_server.handle("server"):
            return None

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return None

        if request_id:
            RNS.log("Server - Pages: Request "+RNS.prettyhexrep(request_id)+" for: "+str(path), RNS.LOG_VERBOSE)
        else:
            RNS.log("Server - Pages: Request <local> for: "+str(path), RNS.LOG_VERBOSE)

        if remote_identity:
            dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        else:
            dest = None

        if data:
            RNS.log("Server - Pages: Data: "+str(data), RNS.LOG_DEBUG)

        try:
            self.statistic["pages"] += 1
        except:
            pass

        file_path = path.replace("/page", self.pages_path, 1)

        allowed_path = file_path+".allowed"
        allowed = False

        if os.path.isfile(allowed_path):
            allowed_list = []

            try:
                if self.pages_execute and os.access(allowed_path, os.X_OK):
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
                            RNS.log("Server - Pages: Could not decode RNS Identity hash from: "+str(hash_str), RNS.LOG_DEBUG)
                            RNS.log("Server - Pages: The contained exception was: "+str(e), RNS.LOG_DEBUG)

            except Exception as e:
                RNS.log("Server - Pages: Error while fetching list of allowed identities for request: "+str(e), RNS.LOG_ERROR)

            if hasattr(remote_identity, "hash"):
                if self.destination_mode == False and remote_identity.hash in allowed_list:
                    allowed = True
                elif self.destination_mode == True and dest in allowed_list:
                    allowed = True

        elif self.pages_allow_all:
            allowed = True

        elif hasattr(remote_identity, "hash"):
            if self.destination_mode == False and remote_identity.hash in self.pages_allow:
                allowed = True
            elif self.destination_mode == True and dest in self.pages_allow:
                allowed = True

        if hasattr(remote_identity, "hash"):
            if self.destination_mode == False and remote_identity.hash in self.pages_deny:
                allowed = False
            elif self.destination_mode == True and dest in self.pages_deny:
                allowed = False

        if request_id == None:
            allowed = True

        try:
            if allowed:
                RNS.log("Server - Pages: Serving "+file_path, RNS.LOG_VERBOSE)
                if self.pages_execute and os.access(file_path, os.X_OK):
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
                RNS.log("Server - Pages: Request denied", RNS.LOG_VERBOSE)
                return self.pages_content_auth.encode("utf-8")

        except Exception as e:
            RNS.log("Server - Pages: Error occurred while handling request for: "+str(path), RNS.LOG_ERROR)
            RNS.log("Server - Pages: The contained exception was: "+str(e), RNS.LOG_ERROR)
            return None


    def pages_download_index(self, path, data, request_id, link_id, remote_identity, requested_at):
        if self.limiter_server and not self.limiter_server.handle("server"):
            return None

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return None

        if request_id:
            RNS.log("Server - Pages: Serving index for request "+RNS.prettyhexrep(request_id)+" for: "+str(path), RNS.LOG_VERBOSE)
        else:
            RNS.log("Server - Pages: Serving index for request <local> for: "+str(path), RNS.LOG_VERBOSE)

        if remote_identity:
            dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        else:
            dest = None

        if data:
            RNS.log("Server - Pages: Data: "+str(data), RNS.LOG_DEBUG)

        try:
            self.statistic["pages"] += 1
        except:
            pass

        allowed = False

        if self.pages_allow_all or self.files_allow_all:
            allowed = True

        if hasattr(remote_identity, "hash"):
            if self.destination_mode == False and (remote_identity.hash in self.pages_allow or remote_identity.hash in self.files_allow):
                allowed = True
            elif self.destination_mode == True and (dest in self.pages_allow or dest in self.files_allow):
                allowed = True

        if hasattr(remote_identity, "hash"):
            if self.destination_mode == False and (remote_identity.hash in self.pages_deny or remote_identity.hash in self.files_deny):
                allowed = False
            elif self.destination_mode == True and (dest in self.pages_deny or dest in self.files_deny):
                allowed = False

        if request_id == None:
            allowed = True

        if allowed:
            if self.pages_content_index_header != "":
                content = self.pages_content_index_header+"\n\n"
            else:
                content = ""

            if self.pages_index == "none":
                content = ""

            elif self.pages_index == "pages":
                if len(self.pages) > 0:
                    content += self.pages_content_index_pages_header
                    if self.pages_index_depth > 1:
                        for page in self.pages:
                            content_add = self.pages_content_index_pages_entry
                            content_add = content_add.replace("{name}", page.replace("/page/", "", 1))
                            content_add = content_add.replace("{url}", page)
                            content += content_add
                    else:
                        for page in self.pages_root:
                            content_add = self.pages_content_index_pages_entry
                            content_add = content_add.replace("{name}", page.replace("/page/", "", 1))
                            content_add = content_add.replace("{url}", page)
                            content += content_add
                if self.pages_content_index_footer != "":
                    content += self.pages_content_index_footer

            elif self.pages_index == "files":
                if len(self.files) > 0:
                    content += self.pages_content_index_files_header
                    if self.files_index_depth > 1:
                        for file in self.files:
                            content_add = self.pages_content_index_files_entry
                            content_add = content_add.replace("{name}", file.replace("/file/", "", 1))
                            content_add = content_add.replace("{url}", file)
                            content += content_add
                    else:
                        for file in self.files_root:
                            content_add = self.pages_content_index_files_entry
                            content_add = content_add.replace("{name}", file.replace("/file/", "", 1))
                            content_add = content_add.replace("{url}", file)
                            content += content_add
                if self.pages_content_index_footer != "":
                    content += self.pages_content_index_footer

            elif self.pages_index == "both":
                if len(self.pages) > 0:
                    content += self.pages_content_index_pages_header
                    if self.pages_index_depth > 1:
                        for page in self.pages:
                            content_add = self.pages_content_index_pages_entry
                            content_add = content_add.replace("{name}", page.replace("/page/", "", 1))
                            content_add = content_add.replace("{url}", page)
                            content += content_add
                    else:
                        for page in self.pages_root:
                            content_add = self.pages_content_index_pages_entry
                            content_add = content_add.replace("{name}", page.replace("/page/", "", 1))
                            content_add = content_add.replace("{url}", page)
                            content += content_add
                if len(self.files) > 0:
                    content += self.pages_content_index_files_header
                    if self.files_index_depth > 1:
                        for file in self.files:
                            content_add = self.pages_content_index_files_entry
                            content_add = content_add.replace("{name}", file.replace("/file/", "", 1))
                            content_add = content_add.replace("{url}", file)
                            content += content_add
                    else:
                        for file in self.files_root:
                            content_add = self.pages_content_index_files_entry
                            content_add = content_add.replace("{name}", file.replace("/file/", "", 1))
                            content_add = content_add.replace("{url}", file)
                            content += content_add
                if self.pages_content_index_footer != "":
                    content += self.pages_content_index_footer

            else:
                content = self.pages_content_index

        else:
            RNS.log("RNS - Pages: Request denied", RNS.LOG_VERBOSE)
            return self.content_auth.encode("utf-8")

        content = content.encode("utf-8")

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(content))

        if self.limiter_peer:
            self.limiter_peer.handle_size(str(remote_identity), len(content))

        return content


    def files_register(self):
        array = self.files.copy()

        self.files = []
        self.files_scan(self.files_path)
        self.files.sort()

        self.files_root = []
        self.files_root_scan(self.files_path)
        self.files_root.sort()

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
                self.files.append("/file"+file.replace(self.files_path, ""))

        for directory in directories:
            self.files_scan(base_path+"/"+directory)


    def files_root_scan(self, base_path):
        files = [file for file in os.listdir(base_path) if os.path.isfile(os.path.join(base_path, file)) and file[:1] != "."]

        for file in files:
            ext = os.path.splitext(file)[1][1:]
            if ext in self.files_ext_allow or ext not in self.files_ext_deny:
                file = base_path+"/"+file
                self.files_root.append("/file"+file.replace(self.files_path, ""))


    def files_local(self, path, data):
        if not self.files_enabled:
            return None

        if path in self.files:
            return self.files_download(path, data, request_id=None, remote_identity=None, requested_at=None)
        else:
            return None


    def files_download(self, path, data, request_id, remote_identity, requested_at):
        if self.limiter_server and not self.limiter_server.handle("server"):
            return None

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return None

        if request_id:
            RNS.log("Server - Files: Request "+RNS.prettyhexrep(request_id)+" for: "+str(path), RNS.LOG_VERBOSE)
        else:
            RNS.log("Server - Files: Request <local> for: "+str(path), RNS.LOG_VERBOSE)

        if remote_identity:
            dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        else:
            dest = None

        try:
            self.statistic["files"] += 1
        except:
            pass

        file_path = path.replace("/file", self.files_path, 1)

        allowed_path = file_path+".allowed"
        allowed = False

        if os.path.isfile(allowed_path):
            allowed_list = []

            try:
                if self.files_execute and os.access(allowed_path, os.X_OK):
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
                fh = open(file_path, "rb")
                file_data = fh.read()
                fh.close()
                if self.limiter_server:
                    self.limiter_server.handle_size("server", len(file_data))
                if self.limiter_peer:
                    self.limiter_peer.handle_size(str(remote_identity), len(file_data))
                return [path.replace("/file/", "", 1), file_data]
            else:
                RNS.log("Server - Files: Request denied", RNS.LOG_VERBOSE)
                return None

        except Exception as e:
            RNS.log("Server - Files: Error occurred while handling request for: "+str(path), RNS.LOG_ERROR)
            RNS.log("Server - Files: The contained exception was: "+str(e), RNS.LOG_ERROR)
            return None


    def upload_remote_identified(self, link, identity):
        if identity.hash in self.upload_allow:
            RNS.log("Server - Upload: Authenticated sender", RNS.LOG_VERBOSE)
        else:
            if not self.upload_allow_all:
                RNS.log("Server - Upload: Sender not allowed, tearing down link", RNS.LOG_VERBOSE)
                link.teardown()
            else:
                pass


    def upload_resource_callback(self, resource):
        remote_identity = resource.link.get_remote_identity()

        if self.limiter_server and not self.limiter_server.handle("server"):
            return False

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return False

        if self.upload_allow_all:
            return True

        if remote_identity != None:
            dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        else:
            dest = None

        if self.destination_mode == False and remote_identity.hash in self.upload_allow:
            return True
        elif self.destination_mode == True and dest in self.upload_allow:
            return True

        return False


    def upload_resource_started(self, resource):
        if resource.link.get_remote_identity():
            id_str = " from "+RNS.prettyhexrep(resource.link.get_remote_identity().hash)
        else:
            id_str = ""

        RNS.log("Server - Upload: Starting resource transfer "+RNS.prettyhexrep(resource.hash)+id_str, RNS.LOG_DEBUG)


    def upload_resource_concluded(self, resource):
        if resource.status == RNS.Resource.COMPLETE:
            RNS.log("Server - Upload: "+str(resource)+" completed", RNS.LOG_DEBUG)

            if resource.total_size > 4:
                try:
                    self.statistic["uploads"] += 1
                except:
                    pass

                try:
                    file_name_len = int.from_bytes(resource.data.read(2), "big")
                    file_name = resource.data.read(file_name_len).decode("utf-8")

                    file_path = self.upload_path+"/"+file_name
                    file_name, file_ext = file_path.rsplit('.', 1)
                    i = 1
                    while os.path.isfile(file_path):
                        file_path = file_name+"("+str(i)+")."+file_ext
                        i += 1

                    file = open(file_path, "wb")
                    file.write(resource.data.read())
                    file.close()

                    if self.upload_register:
                        if self.pages_enabled and self.pages_path == self.upload_path:
                            self.pages_register()
                        elif self.files_enabled and self.files_path == self.upload_path:
                            self.files_register()

                except Exception as e:
                    RNS.log("Server - Upload: Resource failed: "+str(e), RNS.LOG_ERROR)

            else:
                RNS.log("Server - Upload: Invalid data received, ignoring resource", RNS.LOG_DEBUG)

        else:
            RNS.log("Server - Upload: Resource failed", RNS.LOG_DEBUG)


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
def setup(path=None, path_rns=None, path_log=None, loglevel=None, service=False, require_shared_instance=False):
    global PATH
    global PATH_RNS
    global LOG_LEVEL
    global LOG_FILE
    global RNS_CONNECTION
    global RNS_SERVER_PAGE

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

    RNS_CONNECTION = RNS.Reticulum(configdir=PATH_RNS, loglevel=rns_loglevel, require_shared_instance=require_shared_instance)

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
    if len(fields) > 0:
        announce_data = [CONFIG["rns_server"]["display_name"].encode("utf-8"), None, fields]
        log("RNS - Configured announce data: "+str(announce_data), LOG_DEBUG)
        announce_data = msgpack.packb(announce_data)

    RNS_SERVER_PAGE = ServerPage(
        storage_path=path,
        identity_file="identity",
        identity=None,
        ratchets=CONFIG["rns_server"].getboolean("destination_ratchets"),
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
        statistic=None,
        limiter_server_enabled=CONFIG["rns_server"].getboolean("limiter_server_enabled"),
        limiter_server_calls=CONFIG["rns_server"]["limiter_server_calls"],
        limiter_server_size=CONFIG["rns_server"]["limiter_server_size"],
        limiter_server_duration=CONFIG["rns_server"]["limiter_server_duration"],
        limiter_peer_enabled=CONFIG["rns_server"].getboolean("limiter_peer_enabled"),
        limiter_peer_calls=CONFIG["rns_server"]["limiter_peer_calls"],
        limiter_peer_size=CONFIG["rns_server"]["limiter_peer_size"],
        limiter_peer_duration=CONFIG["rns_server"]["limiter_peer_duration"]
    )

    RNS_SERVER_PAGE.pages_config(
        enabled=CONFIG["rns_server"].getboolean("pages_enabled"),
        path=CONFIG["rns_server"]["pages_path"],
        execute=CONFIG["rns_server"].getboolean("pages_execute"),
        ext_allow=CONFIG["rns_server"]["pages_ext_allow"].split(","),
        ext_deny=CONFIG["rns_server"]["pages_ext_deny"].split(","),
        index=CONFIG["rns_server"]["index"],
        pages_index_depth=CONFIG["rns_server"]["pages_index_depth"],
        files_index_depth=CONFIG["rns_server"]["files_index_depth"],
        content_index_header=CONFIG["rns_server"]["content_index_header"],
        content_index_footer=CONFIG["rns_server"]["content_index_footer"],
        content_index_pages_header=CONFIG["rns_server"]["content_index_pages_header"],
        content_index_pages_entry=CONFIG["rns_server"]["content_index_pages_entry"],
        content_index_files_header=CONFIG["rns_server"]["content_index_files_header"],
        content_index_files_entry=CONFIG["rns_server"]["content_index_files_entry"],
        content_index=CONFIG["rns_server"]["content_index"],
        content_auth=CONFIG["rns_server"]["content_auth"]
    )

    RNS_SERVER_PAGE.files_config(
        enabled=CONFIG["rns_server"].getboolean("files_enabled"),
        path=CONFIG["rns_server"]["files_path"],
        execute=CONFIG["rns_server"].getboolean("files_execute"),
        ext_allow=CONFIG["rns_server"]["files_ext_allow"].split(","),
        ext_deny=CONFIG["rns_server"]["files_ext_deny"].split(",")
    )

    RNS_SERVER_PAGE.upload_config(
        enabled=CONFIG["rns_server"].getboolean("upload_enabled"),
        path=CONFIG["rns_server"]["upload_path"],
        ext_allow=CONFIG["rns_server"]["upload_ext_allow"].split(","),
        ext_deny=CONFIG["rns_server"]["upload_ext_deny"].split(","),
        allow_all=CONFIG["rns_server"].getboolean("upload_allow_all"),
        register=True
    )

    RNS_SERVER_PAGE.start()

    log("RNS - Connected", LOG_DEBUG)

    log("...............................................................................", LOG_FORCE)
    log("RNS - Address: " + RNS.prettyhexrep(RNS_SERVER_PAGE.destination_hash()), LOG_FORCE)
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
        parser.add_argument("-rs", "--require_shared_instance", action="store_true", default=False, help="Require a shared reticulum instance")

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

        setup(path=params.path, path_rns=params.path_rns, path_log=params.path_log, loglevel=params.loglevel, service=params.service, require_shared_instance=params.require_shared_instance)

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
name = RNS Server Page/File


#### RNS server settings ####
[rns_server]

# Enable ratchets for the destination
destination_ratchets = No

# Destination name & type need to fits the RNS protocoll
# to be compatibel with other RNS programs.
destination_name = nomadnetwork
destination_type = node

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


# Pages
pages_enabled = True
pages_path = pages
pages_execute = True
pages_ext_allow = #,-separated list
pages_ext_deny = py,sh #,-separated list
index = content #none=none/empty, #content=configured string, pages=Index pages, files=Index files, both=Index pages/files
pages_index_depth = 255 #0=root, 255=all
files_index_depth = 255 #0=root, 255=all
content_index_header = 
content_index_footer = 
content_index_pages_header = >>Index - Pages!n!!n!
content_index_pages_entry = `[{name}`:{url}]`!n!!n!
content_index_files_header = >>Index - Files!n!!n!
content_index_files_entry = `[{name}`:{url}]`!n!!n!
content_index = Default Home Page!n!!n!This server is serving pages, but the home page file (index.mu) was not found in the page storage directory.
content_auth = Request Not Allowed!n!!n!You are not authorised to carry out the request.

# Files
files_enabled = True
files_path = files
files_execute = True
files_ext_allow = #,-separated list
files_ext_deny = #,-separated list

# Upload
upload_enabled = False
upload_path = files
upload_ext_allow = #,-separated list
upload_ext_deny = py,sh #,-separated list
upload_allow_all = False


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