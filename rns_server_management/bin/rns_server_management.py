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
import shutil
import pwd
import grp
import time
import datetime
import argparse
import random

#### Config ####
import configparser

#### Process ####
import threading

#### Console ####
import subprocess
import pty
import termios
import select
import struct
import fcntl
import shlex
import signal

#### JSON ####
import json

#### Regex ####
import re

#### Polib ####
# Install: pip3 install polib
try:
    import polib
except ImportError:
    pass

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "RNS Server Management"
DESCRIPTION = "Tool for the remote administration of servers"
VERSION = "0.0.1 (2024-05-31)"
COPYRIGHT = "(c) 2024 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/"+os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None


#### Global Variables - System (Not changeable) ####
CONFIG = None
RNS_CONNECTION = None
RNS_SERVER_MANAGEMENT = None

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
# ServerManagementConsole Class


class ServerManagementConsole:
    fd = None
    pid = None


    def size(self, rows, cols, xpix=0, ypix=0):
        if self.fd:
            size = struct.pack("HHHH", rows, cols, xpix, ypix)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, size)


    def get(self, timeout=None, read_bytes=None):
        if not timeout:
            timeout = self.timeout
        if not read_bytes:
            read_bytes = self.read_bytes
        if not self.fd: return ["", 0]
        (data_ready, _, _) = select.select([self.fd], [], [], timeout)
        if not data_ready: return ["", 0]
        output = ""
        state = 0
        try:
            read_bytes = 1024 * read_bytes
            output = os.read(self.fd, read_bytes).decode()
        except Exception as e:
            output = str(e)
            state = e.errno
            if e.errno == 5: self.stop()
        return [output, state]


    def set(self, cmd):
        if not self.fd and not self.restart_session: return False
        if not self.fd and self.restart_session: self.start()
        if not self.fd: return False
        try:
            cmd = cmd.strip() + "\n"
            os.write(self.fd, cmd.encode())
        except:
            return False
        return True


    def set_env(self, env=None):
        if not env: return
        if len(env) == 0: return

        if "bash" in self.cmd:
            cmd = "export"
        elif "sh" in self.cmd:
            cmd = "setenv"
        else:
            cmd = ""

        if cmd != "":
            for key in env.keys():
                self.set(cmd + " " + key + "=" + env[key])
            time.sleep(1)
            self.get()


    def start(self):
        if not self.pid:
            (pid, fd) = pty.fork()
            if pid == 0:
                cmd = [self.cmd] + shlex.split(self.cmd_args)
                if self.path != "": os.chdir(self.path)
                subprocess.run(cmd)
            else:
                self.fd = fd
                self.pid = pid
                self.size(self.fd, self.rows, self.cols)
            self.set_env(self.env)


    def stop(self):
        if self.fd:
            fd = self.fd
            self.fd = None
            self.pid = None
            try:
                os.kill(fd, signal.SIGTERM)
            except:
                return False
        return True


    def __init__(self, path="", cmd="bash", cmd_args="", env=None, timeout=0, read_bytes=20, rows=100, cols=200, restart_session=True):
        self.path = path
        self.cmd = cmd
        self.cmd_args = cmd_args
        self.env = env
        self.timeout = timeout
        self.read_bytes = read_bytes
        self.rows = rows
        self.cols = cols
        self.restart_session = restart_session
        self.start()
        return


    def __del__(self):
        self.stop()
        return


##############################################################################################################
# ServerManagement Class


class ServerManagement:
    KEY_RESULT        = "result" # Result
    KEY_RESULT_REASON = "result_reason" # Result - Reason

    LIMITER_TYPE_JSON    = 0x00
    LIMITER_TYPE_MSGPACK = 0x01
    LIMITER_TYPE_NONE    = 0x02

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


    def __init__(self, storage_path=None, identity_file="identity", identity=None, ratchets=False, destination_name="nomadnetwork", destination_type="management", destination_conv_name="lxmf", destination_conv_type="delivery", destination_mode=True, announce_startup=False, announce_startup_delay=0, announce_periodic=False, announce_periodic_interval=360, announce_data="", announce_hidden=False, allow=[], statistic=None, link_timeout=300, default_user=None, default_user_interfaces=None, default_user_hops=None, default_user_callback=None, configs_cmd=None, environment_variables=None, services_system_path="/etc/systemd/system", services_system_extension=".service", services_files=[], limiter_server_enabled=False, limiter_server_calls=1000, limiter_server_size=0, limiter_server_duration=60, limiter_peer_enabled=True, limiter_peer_calls=0, limiter_peer_size=0, limiter_peer_duration=60):
        self.storage_path = storage_path
        self.configs_path = self.storage_path+"/configs"
        self.files_path = os.path.expanduser("~")
        self.infos_path = self.storage_path+"/infos"
        self.locales_path = self.storage_path+"/locales"
        self.logs_path = self.storage_path+"/logs"
        self.notes_path = self.storage_path+"/notes.txt"
        self.scripts_path = self.storage_path+"/scripts"
        self.services_path = self.storage_path+"/services"

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

        self.allow = allow

        if statistic:
            self.statistic = statistic
        else:
            self.statistic_reset()

        self.link_timeout = int(link_timeout)

        self.default_user = default_user
        self.default_user_interfaces = default_user_interfaces
        self.default_user_hops = default_user_hops
        self.default_user_callback = default_user_callback

        self.configs_cmd_mapping = configs_cmd
        if self.configs_cmd_mapping == None:
            self.configs_cmd_mapping = {}

        self.environment_variables = environment_variables
        if self.environment_variables == None:
            self.environment_variables = {}

        self.services_system_path = services_system_path
        self.services_system_extension = services_system_extension
        self.services_files = services_files

        if self.storage_path:
            if not os.path.isdir(self.storage_path):
                os.makedirs(self.storage_path)
                RNS.log("Server - Storage path was created", RNS.LOG_NOTICE)
            if not os.path.isdir(self.configs_path):
                os.makedirs(self.configs_path)
            if not os.path.isdir(self.files_path):
                os.makedirs(self.files_path)
            if not os.path.isdir(self.infos_path):
                os.makedirs(self.infos_path)
            if not os.path.isdir(self.logs_path):
                os.makedirs(self.logs_path)
            if not os.path.isdir(self.scripts_path):
                os.makedirs(self.scripts_path)
            if not os.path.isdir(self.services_path):
                os.makedirs(self.services_path)
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

        self.link = None
        self.link_ts = 0
        self.buffer = None
        self.locales = None

        if self.announce_startup or self.announce_periodic:
            self.announce(initial=True)

        self.register()

        self.scripts = None
        self.scripts_env = {}

        self.console = ServerManagementConsole()
        self.console_env = {}
        self.configs_reboot = False

        if limiter_server_enabled:
            self.limiter_server = RateLimiter(int(limiter_server_calls), int(limiter_server_size), int(limiter_server_duration))
        else:
            self.limiter_server = None

        if limiter_peer_enabled:
            self.limiter_peer = RateLimiter(int(limiter_peer_calls), int(limiter_peer_size), int(limiter_peer_duration))
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
            "online": len(self.statistic["online"])
        }


    def statistic_set(self, statistic):
        self.statistic = statistic


    def statistic_reset(self):
        self.statistic = {"ts": time.time(), "connects": 0, "online": {}}


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
        self.register_request_handler(path="configs_list", response_generator=self.configs_list, limiter_type=self.LIMITER_TYPE_MSGPACK)
        self.register_request_handler(path="configs_cmd", response_generator=self.configs_cmd, limiter_type=self.LIMITER_TYPE_MSGPACK)
        self.register_request_handler(path="files_list", response_generator=self.files_list, limiter_type=self.LIMITER_TYPE_MSGPACK)
        self.register_request_handler(path="files_cmd", response_generator=self.files_cmd, limiter_type=self.LIMITER_TYPE_MSGPACK)
        self.register_request_handler(path="files_download", response_generator=self.files_download, limiter_type=self.LIMITER_TYPE_NONE)
        self.register_request_handler(path="infos_list", response_generator=self.infos_list, limiter_type=self.LIMITER_TYPE_MSGPACK)
        self.register_request_handler(path="logs_list", response_generator=self.logs_list, limiter_type=self.LIMITER_TYPE_MSGPACK)
        self.register_request_handler(path="logs_cmd", response_generator=self.logs_cmd, limiter_type=self.LIMITER_TYPE_MSGPACK)
        self.register_request_handler(path="notes_cmd", response_generator=self.notes_cmd, limiter_type=self.LIMITER_TYPE_MSGPACK)
        self.register_request_handler(path="scripts_list", response_generator=self.scripts_list, limiter_type=self.LIMITER_TYPE_MSGPACK)
        self.register_request_handler(path="services_list", response_generator=self.services_list, limiter_type=self.LIMITER_TYPE_MSGPACK)
        self.register_request_handler(path="services_cmd", response_generator=self.services_cmd, limiter_type=self.LIMITER_TYPE_MSGPACK)
        self.register_request_handler(path="services_logs", response_generator=self.services_logs, limiter_type=self.LIMITER_TYPE_MSGPACK)



    def register_request_handler(self, path, response_generator=None, allow=None, allowed_list=None, limiter=None, limiter_type=None):
        self.destination.register_request_handler(
            path=path,
            response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: self.request_handler(response_generator, limiter, limiter_type, path, data, request_id, link_id, remote_identity, requested_at),
            allow=allow if allow != None else RNS.Destination.ALLOW_ALL,
            allowed_list=allowed_list
        )


    def deregister_request_handler(self, path):
        self.destination.deregister_request_handler(path)


    def request_handler(self, callback, limiter, limiter_type, path, data, request_id, link_id, remote_identity, requested_at):
        if not remote_identity:
            if limiter_type == self.LIMITER_TYPE_MSGPACK:
                return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_IDENTITY})
            else:
                return None

        if self.limiter_server and not self.limiter_server.handle("server"):
            if limiter_type == self.LIMITER_TYPE_MSGPACK:
                return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_SERVER})
            else:
                return None

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            if limiter_type == self.LIMITER_TYPE_MSGPACK:
                return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_PEER})
            else:
                return None

        if limiter and not limiter.handle(str(remote_identity)):
            if limiter_type == self.LIMITER_TYPE_MSGPACK:
                return msgpack.packb({self.KEY_RESULT: self.RESULT_LIMIT_PEER})
            else:
                return None

        data = callback(path, data, request_id, link_id, remote_identity, requested_at)

        if self.limiter_server:
            self.limiter_server.handle_size("server", len(data))

        if self.limiter_peer:
            self.limiter_peer.handle_size(str(remote_identity), len(data))

        if limiter:
            limiter.handle_size(str(remote_identity), len(data))

        return data


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
            if link.hash in self.statistic["online"]:
                del self.statistic["online"][link.hash]
        except:
            pass


    def peer_identified(self, link, identity):
        if not identity:
            link.teardown()
            return

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, identity)

        if len(self.allow) == 0:
            hop_interface = RNS_CONNECTION.get_next_hop_if_name(dest)
            if self.default_user_interfaces == None or len(self.default_user_interfaces) == 0 or any(hop_interface.startswith(prefix) for prefix in self.default_user_interfaces):
                hop_count = RNS.Transport.hops_to(dest)
                #hop_interface_self = str(RNS.Transport.next_hop_interface(dest))
                #if hop_interface_self and hop_interface_self.startswith("LocalInterface"):
                #    hop_count -= 1
                if self.default_user_hops == None or self.default_user_hops == 0 or hop_count <= self.default_user_hops:
                    RNS.log("Server - Create new user "+RNS.prettyhexrep(dest)+" connected via "+hop_interface+" with "+str(hop_count)+" hops", RNS.LOG_DEBUG)
                    if self.default_user_callback:
                        self.allow = self.default_user_callback(dest)

        if dest not in self.allow:
            link.teardown()
            return

        self.scripts_env = {}
        self.console_env = {}
        if identity != None:
            self.scripts_env["remote_identity"] = RNS.hexrep(identity.hash, delimit=False)
            self.console_env["remote_identity"] = RNS.hexrep(identity.hash, delimit=False)
        if dest != None:
            self.scripts_env["dest"] = RNS.hexrep(dest, delimit=False)
            self.console_env["dest"] = RNS.hexrep(dest, delimit=False)
        self.scripts_env.update(self.environment_variables)
        self.console_env.update(self.environment_variables)

        link.set_resource_strategy(RNS.Link.ACCEPT_APP)
        link.set_resource_callback(self.files_upload_callback)
        link.set_resource_started_callback(self.files_upload_started)
        link.set_resource_concluded_callback(self.files_upload_concluded)
        self.link = link
        self.link_ts = time.time()
        channel = link.get_channel()
        if self.buffer:
            self.buffer.close()
        self.buffer = RNS.Buffer.create_bidirectional_buffer(0, 0, channel, self.buffer_rx)
        self.buffer_tx_thread = threading.Thread(target=self.buffer_tx, daemon=True)
        self.buffer_tx_thread.start()
        self.locales = None


    #################################################
    # Log                                           #
    #################################################


    def log(self, text="", level=None):
        if level == None:
            level = RNS.LOG_ERROR

        RNS.log(text, level)


    def log_exception(self, e, text="", level=None):
        import traceback

        if level == None:
            level = RNS.LOG_ERROR

        RNS.log(text+" - An "+str(type(e))+" occurred: "+str(e), level)
        RNS.log("".join(traceback.TracebackException.from_exception(e).format()), level)


    #################################################
    # Configs                                       #
    #################################################


    def configs_list(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK

        data_return["configs"] = {}

        if "filter" in data and data["filter"]:
            filter = data["filter"]
        else:
            filter = False

        if "search" in data and data["search"]:
            search = data["search"]
        else:
            search = False

        try:
            env_map = {}
            if "PATH" in os.environ:
                env_map["PATH"] = os.environ["PATH"]
            if link_id != None:
                env_map["link_id"] = RNS.hexrep(link_id, delimit=False)
            if remote_identity != None:
                env_map["remote_identity"] = RNS.hexrep(remote_identity.hash, delimit=False)
            if dest != None:
                env_map["dest"] = RNS.hexrep(dest, delimit=False)
            env_map.update(self.environment_variables)

            if "path" in data and data["path"] != "" and data["path"] != "/":
                data_return["path"] = [data["path"], self.locales_text(data["path"], path=True)]
                path = self.configs_path+data["path"]
            else:
                data_return["path"] = ["", ""]
                path = self.configs_path

            if not os.path.isdir(path):
                data_return["path"] = ["", ""]
                path = self.configs_path

            files = []
            folders = []
            items = os.listdir(path)
            for item in items:
                if item.startswith("."):
                    continue
                full_path = os.path.join(path, item)
                if os.path.isfile(full_path):
                    files.append(full_path)
                elif os.path.isdir(full_path):
                    folders.append(item)
            files.sort()
            folders.sort()
            if path != self.configs_path:
                data_return["configs"][".."] = [".."]
            for folder in folders:
                name = self.locales_text(folder)
                if search and search.lower() not in name.lower():
                    continue
                data_return["configs"][folder] = [name]

            for file in files:
                try:
                    if os.access(file, os.X_OK):
                        data = subprocess.run([file], stdout=subprocess.PIPE, env=env_map)
                        data_dict = json.loads(data.stdout)
                        data_return["configs"][file] = {}
                        for key, value in data_dict.items():
                            data_return["configs"][file][key] = value
                    else:
                        with open(file, "r") as fh:
                            data_dict = json.load(fh)
                            for key, value in data_dict.items():
                                data_return["configs"][file][key] = value
                except Exception as e:
                    self.log_exception(e, "Server - configs - List '"+file+"'")

        except Exception as e:
            self.log_exception(e, "Server - configs - List")
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        if self.configs_reboot:
            data_return["configs_reboot"] = self.configs_reboot

        data_return = msgpack.packb(data_return)

        return data_return


    def configs_cmd(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK

        if "cmd" in data and data["cmd"] == "apply" and "data" in data:
            try:
                data_return["configs_apply"] = []
                env_map = {}
                if "PATH" in os.environ:
                    env_map["PATH"] = os.environ["PATH"]
                if link_id != None:
                    env_map["link_id"] = RNS.hexrep(link_id, delimit=False)
                if remote_identity != None:
                    env_map["remote_identity"] = RNS.hexrep(remote_identity.hash, delimit=False)
                if dest != None:
                    env_map["dest"] = RNS.hexrep(dest, delimit=False)
                env_map.update(self.environment_variables)

                for file, values in data["data"].items():
                    if not os.path.isfile(file):
                        raise ValueError(file+" does not exist.")
                    if os.access(file, os.X_OK):
                        env_map["data"] = json.dumps(values)
                        result = subprocess.run([file], stdout=subprocess.PIPE, env=env_map)
                        if result.returncode == 0:
                            data_return["configs_apply"].append(file)
                            try:
                                result_dict = json.loads(result.stdout)
                                if "configs_reboot" in result_dict:
                                    self.configs_reboot = True
                            except:
                                pass
            except Exception as e:
                self.log_exception(e, "Server - Configs - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and data["cmd"] in self.configs_cmd_mapping:
            try:
                result = subprocess.run([self.configs_cmd_mapping[data["cmd"]]], capture_output=True, text=True)
                if result.returncode == 0:
                    if data["cmd"] == "reboot":
                        self.configs_reboot = False
                else:
                    raise ValueError(result.returncode)
            except Exception as e:
                self.log_exception(e, "Server - Configs - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        else:
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        if self.configs_reboot:
            data_return["configs_reboot"] = self.configs_reboot

        data_return = msgpack.packb(data_return)

        return data_return


    #################################################
    # Files                                         #
    #################################################


    def files_list(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK

        data_return["files"] = {}

        if "filter" in data and data["filter"]:
            filter = data["filter"]
        else:
            filter = False

        if "search" in data and data["search"]:
            search = data["search"]
        else:
            search = False

        try:
            if "ids" in data and data["ids"]:
                data_return["files_uids"] = {}
                for entry in pwd.getpwall():
                    data_return["files_uids"][entry.pw_uid] = entry.pw_name
                data_return["files_gids"] = {}
                for entry in grp.getgrall():
                    data_return["files_gids"][entry.gr_gid] = entry.gr_name

            if "path" in data and data["path"]:
                path = data["path"]
            else:
                path = self.files_path

            data_return["path"] = path
            files = []
            folders = []
            items = os.listdir(path)
            for item in items:
                if search and search.lower() not in item.lower():
                    continue
                full_path = os.path.join(path, item)
                if os.path.isfile(full_path):
                    if filter and "file" not in filter:
                        continue
                    files.append(item)
                elif os.path.isdir(full_path):
                    if filter and "folder" not in filter:
                        continue
                    folders.append(item)
            files.sort()
            folders.sort()
            if path != "/":
                data_return["files"][".."] = []
            for folder in folders:
                data_return["files"][folder] = []
            for file in files:
                full_path = os.path.join(path, file)
                file_stat = os.stat(full_path)
                data_return["files"][file] = [os.path.getsize(full_path), file_stat.st_mode, file_stat.st_uid, file_stat.st_gid]
        except Exception as e:
            self.log_exception(e, "Server - Files - List")
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    def files_cmd(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK

        if "cmd" in data and (data["cmd"] == "move" or data["cmd"] == "mv") and "file_src" in data and "file_dst" in data:
            try:
                file_src = data["file_src"]
                file_dst = data["file_dst"]
                if file_src == file_dst:
                    raise ValueError("Source/destination are the same.")
                if os.path.isfile(file_src):
                    if os.path.isfile(file_dst):
                        raise ValueError(file_dst+" does exist.")
                    shutil.move(file_src, file_dst)
                    data_return["files_update"] = {}
                    file_stat = os.stat(file_dst)
                    data_return["files_update"][os.path.basename(file_dst)] = [os.path.getsize(file_dst), file_stat.st_mode, file_stat.st_uid, file_stat.st_gid]
                elif os.path.isdir(file_src):
                    if os.path.isdir(file_dst):
                        raise ValueError(file_dst+" does exist.")
                    shutil.move(file_src, os.path.dirname(file_dst))
                    data_return["files_update"] = {}
                    data_return["files_update"][os.path.basename(file_dst)] = []
                else:
                    raise ValueError(file_src+" does not exist.")
            except Exception as e:
                self.log_exception(e, "Server - Files - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and (data["cmd"] == "copy" or data["cmd"] == "cp" or data["cmd"] == "clone") and "file_src" in data and "file_dst" in data:
            try:
                file_src = data["file_src"]
                file_dst = data["file_dst"]
                if file_src == file_dst:
                    raise ValueError("Source/destination are the same.")
                if os.path.isfile(file_src):
                    if os.path.isfile(file_dst):
                        raise ValueError(file_dst+" does exist.")
                    self.shutil_copy(file_src, file_dst)
                    data_return["files_update"] = {}
                    file_stat = os.stat(file_dst)
                    data_return["files_update"][os.path.basename(file_dst)] = [os.path.getsize(file_dst), file_stat.st_mode, file_stat.st_uid, file_stat.st_gid]
                elif os.path.isdir(file_src):
                    if os.path.isdir(file_dst):
                        raise ValueError(file_dst+" does exist.")
                    self.shutil_copytree(file_src, file_dst)
                    data_return["files_update"] = {}
                    data_return["files_update"][os.path.basename(file_dst)] = []
                else:
                    raise ValueError(file_src+" does not exist.")
            except Exception as e:
                self.log_exception(e, "Server - Files - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and (data["cmd"] == "del" or data["cmd"] == "rm") and "file" in data:
            try:
                file = data["file"]
                if os.path.isfile(file):
                    os.remove(file)
                elif os.path.isdir(file):
                    shutil.rmtree(file)
                else:
                    raise ValueError(file+" does not exist.")
                data_return["files_del"] = {}
                data_return["files_del"][os.path.basename(file)] = True
            except Exception as e:
                self.log_exception(e, "Server - Files - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and data["cmd"] == "rename" and "file" in data and "name" in data:
            try:
                file_src = data["file"]
                file_dst = os.path.join(os.path.dirname(file_src), data["name"])
                if file_src == file_dst:
                    raise ValueError("Source/destination are the same.")
                if not os.path.isfile(file_src) and not os.path.isdir(file_src):
                    raise ValueError(file_src+" does not exist.")
                if os.path.isfile(file_dst) or os.path.isdir(file_dst):
                    raise ValueError(file_dst+" does exist.")
                shutil.move(file_src, file_dst)
                data_return["files_del"] = {}
                data_return["files_del"][os.path.basename(file_src)] = True
                data_return["files_update"] = {}
                if os.path.isfile(file_dst):
                    file_stat = os.stat(file_dst)
                    data_return["files_update"][os.path.basename(file_dst)] = [os.path.getsize(file_dst), file_stat.st_mode, file_stat.st_uid, file_stat.st_gid]
                else:
                    data_return["files_update"][os.path.basename(file_dst)] = []
            except Exception as e:
                self.log_exception(e, "Server - Files - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and (data["cmd"] == "new" or data["cmd"] == "create") and ("file" in data or "folder" in data):
            try:
                if "file" in data:
                    if os.path.isfile(data["file"]):
                        raise ValueError(data["file"]+" does exist.")
                    with open(data["file"], 'w'):
                        pass
                    data_return["files_update"] = {}
                    file_stat = os.stat(data["file"])
                    data_return["files_update"][os.path.basename(data["file"])] = [os.path.getsize(data["file"]), file_stat.st_mode, file_stat.st_uid, file_stat.st_gid]
                elif "folder" in data:
                    if os.path.isdir(data["folder"]):
                        raise ValueError(data["folder"]+" does exist.")
                    os.mkdir(data["folder"])
                    data_return["files_update"] = {}
                    data_return["files_update"][os.path.basename(data["folder"])] = []
            except Exception as e:
                self.log_exception(e, "Server - Files - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and data["cmd"] == "properties" and "file" in data:
            try:
                file = data["file"]
                if not os.path.isfile(file):
                    raise ValueError(file+" does not exist.")
                os.chown(file, data["uid"], data["gid"])
                os.chmod(file, data["rights"])
                file_stat = os.stat(file)
                data_return["files_update"] = {}
                data_return["files_update"][os.path.basename(file)] = [os.path.getsize(file), file_stat.st_mode, file_stat.st_uid, file_stat.st_gid]
            except Exception as e:
                self.log_exception(e, "Server - Files - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        else:
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    def files_download(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return None

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return None

        self.link_ts = time.time()

        if not "file" in data:
            return None

        if data["file"] == "":
            return None

        if not os.path.isfile(data["file"]):
            return None

        try:
            RNS.log("Server - Files - Download: "+data["file"], RNS.LOG_VERBOSE)
            fh = open(data["file"], "rb")
            file_data = fh.read()
            fh.close()

            if self.limiter_server:
                self.limiter_server.handle_size("server", len(file_data))

            if self.limiter_peer:
                self.limiter_peer.handle_size(str(remote_identity), len(file_data))

            return [data["file"], file_data]

        except Exception as e:
            self.log_exception(e, "Server - Files - Download")
            return None


    def files_upload_callback(self, resource):
        remote_identity = resource.link.get_remote_identity()

        if not remote_identity:
            return False

        if self.limiter_server and not self.limiter_server.handle("server"):
            return False

        if self.limiter_peer and not self.limiter_peer.handle(str(remote_identity)):
            return False

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return False

        return True


    def files_upload_started(self, resource):
        self.link_ts = time.time()

        if resource.link.get_remote_identity():
            id_str = " from "+RNS.prettyhexrep(resource.link.get_remote_identity().hash)
        else:
            id_str = ""

        RNS.log("Server - Files - Upload: Starting resource transfer "+RNS.prettyhexrep(resource.hash)+id_str, RNS.LOG_DEBUG)


    def files_upload_concluded(self, resource):
        self.link_ts = time.time()

        if resource.status == RNS.Resource.COMPLETE:
            RNS.log("Server - Files - Upload: "+str(resource)+" completed", RNS.LOG_DEBUG)

            if resource.total_size > 4:
                try:
                    file_name_len = int.from_bytes(resource.data.read(2), "big")
                    file_name = resource.data.read(file_name_len).decode("utf-8")

                    file = open(file_name, "wb")
                    file.write(resource.data.read())
                    file.close()

                except Exception as e:
                    self.log_exception(e, "Server - Files - Upload: Resource failed")

            else:
                RNS.log("Server - Files - Upload: Invalid data received, ignoring resource", RNS.LOG_DEBUG)

        else:
            RNS.log("Server - Files - Upload: Resource failed", RNS.LOG_DEBUG)


    #################################################
    # Infos                                         #
    #################################################


    def infos_list(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK

        data_return["infos"] = {}

        if "filter" in data and data["filter"]:
            filter = data["filter"]
        else:
            filter = False

        if "search" in data and data["search"]:
            search = data["search"]
        else:
            search = False

        try:
            env_map = {}
            if "PATH" in os.environ:
                env_map["PATH"] = os.environ["PATH"]
            if link_id != None:
                env_map["link_id"] = RNS.hexrep(link_id, delimit=False)
            if remote_identity != None:
                env_map["remote_identity"] = RNS.hexrep(remote_identity.hash, delimit=False)
            if dest != None:
                env_map["dest"] = RNS.hexrep(dest, delimit=False)
            env_map.update(self.environment_variables)

            if "path" in data and data["path"] != "" and data["path"] != "/":
                data_return["path"] = [data["path"], self.locales_text(data["path"], path=True)]
                path = self.infos_path+data["path"]
            else:
                data_return["path"] = ["", ""]
                path = self.infos_path

            if not os.path.isdir(path):
                data_return["path"] = ["", ""]
                path = self.infos_path

            files = []
            folders = []
            items = os.listdir(path)
            for item in items:
                if item.startswith("."):
                    continue
                full_path = os.path.join(path, item)
                if os.path.isfile(full_path):
                    files.append(full_path)
                elif os.path.isdir(full_path):
                    folders.append(item)
            files.sort()
            folders.sort()
            if path != self.infos_path:
                data_return["infos"][".."] = [".."]
            for folder in folders:
                name = self.locales_text(folder)
                if search and search.lower() not in name.lower():
                    continue
                data_return["infos"][folder] = [name]

            infos = {}
            for file in files:
                try:
                    if os.access(file, os.X_OK):
                        data = subprocess.run([file], stdout=subprocess.PIPE, env=env_map)
                        data_dict = json.loads(data.stdout)
                        infos.update(data_dict)
                    else:
                        with open(file, "r") as fh:
                            data_dict = json.load(fh)
                            infos.update(data_dict)
                except Exception as e:
                    self.log_exception(e, "Server - Infos - List '"+file+"'")

            for key, value in infos.items():
                if filter and "state" in filter and len(value) >= 4 and value[3] not in filter["state"]:
                    continue
                key = self.locales_text(key)
                value[0] = self.locales_text(value[0])
                value[1] = self.locales_text(value[1])
                if search and search.lower() not in key.lower() and search.lower() not in value[0].lower() and search.lower() not in value[1].lower():
                    continue
                data_return["infos"][key] = value

        except Exception as e:
            self.log_exception(e, "Server - Infos - List")
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    #################################################
    # Logs                                          #
    #################################################


    def logs_list(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK

        data_return["logs"] = {}

        if "filter" in data and data["filter"]:
            filter = data["filter"]
        else:
            filter = False

        if "search" in data and data["search"]:
            search = data["search"]
        else:
            search = False

        try:
            if "path" in data and data["path"] != "" and data["path"] != "/":
                data_return["path"] = [data["path"], self.locales_text(data["path"], path=True)]
                path = self.logs_path+data["path"]
            else:
                data_return["path"] = ["", ""]
                path = self.logs_path

            if not os.path.isdir(path):
                data_return["path"] = ["", ""]
                path = self.logs_path

            files = []
            folders = []
            items = os.listdir(path)
            for item in items:
                if item.startswith("."):
                    continue
                full_path = os.path.join(path, item)
                if os.path.isfile(full_path):
                    if filter and "file" not in filter:
                        continue
                    files.append(item)
                elif os.path.isdir(full_path):
                    if filter and "folder" not in filter:
                        continue
                    folders.append(item)
            files.sort()
            folders.sort()
            if path != self.logs_path:
                data_return["logs"][".."] = [".."]
            for folder in folders:
                name = self.locales_text(folder)
                if search and search.lower() not in name.lower():
                    continue
                data_return["logs"][folder] = [name]
            for file in files:
                name = self.locales_text(os.path.splitext(file)[0])
                if search and search.lower() not in name.lower():
                    continue
                data_return["logs"][file] = [name, True]
        except Exception as e:
            self.log_exception(e, "Server - Logs - List")
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    def logs_cmd(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK
        data_return["logs_o"] = []

        if "file" in data and "mode" in data:
            try:
                file = self.logs_path+data["file"]
                mode = data["mode"]

                if not os.path.isfile(file):
                    raise ValueError(file+" does not exist.")

                env_map = {}
                if "PATH" in os.environ:
                    env_map["PATH"] = os.environ["PATH"]
                if link_id != None:
                    env_map["link_id"] = RNS.hexrep(link_id, delimit=False)
                if remote_identity != None:
                    env_map["remote_identity"] = RNS.hexrep(remote_identity.hash, delimit=False)
                if dest != None:
                    env_map["dest"] = RNS.hexrep(dest, delimit=False)
                env_map.update(self.environment_variables)

                if os.access(file, os.X_OK):
                    result = subprocess.run([file], stdout=subprocess.PIPE, env=env_map)
                    if result.returncode == 0:
                        lines = result.stdout.decode("utf-8").split('\n')
                        lines = lines[-mode:]
                        data_return["logs_o"] = lines
                else:
                    with open(file, "r") as fh:
                        lines = fh.readlines()
                    for line in lines:
                        line = line.strip()
                        if line != "" and line.startswith("/") and os.path.isfile(line):
                            with open(line, "r") as fh:
                                lines = fh.readlines()
                                lines = lines[-mode:]
                                data_return["logs_o"] = lines
                            break
                        elif line != "" and not line.startswith("/"):
                            result = subprocess.run(line, capture_output=True, shell=True, text=True, env=env_map)
                            if result.returncode == 0:
                                lines = result.stdout.split('\n')
                                lines = lines[-mode:]
                                data_return["logs_o"] = lines
                            break
            except Exception as e:
                self.log_exception(e, "Server - Logs - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        else:
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    #################################################
    # Notes                                         #
    #################################################


    def notes_cmd(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK

        if "cmd" in data and data["cmd"] == "r":
            try:
                data_return["notes"] = ""
                file = self.notes_path
                if os.path.isfile(file):
                    with open(file, "r") as fh:
                        data_return["notes"] = fh.read()
            except Exception as e:
                self.log_exception(e, "Server - Notes - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and data["cmd"] == "w" and "content" in data:
            try:
                file = self.notes_path
                with open(file, "w") as fh:
                    fh.write(data["content"])
            except Exception as e:
                self.log_exception(e, "Server - Notes - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        else:
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    #################################################
    # Scripts                                       #
    #################################################


    def scripts_list(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK

        data_return["scripts"] = {}

        if "filter" in data and data["filter"]:
            filter = data["filter"]
        else:
            filter = False

        if "search" in data and data["search"]:
            search = data["search"]
        else:
            search = False

        try:
            if "path" in data and data["path"] != "" and data["path"] != "/":
                data_return["path"] = [data["path"], self.locales_text(data["path"], path=True)]
                path = self.scripts_path+data["path"]
            else:
                data_return["path"] = ["", ""]
                path = self.scripts_path

            if not os.path.isdir(path):
                data_return["path"] = ["", ""]
                path = self.scripts_path

            files = []
            folders = []
            items = os.listdir(path)
            for item in items:
                if item.startswith("."):
                    continue
                full_path = os.path.join(path, item)
                if os.path.isfile(full_path):
                    if filter and "file" not in filter:
                        continue
                    files.append(item)
                elif os.path.isdir(full_path):
                    if filter and "folder" not in filter:
                        continue
                    folders.append(item)
            files.sort()
            folders.sort()
            if path != self.scripts_path:
                data_return["scripts"][".."] = [".."]
            for folder in folders:
                name = self.locales_text(folder)
                if search and search.lower() not in name.lower():
                    continue
                data_return["scripts"][folder] = [name]
            for file in files:
                name = self.locales_text(os.path.splitext(file)[0])
                if search and search.lower() not in name.lower():
                    continue
                data_return["scripts"][file] = [name, True]
        except Exception as e:
            self.log_exception(e, "Server - Scripts - List")
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    #################################################
    # Services                                      #
    #################################################


    def services_list(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK

        data_return["services"] = {}

        if "filter" in data and data["filter"]:
            filter = data["filter"]
        else:
            filter = False

        if "search" in data and data["search"]:
            search = data["search"]
        else:
            search = False

        try:
            env_map = {}
            if "PATH" in os.environ:
                env_map["PATH"] = os.environ["PATH"]
            if link_id != None:
                env_map["link_id"] = RNS.hexrep(link_id, delimit=False)
            if remote_identity != None:
                env_map["remote_identity"] = RNS.hexrep(remote_identity.hash, delimit=False)
            if dest != None:
                env_map["dest"] = RNS.hexrep(dest, delimit=False)
            env_map.update(self.environment_variables)

            if "path" in data and data["path"] != "" and data["path"] != "/":
                data_return["path"] = [data["path"], self.locales_text(data["path"], path=True)]
                path = self.services_path+data["path"]
            else:
                data_return["path"] = ["", ""]
                path = self.services_path

            if not os.path.isdir(path):
                data_return["path"] = ["", ""]
                path = self.services_path

            files = []
            folders = []
            items = os.listdir(path)
            for item in items:
                if item.startswith("."):
                    continue
                full_path = os.path.join(path, item)
                if os.path.isfile(full_path):
                    files.append(full_path)
                elif os.path.isdir(full_path):
                    folders.append(item)
            files.sort()
            folders.sort()
            if path != self.services_path:
                data_return["services"][".."] = [".."]
            for folder in folders:
                name = self.locales_text(folder)
                if search and search.lower() not in name.lower():
                    continue
                data_return["services"][folder] = [name]

            services = {}
            for file in files:
                try:
                    if os.access(file, os.X_OK):
                        data = subprocess.run([file], stdout=subprocess.PIPE, env=env_map)
                        data_dict = json.loads(data.stdout)
                        services.update(data_dict)
                    else:
                        with open(file, "r") as fh:
                            data_dict = json.load(fh)
                            services.update(data_dict)
                except Exception as e:
                    self.log_exception(e, "Server - Services - List '"+file+"'")

            for key, value in services.items():
                if key == "":
                    continue
                enabled, state = self.services_state_mapping_int(value[0], value[1])
                if filter and "enabled" in filter and enabled not in filter["enabled"]:
                    continue
                if filter and "state" in filter and state not in filter["state"]:
                    continue
                if search and search.lower() not in key.lower():
                    continue
                data_return["services"][key] = [enabled, state]

        except Exception as e:
            self.log_exception(e, "Server - Services - List")
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    def services_cmd(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK

        if "cmd" in data and data["cmd"] == "rename" and "service" in data and data["service"] != "" and "name" in data and data["name"] != "":
            try:
                file_src = self.services_system_path+"/"+data["service"]+self.services_system_extension
                file_dst = self.services_system_path+"/"+data["name"]+self.services_system_extension
                if file_src == file_dst:
                    raise ValueError("Source/destination are the same.")
                if not os.path.isfile(file_src):
                    raise ValueError(file_src+" does not exist.")
                if os.path.isfile(file_dst):
                    raise ValueError(file_dst+" does exist.")
                state_enabled, state_running = self.services_state(data["service"], True)
                result = subprocess.run(["systemctl", "stop", data["service"]], capture_output=True, text=True)
                if result.returncode != 0:
                    raise ValueError(result.returncode)
                result = subprocess.run(["systemctl", "disable", data["service"]], capture_output=True, text=True)
                if result.returncode != 0:
                    raise ValueError(result.returncode)
                shutil.move(file_src, file_dst)
                if ("files" in data and data["files"]) or ("config" in data and data["config"]):
                    with open(file_dst, "r") as fh:
                        content = fh.read()
                    if "files" in data and data["files"]:
                        search = data["service"]
                        pattern = re.compile(rf'(\/(?:[^\/\s]+\/)*{re.escape(search)})\b')
                        matches = pattern.findall(content)
                        for files_src in matches:
                            if os.path.isdir(files_src):
                                files_dst = files_src.replace(data["service"], data["name"])
                                shutil.move(files_src, files_dst)
                                break
                    if "config" in data and data["config"]:
                        content = content.replace(data["service"], data["name"])
                        with open(file_dst, "w") as fh:
                            fh.write(content)
                result = subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True)
                if result.returncode != 0:
                    raise ValueError(result.returncode)
                if state_enabled:
                    result = subprocess.run(["systemctl", "enable", data["name"]], capture_output=True, text=True)
                    if result.returncode != 0:
                        raise ValueError(result.returncode)
                if state_running:
                    result = subprocess.run(["systemctl", "start", data["name"]], capture_output=True, text=True)
                    if result.returncode != 0:
                        raise ValueError(result.returncode)
                data_return["services_del"] = {}
                data_return["services_del"][data["service"]] = True
                data_return["services_update"] = {}
                data_return["services_update"][data["name"]] = self.services_state(data["name"])
            except Exception as e:
                self.log_exception(e, "Server - Services - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and data["cmd"] == "clone" and "service" in data and data["service"] != "" and "name" in data and data["name"] != "":
            try:
                file_src = self.services_system_path+"/"+data["service"]+self.services_system_extension
                file_dst = self.services_system_path+"/"+data["name"]+self.services_system_extension
                if file_src == file_dst:
                    raise ValueError("Source/destination are the same.")
                if not os.path.isfile(file_src):
                    raise ValueError(file_src+" does not exist.")
                if os.path.isfile(file_dst):
                    raise ValueError(file_dst+" does exist.")
                with open(file_src, "r") as fh:
                    content = fh.read()
                if "files" in data and data["files"]:
                    search = data["service"]
                    pattern = re.compile(rf'(\/(?:[^\/\s]+\/)*{re.escape(search)})\b')
                    matches = pattern.findall(content)
                    for files_src in matches:
                        if os.path.isdir(files_src):
                            files_dst = files_src.replace(data["service"], data["name"])
                            self.shutil_copytree(files_src, files_dst)
                            break
                if "config" in data and data["config"]:
                    content = content.replace(data["service"], data["name"])
                with open(file_dst, "w") as fh:
                    fh.write(content)
                result = subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True)
                if result.returncode != 0:
                    raise ValueError(result.returncode)
                data_return["services_update"] = {}
                data_return["services_update"][data["name"]] = self.services_state(data["name"])
            except Exception as e:
                self.log_exception(e, "Server - Services - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and data["cmd"] == "edit" and "service" in data and data["service"] != "" and "content" not in data:
            try:
                file = self.services_system_path+"/"+data["service"]+self.services_system_extension
                if not os.path.isfile(file):
                    raise ValueError(file+" does not exist.")
                with open(file, "r") as fh:
                    lines = fh.readlines()
                data_return["services_edit"] = [data["service"], "".join(lines)]
            except Exception as e:
                self.log_exception(e, "Server - Services - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and data["cmd"] == "edit" and "service" in data and data["service"] != "" and "content" in data:
            try:
                file = self.services_system_path+"/"+data["service"]+self.services_system_extension
                if not os.path.isfile(file):
                    raise ValueError(file+" does not exist.")
                with open(file, "w") as fh:
                    fh.write(data["content"])
                result = subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True)
                if result.returncode != 0:
                    raise ValueError(result.returncode)
            except Exception as e:
                self.log_exception(e, "Server - Services - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and (data["cmd"] == "del" or data["cmd"] == "rm") and "service" in data and data["service"] != "":
            try:
                result = subprocess.run(["systemctl", "stop", data["service"]], capture_output=True, text=True)
                if result.returncode != 0:
                    raise ValueError(result.returncode)
                result = subprocess.run(["systemctl", "disable", data["service"]], capture_output=True, text=True)
                if result.returncode != 0:
                    raise ValueError(result.returncode)
                file = self.services_system_path+"/"+data["service"]+self.services_system_extension
                if not os.path.isfile(file):
                    raise ValueError(file_src+" does not exist.")
                if "files" in data and data["files"]:
                    with open(file, "r") as fh:
                        content = fh.read()
                    search = data["service"]
                    pattern = re.compile(rf'(\/(?:[^\/\s]+\/)*{re.escape(search)})\b')
                    matches = pattern.findall(content)
                    for files in matches:
                        if os.path.isdir(files):
                            shutil.rmtree(files)
                            break
                os.remove(file)
                result = subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True)
                if result.returncode != 0:
                    raise ValueError(result.returncode)
                data_return["services_del"] = {}
                data_return["services_del"][data["service"]] = True
            except Exception as e:
                self.log_exception(e, "Server - Services - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and data["cmd"] == "files" and "service" in data and data["service"] != "":
            try:
                file = self.services_system_path+"/"+data["service"]+self.services_system_extension
                if not os.path.isfile(file):
                    raise ValueError(file+" does not exist.")
                path = None
                for item in self.services_files:
                    if os.path.isdir(item+"/"+data["service"]):
                        path = item+"/"+data["service"]
                        break
                with open(file, "r") as fh:
                    content = fh.read()
                search = data["service"]
                pattern = re.compile(rf'(\/(?:[^\/\s]+\/)*{re.escape(search)})\b')
                matches = pattern.findall(content)
                for match in matches:
                    if os.path.isdir(match):
                        path = match
                        break
                if path:
                    data_return["services_files"] = {}
                    data_return["path"] = path
                    files = []
                    folders = []
                    items = os.listdir(path)
                    for item in items:
                        full_path = os.path.join(path, item)
                        if os.path.isfile(full_path):
                            files.append(item)
                        elif os.path.isdir(full_path):
                            folders.append(item)
                    files.sort()
                    folders.sort()
                    if path != "/":
                        data_return["services_files"][".."] = []
                    for folder in folders:
                        data_return["services_files"][folder] = []
                    for file in files:
                        full_path = os.path.join(path, file)
                        file_stat = os.stat(full_path)
                        data_return["services_files"][file] = [os.path.getsize(full_path), file_stat.st_mode, file_stat.st_uid, file_stat.st_gid]
            except Exception as e:
                self.log_exception(e, "Server - Services - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        elif "cmd" in data and data["cmd"] != "" and "service" in data and data["service"] != "":
            try:
                result = subprocess.run(["systemctl", data["cmd"], data["service"]], capture_output=True, text=True)
                if result.returncode != 0:
                    raise ValueError(result.returncode)
                data_return["services_update"] = {}
                data_return["services_update"][data["service"]] = self.services_state(data["service"])
            except Exception as e:
                self.log_exception(e, "Server - Services - CMD")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        else:
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    def services_logs(self, path, data, request_id, link_id, remote_identity, requested_at):
        if not data:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_DATA})

        dest = RNS.Destination.hash_from_name_and_identity(self.aspect_filter_conv, remote_identity)
        if dest not in self.allow:
            return msgpack.packb({self.KEY_RESULT: self.RESULT_NO_RIGHT})

        self.link_ts = time.time()

        data_return = {}

        if "locales" in data:
            self.locales_init(data["locales"])

        data_return[self.KEY_RESULT] = self.RESULT_OK
        data_return["logs_o"] = []

        if "file" in data and "mode" in data:
            try:
                file = data["file"]
                mode = data["mode"]
                result = subprocess.run(["journalctl", "-u", file, "-n", str(mode)], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    lines = lines[-mode:]
                    data_return["logs_o"] = lines
                else:
                    raise ValueError(result.returncode)
            except Exception as e:
                self.log_exception(e, "Server - Services - Logs")
                data_return[self.KEY_RESULT] = self.RESULT_ERROR

        else:
            data_return[self.KEY_RESULT] = self.RESULT_ERROR

        data_return = msgpack.packb(data_return)

        return data_return


    def services_state(self, service, boolean=False):
        result = subprocess.run(["systemctl", "is-enabled", service], capture_output=True, text=True)
        enabled = result.stdout.strip()

        result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True)
        state = result.stdout.strip()

        if boolean:
            return self.services_state_mapping_boolean(enabled, state)
        else:
            return self.services_state_mapping_int(enabled, state)


    def services_state_mapping_boolean(self, enabled, state):
        enabled_mapping = {"disabled": False, "enabled": True, "static": False, "masked": False, "alias": False}
        state_mapping = {"inactive": False, "active": True, "activating": True, "deactivating": True, "failed": True}

        enabled = enabled_mapping.get(enabled.lower(), False)
        state = state_mapping.get(state.lower(), True)

        return [enabled, state]


    def services_state_mapping_int(self, enabled, state):
        enabled_mapping = {"disabled": 0x00, "enabled": 0x01, "static": 0x02, "masked": 0x03, "alias": 0x04}
        state_mapping = {"inactive": 0x00, "active": 0x01, "activating": 0x02, "deactivating": 0x03, "failed": 0x04}

        enabled = enabled_mapping.get(enabled.lower(), 0xFF)
        state = state_mapping.get(state.lower(), 0xFF)

        if enabled == 0x00 and state == 0xFF:
            state = 0x00

        return [enabled, state]


    #################################################
    # Helpers                                       #
    #################################################


    def shutil_copy(self, src, dst, permissions=True):
        shutil.copy(src, dst)

        if not permissions:
            return

        st = os.stat(src)
        os.chmod(dst, st.st_mode)
        if hasattr(os, "chown"):
            os.chown(dst, st.st_uid, st.st_gid)


    def shutil_copytree(self, src, dst, permissions=True):
        shutil.copytree(src, dst, copy_function=shutil.copy)

        if not permissions:
            return

        for dirpath, dirnames, filenames in os.walk(src):
            relative_path = os.path.relpath(dirpath, src)
            dst_dirpath = os.path.join(dst, relative_path)

            st = os.stat(dirpath)
            os.chmod(dst_dirpath, st.st_mode)

            if hasattr(os, "chown"):
                os.chown(dst_dirpath, st.st_uid, st.st_gid)

            for filename in filenames:
                src_file = os.path.join(dirpath, filename)
                dst_file = os.path.join(dst_dirpath, filename)

                st = os.stat(src_file)
                os.chmod(dst_file, st.st_mode)
                if hasattr(os, "chown"):
                    os.chown(dst_file, st.st_uid, st.st_gid)


    #################################################
    # Helpers - Buffer (Scripts, Console)           #
    #################################################


    def buffer_rx(self, ready_bytes: int):
        self.link_ts = time.time()

        try:
            data = msgpack.unpackb(self.buffer.read(ready_bytes))

            if "c_execute" in data:
                self.console = ServerManagementConsole(path="/tmp", env=self.console_env)
                self.console.set('"'+data["c_execute"]+'"')

            if "c_i" in data:
                if self.console:
                    self.console.set(data["c_i"])

            if "c_reset" in data:
                self.console = None
                self.console = ServerManagementConsole(path="/tmp", env=self.console_env)

            if "c_start" in data:
                self.console = ServerManagementConsole(path="/tmp", env=self.console_env)

            if "c_stop" in data:
                self.console = None

            if "locales" in data:
                self.locales_init(data["locales"])

            if "s_execute" in data:
                self.scripts = ServerManagementConsole(path="/tmp", env=self.scripts_env)
                self.scripts_cmd = '"'+data["s_execute"]+'"'
                self.scripts.set(self.scripts_cmd)

            if "s_i" in data:
                if self.scripts:
                    self.scripts.set(data["s_i"])

            if "s_reset" in data:
                self.scripts = None
                self.scripts = ServerManagementConsole(path="/tmp", env=self.scripts_env)
                self.scripts.set(self.scripts_cmd)

            if "s_start" in data:
                self.scripts = ServerManagementConsole(path="/tmp", env=self.scripts_env)
                self.scripts_cmd = '"'+self.scripts_path+data["s_start"]+'"'
                self.scripts.set(self.scripts_cmd)

            if "s_stop" in data:
                self.scripts = None

        except Exception as e:
            self.log_exception(e, "Server - Buffer - RX")


    def buffer_tx(self):
        while True:
            try:
                time.sleep(1)

                if time.time()-self.link_ts > self.link_timeout:
                    try:
                        self.link.teardown()
                    except:
                        pass
                    self.link = None

                if not self.link or self.link.status != 0x02 or not self.buffer:
                    break

                if self.scripts:
                    output, state = self.scripts.get()
                    if output != "":
                        if self.scripts_cmd and output.startswith(self.scripts_cmd):
                            output = re.sub(r'\u001b\[\?2004h.*?#\s', '', output)
                            output = output.replace("\u001b[?2004l", "")
                            output = re.sub(r'.*@.*#', '', output)
                            output = output.replace(self.scripts_cmd, "", 2)
                            self.scripts_cmd = None
                        data = msgpack.packb({"s_o": self.locales_text(output), "s_s": state})
                        self.buffer.write(data)
                        self.buffer.flush()

                if self.console:
                    output, state = self.console.get()
                    if output != "":
                        data = msgpack.packb({"c_o": output, "c_s": state})
                        self.buffer.write(data)
                        self.buffer.flush()

            except Exception as e:
                self.log_exception(e, "Server - Buffer - TX")


    #################################################
    # Helpers - Locales/Language                    #
    #################################################


    def locales_init(self, locales=None):
        try:
            if locales == None or locales == "en":
                self.locales = None
                self.locales_data = None
            elif locales != self.locales:
                file = self.locales_path+"/"+locales+"/LC_MESSAGES/base.po"
                if os.path.isfile(file):
                    self.locales = locales
                    self.locales_data = {}
                    pofile = polib.pofile(file)
                    podata = {}
                    for entry in pofile:
                        if entry.msgstr != "" and entry.msgstr != entry.msgid:
                            podata[entry.msgid] = entry.msgstr
                    self.locales_data = {key: podata[key] for key in sorted(podata.keys(), key=lambda x: len(x), reverse=True)}
                else:
                    self.locales = None
                    self.locales_data = None
        except:
            self.locales = None
            self.locales_data = None


    def locales_text(self, text, path=False):
        try:
            if self.locales and self.locales_data:
                if path:
                    text = text.replace("/", " / ")
                    text = text.replace("\\", " \\ ")
                text = " "+text+" "
                done = ""
                for key, value in self.locales_data.items():
                    if " "+key+" " in done:
                        continue
                    done += " "+value+" "
                    text = re.sub(r'(\s)'+re.escape(key)+r'(\s)', lambda m: m.group(1)+value+ m.group(2), text)
                if path:
                    text = text.replace(" / ", "/")
                    text = text.replace(" \\ ", "\\")
                text = text.strip()
        except:
            pass

        return text


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


#### Setup default user#####
def setup_default_user(dest):
    data_return = []

    try:
        dest = RNS.hexrep(dest, delimit=False)
        file = PATH+"/config.cfg.owr"
        config = configparser.ConfigParser(allow_no_value=True, inline_comment_prefixes="#")
        if os.path.isfile(file):
            config.read(file, encoding="utf-8")
        if "allowed" not in config:
            config.add_section("allowed")
        config.set("allowed", dest, "")
        with open(file, "w") as file:
            config.write(file)
        for (key, val) in config.items("allowed"):
            try:
                dest_hash = bytes.fromhex(key)
                if len(dest_hash) == RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
                    data_return.append(dest_hash)
            except:
                pass
    except Exception as e:
        pass

    return data_return


#### Setup #####
def setup(path=None, path_rns=None, path_log=None, loglevel=None, service=False, require_shared_instance=False):
    global PATH
    global PATH_RNS
    global LOG_LEVEL
    global LOG_FILE
    global RNS_CONNECTION
    global RNS_SERVER_MANAGEMENT

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

    allow = []
    if CONFIG.has_section("allowed"):
        for (key, val) in CONFIG.items("allowed"):
            try:
                dest_hash = bytes.fromhex(key)
                if len(dest_hash) == RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
                    allow.append(dest_hash)
            except:
                pass

    configs_cmd = {}
    if CONFIG.has_section("configs_cmd"):
        for (key, val) in CONFIG.items("configs_cmd"):
            configs_cmd[key] = val

    environment_variables = {}
    if CONFIG.has_section("environment_variables"):
        for (key, val) in CONFIG.items("environment_variables"):
            environment_variables[key] = val

    services_files = []
    if CONFIG.has_section("services_files"):
        for (key, val) in CONFIG.items("services_files"):
            services_files.append(key)

    RNS_SERVER_MANAGEMENT = ServerManagement(
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
        allow=allow,
        statistic=None,
        link_timeout=CONFIG["rns_server"]["link_timeout"],
        default_user=None,
        default_user_interfaces=CONFIG["rns_server"]["default_user_interfaces"].split(","),
        default_user_hops=int(CONFIG["rns_server"]["default_user_hops"]),
        default_user_callback=setup_default_user,
        configs_cmd=configs_cmd,
        environment_variables=environment_variables,
        services_system_path=CONFIG["services"]["system_path"],
        services_system_extension=CONFIG["services"]["system_extension"],
        services_files=services_files,
        limiter_server_enabled=CONFIG["rns_server"].getboolean("limiter_server_enabled"),
        limiter_server_calls=CONFIG["rns_server"]["limiter_server_calls"],
        limiter_server_size=CONFIG["rns_server"]["limiter_server_size"],
        limiter_server_duration=CONFIG["rns_server"]["limiter_server_duration"],
        limiter_peer_enabled=CONFIG["rns_server"].getboolean("limiter_peer_enabled"),
        limiter_peer_calls=CONFIG["rns_server"]["limiter_peer_calls"],
        limiter_peer_size=CONFIG["rns_server"]["limiter_peer_size"],
        limiter_peer_duration=CONFIG["rns_server"]["limiter_peer_duration"],
    )

    log("RNS - Connected", LOG_DEBUG)

    log("...............................................................................", LOG_FORCE)
    log("RNS - Address: " + RNS.prettyhexrep(RNS_SERVER_MANAGEMENT.destination_hash()), LOG_FORCE)
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


[allowed]
#2858b7a096899116cd529559cc679ffe


[environment_variables]


[services_files]
'''


#### Default configuration file ####
DEFAULT_CONFIG = '''# This is the default config file.
# You should probably edit it to suit your needs and use-case.


#### Main program settings ####
[main]

# Enable/Disable this functionality.
enabled = True

# Name of the program. Only for display in the log or program startup.
name = RNS Server Management


#### RNS server settings ####
[rns_server]

# Enable ratchets for the destination
destination_ratchets = No

# Destination name & type need to fits the RNS protocoll
# to be compatibel with other RNS programs.
destination_name = nomadnetwork
destination_type = management

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

# Limits the number of simultaneous requests/calls per server.
limiter_server_enabled = No
limiter_server_calls = 1000 # Number of calls per duration. 0=Any
limiter_server_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_server_duration = 60 # Seconds

# Limits the number of simultaneous requests/calls per peer.
limiter_peer_enabled = Yes
limiter_peer_calls = 0 # Number of calls per duration. 0=Any
limiter_peer_size = 0 # Data transfer size in bytes per duration. 0=Any
limiter_peer_duration = 60 # Seconds

# Timout after a link is disconnected after inactivity.
link_timeout = 300 #Seconds

# Create default admin user - Restriction to interfaces (,-separated list) (empty=any)
default_user_interfaces = AutoInterface,BZ1Interface,KISSInterface,RNodeInterface,SerialInterface

# Create default admin user - Maximum number of hops (0=any)
default_user_hops = 1


#### Telemetry settings ####
[telemetry]
location_enabled = False
location_lat = 0
location_lon = 0

owner_enabled = False
owner_data = 

state_enabled = False
state_data = 0


#### Right settings ####
# Allow only specific source addresses/hashs.
[allowed]
#2858b7a096899116cd529559cc679ffe


#### configs_cmd settings ####
[configs_cmd]
reboot = reboot
shutdown = shutdown


#### Environment settings ####
[environment_variables]


#### Services settings ####
[services]
system_path = /etc/systemd/system
system_extension = .service


#### Paths where the configuration files of the service are located. ####
[services_files]
'''


##############################################################################################################
# Init


if __name__ == "__main__":
    main()