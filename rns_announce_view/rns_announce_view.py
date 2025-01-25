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

#### Reticulum ####
# Install: pip3 install rns
# Source: https://markqvist.github.io
import RNS
import RNS.vendor.umsgpack as msgpack


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "RNS Announce View"
DESCRIPTION = "View received announcements"
VERSION = "0.0.1 (2024-05-31)"
COPYRIGHT = "(c) 2024 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/"+os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None


#### Global Variables - System (Not changeable) ####
DATA = None
SEARCH = None
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
# Announce functions

def announce_view(dest, dest_type=0x01, dest_recall=None, dest_recall_type=None, data="", metadata=None, location_lat=0, location_lon=0, owner=None, state=0, state_ts=0, hop_count=0, hop_interface="", hop_dest=None, aspect_filter=""):
    global DATA
    global SEARCH

    dest_str = RNS.prettyhexrep(dest)

    if SEARCH:
        if SEARCH not in dest_str.lower() and SEARCH not in data.lower() and SEARCH not in hop_interface.lower():
            return

    if dest not in DATA:
        DATA[dest] = 0
    DATA[dest] += 1

    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+"  |  "+dest_str+"  |  "+data+"  |  "+aspect_filter+"  |  "+str(hop_count)+"  |  "+hop_interface+"  |  "+str(DATA[dest]))


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
def setup(path=None, path_rns=None, path_log=None, loglevel=None, service=False, require_shared_instance=False, search="", aspect_filter="", dest_allow="", dest_deny="", hop_min=0, hop_max=0, hop_interfaces="", hidden=True, recall_app_data=True):
    global DATA
    global SEARCH
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

    DATA = {}

    SEARCH = search.lower()

    RNS_CONNECTION = RNS.Reticulum(configdir=PATH_RNS, loglevel=rns_loglevel, require_shared_instance=require_shared_instance)

    log("...............................................................................", LOG_INFO)
    log("        Name: " + NAME, LOG_INFO)
    log("Program File: " + __file__, LOG_INFO)
    log("     Version: " + VERSION, LOG_INFO)
    log("   Copyright: " + COPYRIGHT, LOG_INFO)
    log("...............................................................................", LOG_INFO)

    log("RNS - Connecting ...", LOG_DEBUG)

    RNS_ANNOUNCE_HANDLER = {}

    if aspect_filter.strip() != "":
        aspect_filter = aspect_filter.strip().split(",")
    else:
        aspect_filter = []

    if dest_allow.strip() != "":
        dest_allow_array = dest_allow.strip().split(",")
        dest_allow = []
        for val in dest_allow_array:
            try:
                if len(val) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                    val = val[1:-1]
                if len(val) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                    continue
                val = bytes.fromhex(val)
                dest_allow.append(val)
            except:
                pass
    else:
        dest_allow = []

    if dest_deny.strip() != "":
        dest_deny_array = dest_deny.strip().split(",")
        dest_deny = []
        for val in dest_deny_array:
            try:
                if len(val) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                    val = val[1:-1]
                if len(val) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                    continue
                val = bytes.fromhex(val)
                dest_deny.append(val)
            except:
                pass
    else:
        dest_deny = []

    if hop_interfaces.strip() != "":
        hop_interfaces = hop_interfaces.strip().split(",")
    else:
        hop_interfaces = []

    for val in aspect_filter:
        try:
            RNS_ANNOUNCE_HANDLER[val] = AnnounceHandler(val, announce_view, None, hidden, hop_min, hop_max, hop_interfaces, recall_app_data, None, dest_allow, dest_deny)
            RNS.Transport.register_announce_handler(RNS_ANNOUNCE_HANDLER[val])
            log("RNS - Added announce handler for '"+val+"'", LOG_DEBUG)
        except Exception as e:
            log("RNS - Error while adding announce handler: "+str(e), LOG_ERROR)

    if len(RNS_ANNOUNCE_HANDLER) == 0:
        log("RNS - Error: No announce handlers connected", LOG_ERROR)
        panic()
    else:
        log("RNS - Connected with "+str(len(RNS_ANNOUNCE_HANDLER))+" announce handlers", LOG_DEBUG)

        print(NAME+" started with "+str(len(RNS_ANNOUNCE_HANDLER))+" announce handlers "+str(aspect_filter))
        print()
        print("Date/Time  |  Destination  | Data |  Aspect  |  Hops  |  Hop interface  |  #")

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

        parser.add_argument("--search", action="store", type=str, default="", help="Search string for destination, data or hop interface")

        parser.add_argument("-f", "--aspect_filter", action="store", required=True, type=str, default="", help="Aspect ,-separated list with one ore more aspects")

        parser.add_argument("-a", "--dest_allow", action="store", type=str, default="", help="Allow certain addresses ,-separated list with one ore more addresses")
        parser.add_argument("-d", "--dest_deny", action="store", type=str, default="", help="Deny certain addresses ,-separated list with one ore more addresses")

        parser.add_argument("--hop_min", action="store", type=int, default=0, help="Minimum hop count")
        parser.add_argument("--hop_max", action="store", type=int, default=0, help="Maximum hop count")
        parser.add_argument("-i", "--hop_interfaces", action="store", type=str, default="", help="Hop interfaces ,-separated list with interface names")

        parser.add_argument("--hidden", action="store_true", default=True, help="View hidden announces")
        parser.add_argument("--recall_app_data", action="store", type=str, default="", help="Recall app data with other aspect to get the announced data")

        params = parser.parse_args()

        setup(path=params.path, path_rns=params.path_rns, path_log=params.path_log, loglevel=params.loglevel, service=params.service, require_shared_instance=params.require_shared_instance, search=params.search, aspect_filter=params.aspect_filter, dest_allow=params.dest_allow, dest_deny=params.dest_deny, hop_min=params.hop_min, hop_max=params.hop_max, hop_interfaces=params.hop_interfaces, hidden=params.hidden, recall_app_data=params.recall_app_data)

    except KeyboardInterrupt:
        print("Terminated by CTRL-C")
        exit()


##############################################################################################################
# Init


if __name__ == "__main__":
    main()