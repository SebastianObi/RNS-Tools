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
# Reticulum, LXMF, NomadNet  /  Copyright (c) 2016-2022 Mark Qvist  /  unsigned.io  /  MIT License
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


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "RNS Hop Simulator"
DESCRIPTION = "Simulation and test system for several hops"
VERSION = "0.0.1 (2024-05-31)"
COPYRIGHT = "(c) 2024 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/"+os.path.splitext(os.path.basename(__file__))[0]


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
def setup(path=None, path_log=None, loglevel=None, service=False, count=2, cfg_entry=None, cfg_exit=None, mode="gateway"):
    global PATH
    global LOG_LEVEL
    global LOG_FILE

    if path is not None:
        if path.endswith("/"):
            path = path[:-1]
        PATH = path

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

    log("...............................................................................", LOG_INFO)
    log("        Name: " + NAME + " - " + DESCRIPTION, LOG_INFO)
    log("Program File: " + __file__, LOG_INFO)
    log("     Version: " + VERSION, LOG_INFO)
    log("   Copyright: " + COPYRIGHT, LOG_INFO)
    log("...............................................................................", LOG_INFO)

    if count < 2:
        count = 2

    for instance in range(count):
        try:
            log_string = "RNS #"+str(instance)
            if instance == 0:
                log_string += " (Entry)"
            elif instance == count-1:
                log_string += " (Exit)"
            else:
                log_string += " (Hop)"

            log(log_string+" - Starting ...", LOG_DEBUG)

            if instance == 0:
                config = """
[reticulum]
  enable_transport = True
  share_instance = No
  shared_instance_port = """+str(31000+instance)+"""
  instance_control_port = """+str(32000+instance)+"""
  panic_on_interface_error = No

[interfaces]

[[tcp_server_instance]]
type = TCPServerInterface
enabled = True
outgoing = True
mode = """+mode+"""
listen_ip = 0.0.0.0
listen_port = """+str(41000+instance)+"""
"""
                if os.path.exists(cfg_entry):
                    with open(cfg_entry, "r") as fh:
                       config += "\n"+fh.read()
                else:
                    raise ValueError("Config file not exist.")

            elif instance == count-1:
                config = """
[reticulum]
  enable_transport = True
  share_instance = No
  shared_instance_port = """+str(31000+instance)+"""
  instance_control_port = """+str(32000+instance)+"""
  panic_on_interface_error = No

[interfaces]

[[tcp_client_instance]]
type = TCPClientInterface
enabled = True
outgoing = True
mode = """+mode+"""
target_host = 127.0.0.1
target_port = """+str(41000+instance-1)+"""
"""
                if os.path.exists(cfg_exit):
                    with open(cfg_exit, "r") as fh:
                       config += "\n"+fh.read()
                else:
                    raise ValueError("Config file not exist.")

            else:
                config = """
[reticulum]
  enable_transport = True
  share_instance = No
  shared_instance_port = """+str(31000+instance)+"""
  instance_control_port = """+str(32000+instance)+"""
  panic_on_interface_error = No

[interfaces]

[[tcp_server_instance]]
type = TCPServerInterface
enabled = True
outgoing = True
mode = """+mode+"""
listen_ip = 0.0.0.0
listen_port = """+str(41000+instance)+"""

[[tcp_client_instance]]
type = TCPClientInterface
enabled = True
outgoing = True
mode = """+mode+"""
target_host = 127.0.0.1
target_port = """+str(41000+instance-1)+"""
"""

            configdir = PATH+"/"+str(instance)
            if not os.path.exists(configdir):
                os.makedirs(configdir)
            with open(configdir+"/config", "w") as fh:
                fh.write(config)

            params = base64.b64encode(msgpack.packb([instance, configdir, rns_loglevel])).decode("utf-8")
            command = ["python", __file__, "-r "+params]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        except Exception as e:
            log(log_string+" - Error: "+str(e), LOG_ERROR)
            panic()

        print(log_string+" - Started")

    print("")
    print("Press CTRL-C to exit")

    while True:
        time.sleep(5)


#### RNS ####
def rns(params):
    global PATH

    try:
        instance = None
        instance, configdir, loglevel = msgpack.unpackb(base64.b64decode(params))

        if not os.path.exists(configdir):
            raise ValueError("Config path not exist.")

        if not os.path.exists(configdir+"/config"):
            raise ValueError("Config file not exist.")

        rns_connection = RNS.Reticulum(configdir=configdir, loglevel=loglevel)

    except Exception as e:
        log("RNS #"+str(instance)+" - Error: "+str(e), LOG_ERROR)
        panic()

    while True:
        time.sleep(5)


#### Start ####
def main():
    try:
        description = NAME + " - " + DESCRIPTION
        parser = argparse.ArgumentParser(description=description)

        parser.add_argument("-p", "--path", action="store", type=str, default=None, help="Path to alternative config directory")
        parser.add_argument("-pl", "--path_log", action="store", type=str, default=None, help="Path to alternative log directory")
        parser.add_argument("-l", "--loglevel", action="store", type=int, default=LOG_LEVEL)
        parser.add_argument("-s", "--service", action="store_true", default=False, help="Running as a service and should log to file")

        parser.add_argument("-c", "--count", action="store", type=int, default=2, help="Hop count")
        parser.add_argument("--cfg_entry", action="store", type=str, default="cfg_entry", help="Interface configuration of the entry hop/node (Which clients connect to)")
        parser.add_argument("--cfg_exit", action="store", type=str, default="cfg_exit", help="Interface configuration of the exit hop/node (Which connects to an existing node)")
        parser.add_argument("-m", "--mode", action="store", type=str, default="gateway", help="Interface mode (full/accesspoint/roaming/boundary/gateway)")

        parser.add_argument("-r", "--rns", action="store", type=str, default=None, help="Internal start parameter of the RNS instance (do not use)")

        parser.add_argument("--example_cfg_entry", action="store_true", default=False, help="Print verbose configuration example to stdout and exit")
        parser.add_argument("--example_cfg_exit", action="store_true", default=False, help="Print verbose configuration example to stdout and exit")

        params = parser.parse_args()

        if params.example_cfg_entry:
            print("Config File: " + PATH + "/example_cfg_entry")
            print("Content:")
            print(DEFAULT_CFG_ENTRY)
            exit()

        if params.example_cfg_exit:
            print("Config File: " + PATH + "/example_cfg_exit")
            print("Content:")
            print(DEFAULT_CFG_EXIT)
            exit()

        if params.rns != None:
            rns(params.rns)
            return

        setup(path=params.path, path_log=params.path_log, loglevel=params.loglevel, service=params.service, count=params.count, cfg_entry=params.cfg_entry, cfg_exit=params.cfg_exit, mode=params.mode)

    except KeyboardInterrupt:
        print("Terminated by CTRL-C")
        exit()


##############################################################################################################
# Files


DEFAULT_CFG_ENTRY = '''
[[Default]]
type = AutoInterface
enabled = True
mode = gateway

[[TCP Server]]
type = TCPServerInterface
enabled = True
outgoing = True
mode = gateway
listen_ip = 0.0.0.0
listen_port = 42042
'''


DEFAULT_CFG_EXIT = '''
[[TCP Testnet]]
type = TCPClientInterface
enabled = True
outgoing = True
mode = boundary
target_host = amsterdam.connect.reticulum.network
target_port = 4965
'''


##############################################################################################################
# Init


if __name__ == "__main__":
    main()