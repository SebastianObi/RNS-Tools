#!/usr/bin/env python3


import json

import re
import subprocess

import platform


def size_str(num, suffix='B'):
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


def speed_str(num, suffix='bps'):
    units = ['','k','M','G','T','P','E','Z']
    last_unit = 'Y'

    if suffix == 'Bps':
        num /= 8
        units = ['','K','M','G','T','P','E','Z']
        last_unit = 'Y'

    for unit in units:
        if abs(num) < 1000.0:
            return "%3.2f %s%s" % (num, unit, suffix)
        num /= 1000.0

    return "%.2f %s%s" % (num, last_unit, suffix)


def frequency_str(hz, suffix="Hz"):
    num = hz*1e6
    units = ["µ", "m", "", "K","M","G","T","P","E","Z"]
    last_unit = "Y"

    for unit in units:
        if abs(num) < 1000.0:
            return "%.2f %s%s" % (num, unit, suffix)
        num /= 1000.0

    return "%.2f%s%s" % (num, last_unit, suffix)


def prettytime(time):
    days = int(time // (24 * 3600))
    if days == 0:
        days = ""
    else:
        days = str(days)+"T "
    time = time % (24 * 3600)
    hours = int(time // 3600)
    time %= 3600
    minutes = int(time // 60)
    time %= 60
    seconds = int(time)
    return "{}{:0>2}:{:0>2}:{:0>2}".format(days, hours, minutes, seconds)


def cmd(cmd, default="", timeout=5):
    if cmd == "":
        return default
    try:
        result = subprocess.run(cmd, capture_output=True, shell=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return re.sub(r'^\s+|\s+$', '', result.stdout)
    except:
        None
    return default


def file(file, default=""):
    if file == "":
        return default
    try:
        file_handler = open(file)
        file_string = file_handler.read()
        file_handler.close()
        return re.sub(r'^\s+|\s+$', '', file_string)
    except:
        None
    return default


data = {}


result = platform.system()
if result != "":
    data["Platform"] = [result, "", "server", 0x00]

result = platform.release()
if result != "":
    data["Release"] = [result, "", "server", 0x00]

result = cmd("lsb_release -sd")
if result != "":
    data["Release name"] = [result, "", "server", 0x00]

result = file("/proc/cpuinfo")
if result != "":
    if group := re.search(r'Model\s+:\s+(.*)', result):
        data["Model"] = [group.group(1), "", "", 0x00]
    else:
        result = file("/proc/device-tree/model")
        if result != "":
            data["Model"] = [result, "", "server", 0x00]

result = cmd("hostname -f")
if result != "":
    data["Hostname"] = [result, "", "server", 0x00]

result = cmd("date +'%Y-%m-%d %T'")
if result != "":
    data["System time"] = [result, "", "clock-time-eight", 0x00]

result = cmd("uptime -s")
if result != "":
    data["Start time"] = [result, "", "clock-time-eight", 0x00]

result = cmd("uptime -p").replace("up ", "")
if result != "":
    data["Runtime"] = [result, "", "timer", 0x00]


json_data = json.dumps(data)

print(json_data)
