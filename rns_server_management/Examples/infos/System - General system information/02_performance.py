#!/usr/bin/env python3


import json

import re
import subprocess


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


result0 = cmd("awk '/^cpu / {idle=$5; total=$1+$2+$3+$4+$5+$6+$7+$8} END {print 100 - (idle / total * 100)}' /proc/stat")
result1 = cmd("awk '{print $1}' /proc/loadavg")
if result0 != "" and result1 != "":
    data["CPU load"] = ["[b]%:[/b] "+result0.replace("\n", ""), "[b]AVG:[/b] "+ result1.replace("\n", ""), "cpu-64-bit", 0x01]

result = cmd("nproc --all")
if result != "":
    data["CPU cores"] = [result.replace("\n", ""), "", "cpu-64-bit", 0x00]

#import psutil
#result = str(round(psutil.virtual_memory().percent))
#if result != "":
#    data["RAM %"] = [result, "", "memory", 0x01]

#import psutil
#result = str(round(psutil.swap_memory().percent))
#if result != "":
#    data["SWAP %"] = [result, "", "memory", 0x01]

result = cmd("free -b")
if result != "":
    if group := re.search(r'^Mem:\s+(\d+)\s+(\d+)\s+(\d+).*', result, flags=re.M):
        if group[1] == "0" or group[2] == "0":
            percent = "0"
        else:
            percent = str(round(int(group[2])/int(group[1])*100, 2))
        data["RAM"] = ["[b]%:[/b] "+percent+"   [b]Größe:[/b] "+size_str(int(group[2]))+"/"+size_str(int(group[1])), "[b]Frei:[/b] "+size_str(int(group[3])), "memory", 0x01]
    if group := re.search(r'^Swap:\s+(\d+)\s+(\d+)\s+(\d+)', result, flags=re.M):
        if group[1] == "0" or group[2] == "0":
            percent = "0"
        else:
            percent = str(round(int(group[2])/int(group[1])*100, 2))
        data["SWAP"] = ["[b]%:[/b] "+percent+"   [b]Größe:[/b] "+size_str(int(group[2]))+"/"+size_str(int(group[1])), "[b]Frei:[/b] "+size_str(int(group[3])), "memory", 0x01]

result = cmd("cat /sys/class/thermal/thermal_zone0/temp")
if result != "":
    data["System temperature"] = [str(int(result)/1000) + "°C", "", "thermometer", 0x01]


json_data = json.dumps(data)

print(json_data)
