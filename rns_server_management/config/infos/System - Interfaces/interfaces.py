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


result = cmd("ls /sys/class/net | grep -v lo")
if result != "":
    interface = []
    regex = re.findall(r'(\w+)', result)
    for match in regex:
        interface.append(match)
    data["LAN"] = [", ".join(interface), "", "ethernet-cable", 0x00]

result = cmd("iw dev")
if result != "":
    interface = []
    result = result + "\n"
    regex = re.findall(r'Interface\s(.*)\n', result)
    for match in regex:
        interface.append(match)
    data["WiFi"] = [", ".join(interface), "", "wifi", 0x00]

#result = cmd("for i in $(ls /sys/class/net/ | egrep -v ^lo$); do sudo iw dev $i scan | grep SSID | awk '{print substr($0, index($0,$2)) }'; done 2>/dev/null | sort -u")
#if result != "":
#    interface = []
#    result = result + "\n"
#    regex = re.findall(r'(.*)\n', result)
#    for match in regex:
#        if match != "SSID List":
#            interface.append(match)
#    data["WiFi networks"] = [", ".join(interface), "", "wifi", 0x00]

#result = cmd("iwconfig")
#if result != "":
#    interface = []
#    regex = re.findall(r'ESSID:\"([^"]+)\"', result)
#    for match in regex:
#        interface.append(match)
#    data["WiFi networks connected"] = [", ".join(interface), "", "wifi", 0x00]

result = cmd("lsusb")
if result != "":
    interface = []
    data["interface_usb_raw"] = result
    result = result + "\n"
    regex = re.findall(r'(.*)\n', result)
    for match in regex:
        interface.append(match)
    data["USB"] = [", ".join(interface), "", "usb", 0x00]

result = cmd("ls /sys/class/bluetooth/")
if result != "":
    interface = []
    data["interface_bluetooth_raw"] = result
    regex = re.findall(r'(\w+)', result)
    for match in regex:
        interface.append(match)
    data["Bluetooth"] = [", ".join(interface), "", "bluetooth", 0x00]

interface = []
result = cmd("ls /dev/ | grep 'ttyACM\|ttyUSB'")
if result != "":
    data["interface_serial_raw"] = data["interface_serial_raw"] + result
    result = result + "\n"
    regex = re.findall(r'(.*)\n', result)
    for match in regex:
        interface.append(match)
result = cmd("ls /dev/serial/by-id/")
if result != "":
    data["interface_serial_raw"] = data["interface_serial_raw"] + result
    result = result + "\n"
    regex = re.findall(r'(.*)\n', result)
    for match in regex:
        interface.append("/dev/serial/by-id/" + match)
if len(interface) > 0:
    data["Serial"] = [", ".join(interface), "", "serial-port", 0x00]

result = cmd("ls /dev/snd")
if result != "":
    interface = []
    data["interface_snd_raw"] = data["interface_snd_raw"] + result
    result = result + "\n"
    regex = re.findall(r'(.*)\n', result)
    for match in regex:
        interface.append(match)
    data["SND"] = [", ".join(interface), "", "volume-high", 0x00]

result = cmd("ls /dev/ | grep 'ttyUSB'")
if result != "":
    interface = []
    data["interface_cat_raw"] = data["interface_cat_raw"] + result
    result = result + "\n"
    regex = re.findall(r'(.*)\n', result)
    for match in regex:
        interface.append(match)
    data["CAT"] = [", ".join(interface), "", "volume-high", 0x00]


json_data = json.dumps(data)

print(json_data)
