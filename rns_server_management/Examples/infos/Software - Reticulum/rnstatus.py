#!/usr/bin/env python3


import json

import re
import subprocess
import os

reticulum_config_paths = ["/home/nomad/.reticulum"]


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


reticulum_config = ""
for key in reticulum_config_paths:
   if os.path.isdir(key):
       reticulum_config = " --config "+key
       break

result = cmd("rnstatus -j"+reticulum_config)
if result != "":
    stats = json.loads(result)
    if stats != None:
        for ifstat in stats["interfaces"]:
            if ifstat["name"].startswith("LocalInterface["):
                continue

            text0 = "[b]RX:[/b] "+size_str(ifstat["rxb"])+" "+"[b]TX:[/b] "+size_str(ifstat["txb"])

            if ifstat["status"]:
                text0 += " [b]Status:[/b] Up"
            else:
                text0 += " [b]Status:[/b] Down"

            if "clients" in ifstat and ifstat["clients"] != None:
                text0 += " [b]Clients:[/b] "+str(ifstat["clients"])

            if "peers" in ifstat and ifstat["peers"] != None:
                text0 += " [b]Peers:[/b] "+str(ifstat["peers"])

            text1 = ""

            if ifstat["mode"] == 0x03:
                text1 += " [b]Mode:[/b] Access Point"
            elif ifstat["mode"] == 0x02:
                text1 += " [b]Mode:[/b] Point-to-Point"
            elif ifstat["mode"] == 0x04:
                text1 += " [b]Mode:[/b] Roaming"
            elif ifstat["mode"] == 0x05:
                text1 += " [b]Mode:[/b] Boundary"
            elif ifstat["mode"] == 0x06:
                text1 += " [b]Mode:[/b] Gateway"
            else:
                text1 += " [b]Mode:[/b] Full"

            if "bitrate" in ifstat and ifstat["bitrate"] != None:
                text1 += " [b]Speed:[/b] "+speed_str(ifstat["bitrate"])

            if "airtime_short" in ifstat and "airtime_long" in ifstat:
                text1 += " [b] Airtime:[/b] "+str(ifstat["airtime_short"])+"% (15s), "+str(ifstat["airtime_long"])+"% (1h)"

            if "channel_load_short" in ifstat and "channel_load_long" in ifstat:
                text1 += " [b]Ch. Load:[/b] "+str(ifstat["channel_load_short"])+"% (15s), "+str(ifstat["channel_load_long"])+"% (1h)"

            if "tunnelstate" in ifstat and ifstat["tunnelstate"] != None:
                text += " [b]I2P:[/b] "+ifstat["tunnelstate"]

            if "announce_queue" in ifstat and ifstat["announce_queue"] != None and ifstat["announce_queue"] > 0:
                aqn = ifstat["announce_queue"]
                if aqn == 1:
                    text1 += " [b] Queued:[/b] "+str(aqn)+" announce"
                else:
                    text1 += " [b] Queued:[/b] "+str(aqn)+" announces"

            if "held_announces" in ifstat and ifstat["held_announces"] != None and ifstat["held_announces"] > 0:
                aqn = ifstat["held_announces"]
                if aqn == 1:
                    text1 += " [b]Held:[/b] "+str(aqn)+" announce"
                else:
                    text1 += " [b]Held:[/b] "+str(aqn)+" announces"

            if "incoming_announce_frequency" in ifstat and ifstat["incoming_announce_frequency"] != None:
                text1 += " [b]Announces:[/b] "+frequency_str(ifstat["outgoing_announce_frequency"])+" up "+frequency_str(ifstat["incoming_announce_frequency"])+" down"

            data[ifstat["name"]] = [text0.strip(), text1.strip(), "connection", 0x01 if ifstat["status"] == True else 0x04]

        if "transport_id" in stats and stats["transport_id"] != None:
            data["Transport Instance"] = ["Running", "", "router", 0x00]

            if "probe_responder" in stats and stats["probe_responder"] != None:
                data["Probe responder"] = ["Running", "", "reply", 0x00]
            data["Uptime"] = [prettytime(stats["transport_uptime"]), "", "clock-time-eight", 0x00]


json_data = json.dumps(data)

print(json_data)
