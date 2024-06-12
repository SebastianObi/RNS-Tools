#!/usr/bin/env python3


import json
import subprocess

filters = ["rnsd", "lxmd", "nomadnet", "rns_", "lxmf_", "blockchain_", "bridge_", "channel_", "echo_", "group_", "page_", "propagation_", "provisioning_", "shop_"]

data = {}


try:
    result = subprocess.run(['systemctl', 'list-unit-files', '--type=service'], capture_output=True, text=True)
    if result.returncode == 0:
        for line in result.stdout.split('\n')[1:-1]:
            columns = line.split()
            key = columns[0]
            if key.endswith(".service"):
                key = key[:-len(".service")]
            if len(filters) > 0:
                for element in filters:
                    if element.lower() in key.lower():
                        data[key] = [columns[1].lower(), ""]
                        break
            else:
                data[key] = [columns[1].lower(), ""]
except:
    pass

try:
    result = subprocess.run(['systemctl', 'list-units', '--type=service'], capture_output=True, text=True)
    if result.returncode == 0:
        for line in result.stdout.split('\n')[1:-1]:
            columns = line.split()
            key = columns[0]
            if key.endswith(".service"):
                key = key[:-len(".service")]
            if key in data:
                data[key][1] = columns[2].lower()
except:
    pass


json_data = json.dumps(data)

print(json_data)
