#!/usr/bin/env python3


import json


data = {}


data["Example1"] = ["Test data", "", "text", 0x00]


json_data = json.dumps(data)

print(json_data)
