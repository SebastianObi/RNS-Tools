#!/usr/bin/env python3


import json


data = {}


data["Example1"] = ["disabled", "inactive"]


json_data = json.dumps(data)

print(json_data)
