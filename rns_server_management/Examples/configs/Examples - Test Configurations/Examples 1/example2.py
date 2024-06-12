#!/usr/bin/env python3


import os
import json


try:
    with open("/tmp/example1.2.json", "r") as fh:
        data = json.load(fh)

except FileNotFoundError:
    data = {}
    data["t0"] = ["text", "Text 2.1", "Text input 1", "t", "Some text", ""]
    data["t1"] = ["text", "Text 2.2", "text input 2", "t", "Some other text", ""]

    with open("/tmp/example1.2.json", 'w') as fh:
        json.dump(data, fh, indent=2)


if "data" in os.environ:
    data_dict = json.loads(os.environ["data"])
    for key, value in data_dict.items():
        if key in data:
            data[key][4] = value
    with open("/tmp/example1.2.json", 'w') as fh:
        json.dump(data, fh, indent=2)

else:
    json_data = json.dumps(data)
    print(json_data)
