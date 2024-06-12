#!/usr/bin/env python3


import os
import json


try:
    with open("/tmp/example1.1.json", "r") as fh:
        data = json.load(fh)

except FileNotFoundError:
    data = {}
    data["l"] = ["label", "Label input", "GUI test", "l"]
    data["t"] = ["text", "Text input", "GUI test", "t", "Some text", ""]
    data["t0"] = ["text", "Text input min 4", "GUI test", "t", "Some text", "", 4]
    data["t1"] = ["text", "Text input max 16", "GUI test", "t", "Some text", "", 0, 16]
    data["m"] = ["text", "Text multiline input", "GUI test", "m", "Some multiline\ntext", ""]
    data["m0"] = ["text", "Text multiline input min 4", "GUI test", "m", "Some multiline\ntext", "", 4]
    data["m1"] = ["text", "Text multiline input max 64", "GUI test", "m", "Some multiline\ntext", "", 0, 64]
    data["p"] = ["text", "Password input", "GUI test", "p", "Password", ""]
    data["i"] = ["numeric-1-box-multiple-outline", "Number int input", "GUI test", "i", 11, 0]
    data["i1"] = ["numeric-1-box-multiple-outline", "Number int input 0-50", "GUI test", "i", 11, 0, 0, 50]
    data["f"] = ["numeric-1-box-multiple-outline", "Number float input", "GUI test", "f", 1.5, 0]
    data["f1"] = ["numeric-1-box-multiple-outline", "Number float input 1-5", "GUI test", "f", 1.5, 1.0, 1.0, 5.0]
    data["s"] = ["electric-switch-closed", "Number slider input", "GUI test", "s", 50, 0, 0, 100]
    data["si"] = ["electric-switch-closed", "Number slider int input", "GUI test", "si", 50, 0, 0, 100]
    data["sf"] = ["electric-switch-closed", "Number slider float input", "GUI test", "sf", 5.0, 0, 0, 20]
    data["b"] = ["toggle-switch", "Boolean input", "GUI test", "b", True, False]
    data["d"] = ["form-dropdown", "Dropdown input", "GUI test", "d", "1", "0", {"0": "-", "1": "Option 1", "2": "Option 2", "3": "Option 3"}]
    data["c"] = ["tag", "Chips/Tags input", "GUI test", "c", ["1"], [], {"1": "Tag 1", "2": "Tag 2", "3": "Tag 3"}]
    data["tp"] = ["clock-time-eight", "Time picker input", "GUI test", "tp", "12:00:00", "12:00:00"]
    data["dp"] = ["calendar-month", "Date picker input", "GUI test", "dp", "2023-12-01", "2023-12-01"]
    data["cp"] = ["palette", "Color picker input", "GUI test", "cp", "FF0000", "FF0000"]

    with open("/tmp/example1.1.json", 'w') as fh:
        json.dump(data, fh, indent=2)


if "data" in os.environ:
    data_dict = json.loads(os.environ["data"])
    for key, value in data_dict.items():
        if key in data:
            data[key][4] = value
    with open("/tmp/example1.1.json", 'w') as fh:
        json.dump(data, fh, indent=2)

else:
    json_data = json.dumps(data)
    print(json_data)
