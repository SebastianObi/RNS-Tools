#!/usr/bin/env python3


import os
import json


try:
    with open("/tmp/example1.1.json", "r") as fh:
        data = json.load(fh)

except FileNotFoundError:
    data = {}

    # Each key in the dictionary must be unique and represents the variable name.

    # Label ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>"]
    data["l"] = ["label", "Label", "GUI test", "l"]

    # Text input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>"]
    data["t"] = ["text", "Text input", "GUI test", "t", "Some text", ""]

    # Text input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>", <lenght_min>]
    data["t0"] = ["text", "Text input min 4", "GUI test", "t", "Some text", "", 4]

    # Text input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>", <lenght_min>, <lenght_max>]
    data["t1"] = ["text", "Text input max 16", "GUI test", "t", "Some text", "", 0, 16]

    # Text multiline input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>"]
    data["m"] = ["text", "Text multiline input", "GUI test", "m", "Some multiline\ntext", ""]

    # Text multiline input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>", <lenght_min>]
    data["m0"] = ["text", "Text multiline input min 4", "GUI test", "m", "Some multiline\ntext", "", 4]

    # Text multiline input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>", <lenght_min>, <lenght_max>]
    data["m1"] = ["text", "Text multiline input max 64", "GUI test", "m", "Some multiline\ntext", "", 0, 64]

    # Text fullscreen input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>"]
    data["tf"] = ["text", "Text fullscreen input", "GUI test", "tf", "Some multiline\ntext", ""]

    # Password input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>"]
    data["p"] = ["text", "Password input", "GUI test", "p", "Password", ""]

    # Number int input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>"]
    data["i"] = ["numeric-1-box-multiple-outline", "Number int input", "GUI test", "i", 11, 0]

    # Number int input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>", <value_min>, <value_max>]
    data["i1"] = ["numeric-1-box-multiple-outline", "Number int input 0-50", "GUI test", "i", 11, 0, 0, 50]

    # Number float input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>"]
    data["f"] = ["numeric-1-box-multiple-outline", "Number float input", "GUI test", "f", 1.5, 0]

    # Number float input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>", <value_min>, <value_max>]
    data["f1"] = ["numeric-1-box-multiple-outline", "Number float input 1-5", "GUI test", "f", 1.5, 1.0, 1.0, 5.0]

    # Number float input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>", <value_min>, <value_max>]
    data["s"] = ["electric-switch-closed", "Number slider input", "GUI test", "s", 50, 0, 0, 100]

    # Number slider int input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>", <value_min>, <value_max>]
    data["si"] = ["electric-switch-closed", "Number slider int input", "GUI test", "si", 50, 0, 0, 100]

    # Number slider float input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>", <value_min>, <value_max>]
    data["sf"] = ["electric-switch-closed", "Number slider float input", "GUI test", "sf", 5.0, 0, 0, 20]

    # Boolean input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>"]
    data["b"] = ["toggle-switch", "Boolean input", "GUI test", "b", True, False]

    # Dropdown input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>", {<key and value pairs>}]
    data["d"] = ["form-dropdown", "Dropdown input", "GUI test", "d", "1", "0", {"0": "-", "1": "Option 1", "2": "Option 2", "3": "Option 3"}]

    # Chips/Tags input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", [<array with values>], [<array with values_default>], {<dict with key and value pairs>}]
    data["c"] = ["tag", "Chips/Tags input", "GUI test", "c", ["1"], [], {"1": "Tag 1", "2": "Tag 2", "3": "Tag 3"}]

    # Time picker input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>"]
    data["tp"] = ["clock-time-eight", "Time picker input", "GUI test", "tp", "12:00:00", "12:00:00"]

    # Date picker input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>"]
    data["dp"] = ["calendar-month", "Date picker input", "GUI test", "dp", "2023-12-01", "2023-12-01"]

    # Color picker input ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>", "<value_default>"]
    data["cp"] = ["palette", "Color picker input", "GUI test", "cp", "FF0000", "FF0000"]

    # Upload file ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>"]
    data["u"] = ["file", "Upload file input", "GUI test", "u", ""]

    # Upload text file ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>"]
    data["ut"] = ["file", "Upload text file input", "GUI test", "ut", ""]

    # Reference/Link ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>"]
    data["r"] = ["link-variant", "Reference", "External link", "r", "https://www.google.com"]

    # Reference/Link ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<value>"]
    data["r1"] = ["link-variant", "Reference", "Internal link", "r", "page@0fe4e4f9819c14e8fecc831e6c1f8672"]

    # Action (internal) ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<action>", "<value>"]
    data["a"] = ["link-variant", "Action", "Infos", "a", "infos", "/"]

    # Action (internal) ["<icon>", "<text 1st row>", "<text 2nd row>", "<type>", "<action>", "<value>"]
    data["a"] = ["link-variant", "Action", "Files", "a", "files", "/tmp"]

    # None/Empty []
    data["n"] = []

    with open("/tmp/example1.1.json", 'w') as fh:
        json.dump(data, fh, indent=2)


if "data" in os.environ:
    data_dict = json.loads(os.environ["data"])
    for key, value in data_dict.items():
        if key in data and data[key][3] != "u" and data[key][3] != "ut":
            data[key][4] = value
    with open("/tmp/example1.1.json", 'w') as fh:
        json.dump(data, fh, indent=2)

else:
    json_data = json.dumps(data)
    print(json_data)
