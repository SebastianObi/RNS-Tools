#!/usr/bin/env python3


import json


data = {}


# Normal element data["<text 1st row>"] = ["<text 2nd row>", "<text 3rd row>", "<icon>", "<status>"]
data["Example1.1"] = ["Test data", "", "text", 0x00]

# Reference/Link data["<text 1st row>"] = ["<text 2nd row>", "<text 3rd row>", "<icon>", "<status>"", "<type>", "<value>"]
data["Example1.2"] = ["Reference", "External link", "link-variant", 0, "r", "https://www.google.com"]

# Reference/Link data["<text 1st row>"] = ["<text 2nd row>", "<text 3rd row>", "<icon>", "<status>"", "<type>", "<value>"]
data["Example1.3"] = ["Reference", "Internal link", "link-variant", 0, "r", "page@0fe4e4f9819c14e8fecc831e6c1f8672"]

# Action (internal) data["<text 1st row>"] = ["<text 2nd row>", "<text 3rd row>", "<icon>", "<status>"", "<type>", "<action>", "<value>"]
data["Example1.4"] = ["Action", "Infos", "link-variant", 0, "a", "infos", "/"]

# Action (internal) data["<text 1st row>"] = ["<text 2nd row>", "<text 3rd row>", "<icon>", "<status>"", "<type>", "<action>", "<value>"]
data["Example1.5"] = ["Action", "Files", "link-variant", 0, "a", "files", "/tmp"]


json_data = json.dumps(data)

print(json_data)
