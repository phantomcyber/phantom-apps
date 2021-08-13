# File: thehive_consts.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

THEHIVE_ERR_FIELDS_JSON_PARSE = "Unable to parse the fields parameter into a dictionary"
THEHIVE_ERR_INVALID_SEVERITY = "Invalid severity entered. Must be one of: Low, Medium, or High."
THEHIVE_ERR_INVALID_TLP = "Invalid TLP entered. Must be one of: White, Green, Amber, or Red."

THEHIVE_SEVERITY_DICT = {"Low": 1, "Medium": 2, "High": 3}
THEHIVE_TLP_DICT = {"White": 0, "Green": 1, "Amber": 2, "Red": 3}
