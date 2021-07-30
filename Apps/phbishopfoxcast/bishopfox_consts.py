# File: bishopfox_consts.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

SEVERITY_MAP = {
    "Critical": "High",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low"
}

STATUS_CODES = {
    "new": "0",
    "acknowledged": "1",
    "request re-test": "2",
    "re-test validated": "3",
    "re-test failed": "4",
    "remediated": "5",
    "won't fix": "6",
    "not applicable": "7"
}

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
