# File: signalfx_consts.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# Define your constants here

# exception handling
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Integer validation constants
VALID_INTEGER_MSG = "Please provide a valid integer value in the {key}"
POSITIVE_INTEGER_MSG = "Please provide a valid non-zero positive integer value in the {key}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {key}"

# page size
PAGE_SIZE = 100
LIMIT_PARAM_KEY = "'limit' action parameter"
