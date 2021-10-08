# File: ssmachine_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --
SSMACHINE_JSON_DOMAIN = "https://api.screenshotmachine.com/"
MAX_CACHE_LIMIT = 14
DEFAULT_CACHE_LIMIT = 0
VALID_CACHE_LIMIT_MSG = "Please provide a valid value in the 'Cache Limit' configuration parameter, the allowed range is [0-14]"

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
