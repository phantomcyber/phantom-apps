# File: autofocus_consts.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

AF_JSON_API_KEY = "api_key"
AF_JSON_SCOPE = "scope"
AF_JSON_SIZE = "size"
AF_JSON_FROM = "from"
AF_JSON_HASH = "hash"
AF_JSON_IP = "ip"
AF_JSON_DOMAIN = "domain"
AF_JSON_URL = "url"
AF_JSON_TAG = "tag"

AF_ERR_INVALID_SCOPE = "Invalid scope: {0}"
AF_ERR_TOO_BIG = "from + size can not be greater than {0}"

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Auto Focus Server. Please check the asset configuration and|or the action parameters"

STATE_FILE_CORRUPT_ERR = "Error occurred while loading the state file due to its unexpected format. Resetting the state file with the default format. Please try again"
