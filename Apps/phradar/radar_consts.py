# File: radar_consts.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
ALLOW_SELF_SIGNED_CERTS = "ALLOW_SELF_SIGNED_CERTS"

# Constants relating to '_get_error_message_from_exception'
ERROR_CODE_MSG = "Error code unavailable"
ERROR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Radar Server. Please check the asset configuration and|or the action parameters"

# Constants relating to '_validate_integer'
VALID_INTEGER_MSG = "Please provide a valid integer value in the {}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {}"
INCIDENT_ID_KEY = "'incident_id' action parameter"
