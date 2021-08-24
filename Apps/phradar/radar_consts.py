# File: radar_consts.py
# Copyright (c) 2020-2021 RADAR, LLC
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
ALLOW_SELF_SIGNED_CERTS = "ALLOW_SELF_SIGNED_CERTS"

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Constants relating to '_validate_integer'
VALID_INTEGER_MSG = "Please provide a valid integer value in the 'incident_id' action parameter"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid positive integer value in the 'incident_id' action parameter"
