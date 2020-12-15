# File: consolidatedscreeninglist_consts.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


BASE_URL = "https://api.trade.gov"
LOOKUP_ENDPOINT = "/gateway/v1/consolidated_screening_list/search?"

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Constants relating to '_validate_integer'
INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the {}"
INVALID_NON_ZERO_NON_NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-zero positive integer value in the {}"

LIMIT_KEY = "'limit' action parameter"
