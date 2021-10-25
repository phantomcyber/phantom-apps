# File: redcanary_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Define your constants here
RC_DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_PER_PAGE = 50
STR_LAST_RUN = "last_run"
STR_META = "meta"
STR_TOTAL_ITEMS = "total_items"
STR_NOT_FOUND = "not_found"
STR_PER_PAGE = "per_page="
STR_SINCE = "since="
STR_PAGE = "page="
DETECTION_ID_KEY = "'detection_id' action"

# Constants related to _get_error_message_from_exception
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Constants related to _validate_integer
INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the {} parameter"
NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-negative integer value in the {} parameter"
