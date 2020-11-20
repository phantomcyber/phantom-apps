# File: ironnet_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
# Constants relating to '_validate_integer'
VALID_INTEGER_MSG = "Please provide a valid integer value in the {}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {}"
MIN_SEVERITY_KEY = "'min_severity' action parameter"
MAX_SEVERITY_KEY = "'max_severity' action parameter"
ALERT_SEVERITY_LOWER_KEY = "'alert_severity_lower' configuration parameter"
ALERT_SEVERITY_UPPER_KEY = "'alert_severity_upper' configuration parameter"
ALERT_LIMIT_KEY = "'alert_limit' configuration parameter"
DOME_LIMIT_KEY = "'dome_limit' configuration parameter"
EVENT_SEVERITY_LOWER_KEY = "'event_severity_lower' configuration parameter"
EVENT_SEVERITY_UPPER_KEY = "'event_severity_upper' configuration parameter"
EVENT_LIMIT_KEY = "'event_limit' configuration parameter"

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Ironnet Server. Please check the asset configuration and|or the action parameters"
