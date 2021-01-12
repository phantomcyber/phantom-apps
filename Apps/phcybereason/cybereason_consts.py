# File: cybereason_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

PHANTOM_TO_CYBEREASON_STATUS = {
    'Unread': "UNREAD",
    'To Review': "TODO",
    'Not Relevant': "FP",
    'Remediated': "CLOSE",
    'Reopend': "REOPEN",
    'Under Investigation': "OPEN"
}
CUSTOM_REPUTATION_LIST = ["whitelist", "blacklist", "remove"]

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Constants relating to '_validate_integer'
INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the {}"
INVALID_NON_NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-negative integer value in the {}"

MALOP_HISTORICAL_DAYS_KEY = "malop_historical_days asset configuration parameter"
MALWARE_HISTORICAL_DAYS_KEY = "malware_historical_days asset configuration parameter"
