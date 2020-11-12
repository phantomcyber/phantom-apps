# File: slashnextphishingincidentresponse_consts.py
# Copyright (c) 2019-2020 SlashNext Inc. (www.slashnext.com)
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Define your constants here
BASE_API = 'https://oti.slashnext.cloud/api'
HOST_REPUTE_API = '/oti/v1/host/reputation'
URL_REPUTE_API = '/oti/v1/url/reputation'
URL_SCAN_API = '/oti/v1/url/scan'
URL_SCANSYNC_API = '/oti/v1/url/scansync'
HOST_REPORT_API = '/oti/v1/host/report'
DL_SC_API = '/oti/v1/download/screenshot'
DL_HTML_API = '/oti/v1/download/html'
DL_TEXT_API = '/oti/v1/download/text'
API_QUOTA = '/oti/v1/quota/status'

# Constants relating to '_get_error_message_from_exception'

ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the SlashNext Server. Please check the asset configuration and|or the action parameters"

# Constants relating to '_validate_integer'

INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the {}"
INVALID_NON_NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-negative integer value in the {}"

LIMIT_KEY = "'limit' action parameter"
TIMEOUT_KEY = "'timeout' action parameter"
