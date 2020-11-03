# File: proofpoint_consts.py
# Copyright (c) 2017-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

PP_API_BASE_URL = "https://tap-api-v2.proofpoint.com"
PP_API_PATH_CLICKS_BLOCKED = "/v2/siem/clicks/blocked"
PP_API_PATH_CLICKS_PERMITTED = "/v2/siem/clicks/permitted"
PP_API_PATH_MESSAGES_BLOCKED = "/v2/siem/messages/blocked"
PP_API_PATH_MESSAGES_DELIVERED = "/v2/siem/messages/delivered"
PP_API_PATH_ISSUES = "/v2/siem/issues"
PP_API_PATH_ALL = "/v2/siem/all"
PP_API_PATH_CAMPAIGN = "/v2/campaign/{}"
PP_API_PATH_FORENSICS = "/v2/forensics"
PP_API_PATH_DECODE = "/v2/url/decode"

# Constants relating to 'get_error_message_from_exception'
ERROR_CODE_MSG = "Error code unavailable"
ERROR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Proofpoint TAP Server. Please check the asset configuration and|or action parameters."
ERROR_MSG_FORMAT_WITH_CODE = "Error Code: {}. Error Message: {}"
ERROR_MSG_FORMAT_WITHOUT_CODE = "Error Message: {}"


# Constants relating to 'validate_integer'
INVALID_INTEGER_ERROR_MSG = "Please provide a valid integer value in the {}"
INVALID_NON_NEGATIVE_INTEGER_ERROR_MSG = "Please provide a valid non-negative integer value in the {}"
INITIAL_INGESTION_WINDOW_KEY = "'initial_ingestion_window' configuration parameter"

# Constant relating to 'handle_py_ver_compat_for_input_str'
PY_2TO3_ERROR_MSG = "Error occurred while handling python 2to3 compatibility for the input string"

# Constant relating to fetching the python major version
ERROR_FETCHING_PYTHON_VERSION = "Error occurred while fetching the Phantom server's Python major version"

# Constants relating to error messages while processing response from server
EMPTY_RESPONSE_MSG = "Status code: {}. Empty response and no information in the header"
HTML_RESPONSE_PARSE_ERROR_MSG = "Cannot parse error details"
JSON_PARSE_ERROR_MSG = 'Unable to parse JSON response. Error: {}'
SERVER_ERROR_MSG = 'Error from server. Status Code: {} Data from server: {}'
SERVER_ERROR_CANT_PROCESS_RESPONSE_MSG = "Can't process response from server. Status Code: {} Data from server: {}"
CONNECTION_REFUSED_ERROR_MSG = "Error Details: Connection Refused from the Server"
SERVER_CONNECTION_ERROR_MSG = "Error Connecting to server. Details: {}"
