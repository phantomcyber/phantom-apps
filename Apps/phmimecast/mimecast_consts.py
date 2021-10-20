# --
# File: mimecast_consts.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

MIMECAST_ERR_EMPTY_RESPONSE = "Status Code {code}. Empty response and no information in the header"
MIMECAST_UNABLE_TO_PARSE_ERR_DETAILS = "Cannot parse error details"
MIMECAST_ERR_UNABLE_TO_PARSE_JSON_RESPONSE = "Unable to parse response as JSON. {error}"
MIMECAST_ERR_INVALID_INT = "Please provide a valid integer value in the '{key}' parameter"
MIMECAST_ERR_NEGATIVE_AND_ZERO_INT = "Please provide a valid non-zero positive integer value in the '{key}' parameter"
MIMECAST_ERR_NEGATIVE_INT = "Please provide a valid non-negative integer value in the '{key}' parameter"
DEFAULT_MAX_RESULTS = 100
MIMECAST_ERR_CODE_UNAVAILABLE = "Error code unavailable"
MIMECAST_ERR_MSG_UNKNOWN = "Unknown error occurred. Please check the asset configuration and|or action parameters"
MIMECAST_PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
MIMECAST_ERR_CONNECTING_SERVER = "Error Connecting to the Mimecast server. Details: {error}"
MIMECAST_ERR_TEST_CONN_FAILED = "Test Connectivity Failed"
MIMECAST_SUCC_TEST_CONN_PASSED = "Test Connectivity Passed"
MIMECAST_ERR_PROCESSING_RESPONSE = "Error occurred while processing the response from the server"
MIMECAST_SUCC_REMOVE_MEMBER = "Successfully removed member from group"
MIMECAST_SUCC_ADD_MEMBER = "Successfully added member to group"
MIMECAST_SUCC_ALLOW_URL = "Successfully added URL to the allowlist"
MIMECAST_SUCC_REMOVE_URL = "Successfully removed URL from URL Protection List"
MIMECAST_SUCC_BLOCK_URL = "Successfully added URL to the blocklist"
MIMECAST_ERR_TYPE_ACTION_PARAMETER = "Please provide a valid value in the 'type' action parameter"
MIMECAST_ERR_TIMESTAMP_INVALID = "'{key}' timestamp format should be YYYY-MM-DDTHH:MM:SS+0000. Error: {error}"
MIMECAST_SUCC_GET_EMAIL = "Successfully retrieved message information"
MIMECAST_SUCC_DECODE_URL = "Successfully decoded URL"
MIMECAST_ERR_ENCODING_SECRET_KEY = "Error occurred while encoding secret key. Please provide a valid secret key value."
MIMECAST_ERR_BYPASS_AUTH = "Please provide Mimecast 'Secret Key' and 'Access Key' for Bypass Authentication"
MIMECAST_STATE_FILE_CORRUPT_ERR = "Error occurred while loading the state file due to its unexpected format. Resetting the state file with the default format. Please try again"
