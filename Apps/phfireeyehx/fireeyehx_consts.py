# --
# File: fireeyehx_consts.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Constants relating to 'get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters."

# Constants relating to 'validate_integer'
FIREEYEHX_VALID_INT_MSG = "Please provide a valid integer value in the {param} parameter"
FIREEYEHX_NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in {param} parameter"
FIREEYEHX_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the {param} parameter"

# Constants relating to error messages
FIREEYEHX_ERR_INVALID_URL = "Error connecting to server. Invalid URL: '{url}'"
FIREEYEHX_ERR_CONNECTION_REFUSED = "Error connecting to server. Connection Refused from the server for '{url}' url."
FIREEYEHX_ERR_INVALID_SCHEMA = "Error connecting to server. No connection adapters were found for '{url}' url."
FIREEYEHX_ERR_CONNECTING_TO_SERVER = "Error connecting to server. Details: {error}"
