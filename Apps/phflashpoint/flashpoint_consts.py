# --
# File: flashpoint_consts.py
#
# Copyright (c) Flashpoint, 2020
#
# This unpublished material is proprietary to Flashpoint.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Flashpoint.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Define your constants here

FLASHPOINT_X_FP_INTEGRATION_PLATFORM = "Phantom"

# Flashpoint endpoints
FLASHPOINT_SIMPLIFIED_INDICATORS_ENDPOINT = "/indicators/simple"
FLASHPOINT_ALL_SEARCH_ENDPOINT = "/all/search"
FLASHPOINT_SIMPLIFIED_INDICATORS_SCROLL_ENDPOINT = "/indicators/scroll"
FLASHPOINT_ALL_SEARCH_SCROLL_ENDPOINT = "/all/scroll"
FLASHPOINT_LIST_REPORTS_ENDPOINT = "/reports"
FLASHPOINT_GET_REPORT_ENDPOINT = "/reports/{report_id}"
FLASHPOINT_LIST_RELATED_REPORTS_ENDPOINT = "/reports/{report_id}/related"

FLASHPOINT_PER_PAGE_DEFAULT_LIMIT = 500
FLASHPOINT_DEFAULT_WAIT_TIMEOUT_PERIOD = 5
FLASHPOINT_NUMBER_OF_RETRIES = 1
FLASHPOINT_SESSION_TIMEOUT = 2

# Validate Integers key constants
FLASHPOINT_CONFIG_WAIT_TIMEOUT_PERIOD_KEY = "'Retry Wait Period(in seconds)' asset configuration"
FLASHPOINT_CONFIG_NO_OF_RETRIES_KEY = "'Number Of Retries' asset configuration"
FLASHPOINT_CONFIG_SESSION_TIMEOUT_KEY = "'Session Timeout(in minutes)' asset configuration"
FLASHPOINT_ACTION_LIMIT_KEY = "'limit' action"

# Error message constants
FLASHPOINT_ERROR_VALID_INT_MESSAGE = "Please provide a valid integer value in the {parameter} parameter"
FLASHPOINT_LIMIT_VALIDATION_ALLOW_ZERO_MESSAGE = "Please provide zero or positive integer value in the {parameter} parameter"
FLASHPOINT_LIMIT_VALIDATION_MESSAGE = "Please provide a valid non-zero positive integer value in the {parameter} parameter"
FLASHPOINT_ALREADY_DISABLE_SESSION_SCROLL_ERROR_MESSAGE = "Status code: 404"
FLASHPOINT_ERROR_CODE_MESSAGE = "Error code unavailable"
FLASHPOINT_UNKNOWN_ERROR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or the action parameters."
FLASHPOINT_INVALID_COMMA_SEPARATED_LIST_ERROR = "Please provide valid comma-separated list of attribute types"
FLASHPOINT_UNICODE_DAMMIT_TYPE_ERROR_MESSAGE = "Error occurred while connecting to the Flashpoint server. Please check the asset configuration and|or the action parameters."
FLASHPOINT_ERROR_SESSION_TIMEOUT_VALUE = "Please provide session timeout value between 1 and 60."
