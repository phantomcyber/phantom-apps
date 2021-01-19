# --
# File: cuckoo_consts.py
#
# Copyright (c) 2014-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
# Define your constants here

POLL_SLEEP_SECS = 10
CUCKOO_POLL_STATES = ('pending', 'running', 'completed')
CUCKOO_DONE_STATES = ('reported')
RESULT_STATUS_KEY = 'task_status'
RESULT_REPORT_KEY = 'report'
RESULTS_URL_KEY = 'results_url'
TASK_ID_KEY = 'id'
TARGET_KEY = 'target'
RESPONSE_TASK_KEY = 'task'
RESPONSE_STATUS_KEY = 'status'

# Integer validation constants
VALID_INTEGER_MSG = "Please provide a valid integer value in the {key}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {key}"
TIMEOUT_KEY = "'timeout' configuration parameter"

# Error message handling constants
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
