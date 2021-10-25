# File: cuckoo_consts.py
#
# Copyright (c) 2014-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
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
