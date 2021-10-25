# File: threatgrid_consts.py
#
# Copyright (c) 2016-2021 Splunk Inc.
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
THREATGRID_DONE_STATES = ('succ', 'fail')
RESULT_STATUS_KEY = 'status'
RESULT_REPORT_KEY = 'report'
THREAT_KEY = 'threat'
TARGET_KEY = 'target'
TASK_ID_KEY = 'id'
RESULTS_URL_KEY = 'results_url'
RESPONSE_DATA_KEY = 'data'
RESPONSE_ERROR_KEY = 'error'
RESPONSE_ERRORS_KEY = 'errors'
RESPONSE_ERROR_CODE_KEY = 'code'
RESPONSE_ERROR_MSG_KEY = 'message'
RESPONSE_STATE_KEY = 'state'

POLL_SLEEP_SECS = 60

THREATGRID_ERROR_CODE_UNAVAILABLE = 'Error code unavailable'
THREATGRID_ERROR_MESSAGE_UNAVAILABLE = 'Error message unavailable. Please check the asset configuration and|or action parameters'
THREATGRID_TEST_CONNECTIVITY_FAILED = 'Test Connectivity Failed'
THREATGRID_TEST_CONNECTIVITY_PASSED = 'Test Connectivity Passed'
THREATGRID_UNSPECIFIED_ERROR = 'Unspecified Error'
THREATGRID_FILE_NOT_FOUND_ERROR = 'File not found in vault ("{}")'
THREATGRID_REST_CALL_ERROR = 'Error making rest call to server. Details: {0}'
THREATGRID_API_KEY_REPLACE_MSG = '<api_key_value_provided_in_config_params>'
