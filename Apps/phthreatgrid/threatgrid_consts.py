# File: threatgrid_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


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

SUBMIT_FILE = '{base_uri}/api/v2/samples'
TEST_CONNECTIVITY_URL = '{base_uri}/api/v2/samples?api_key={api_key}&limit=1'
RESULTS_URL = '{base_uri}/samples/{task_id}'
STATUS_URL = '{base_uri}/api/v2/samples/{task_id}?api_key={api_key}'
ANALYSIS_URL = '{base_uri}/api/v2/samples/{task_id}/analysis.json?api_key={api_key}'
HTML_REPORT_URL = '{base_uri}/api/v2/samples/{task_id}/report.html?api_key={api_key}'
THREAT_URL = '{base_uri}/api/v2/samples/{task_id}/threat?api_key={api_key}'
HASH_SEARCH_URL = '{base_uri}/api/v2/samples/search?api_key={api_key}&checksum={hash}'
PLAYBOOKS_URL = '{base_uri}/api/v3/configuration/playbooks?api_key={api_key}'
SEARCH_REPORT_URL = '{base_uri}/api/v2/search/submissions?api_key={api_key}&limit={limit}'
INVALID_INT = "Please provide a valid integer value in the {param}"
ERR_NEGATIVE_INT_PARAM = "Please provide a valid non-negative integer value in the {param}"
NON_ZERO_ERROR = "Please provide non-zero positive integer in {param}"
DEFAULT_LIMIT = 100
THREATGRID_VAULT_ERROR = "Could not find meta information of the downloaded report's Vault"

THREATGRID_ERROR_CODE_UNAVAILABLE = 'Error code unavailable'
THREATGRID_ERROR_MESSAGE_UNAVAILABLE = 'Error message unavailable. Please check the asset configuration and|or action parameters'
THREATGRID_TEST_CONNECTIVITY_FAILED = 'Test Connectivity Failed'
THREATGRID_TEST_CONNECTIVITY_PASSED = 'Test Connectivity Passed'
THREATGRID_UNSPECIFIED_ERROR = 'Unspecified Error'
THREATGRID_FILE_NOT_FOUND_ERROR = 'File not found in vault ("{}")'
THREATGRID_REST_CALL_ERROR = 'Error making rest call to server. Details: {0}'
THREATGRID_API_KEY_REPLACE_MSG = '<api_key_value_provided_in_config_params>'
THREATGRID_SUCC_RET_REPORT = 'Number of results retrieved: {}'
