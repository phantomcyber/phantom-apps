# File: windowsdefenderatp_consts.py
#
# Copyright (c) 2019-2021 Splunk Inc.
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
DEFENDERATP_PHANTOM_BASE_URL = '{phantom_base_url}rest'
DEFENDERATP_PHANTOM_SYS_INFO_URL = '/system_info'
DEFENDERATP_PHANTOM_ASSET_INFO_URL = '/asset/{asset_id}'
DEFENDERATP_LOGIN_BASE_URL = 'https://login.microsoftonline.com'
DEFENDERATP_SERVER_TOKEN_URL = '/{tenant_id}/oauth2/token'
DEFENDERATP_AUTHORIZE_URL = '/{tenant_id}/oauth2/authorize?client_id={client_id}&redirect_uri={redirect_uri}' \
                            '&response_type={response_type}&state={state}&resource={resource}'
DEFENDERATP_RESOURCE_URL = 'https://api.securitycenter.windows.com'
DEFENDERATP_MSGRAPH_API_BASE_URL = 'https://api.securitycenter.windows.com/api'
DEFENDERATP_MACHINES_ENDPOINT = '/machines'
DEFENDERATP_DOMAIN_MACHINES_ENDPOINT = '/domains/{input}/machines'
DEFENDERATP_FILE_MACHINES_ENDPOINT = '/files/{input}/machines'
DEFENDERATP_ALERTS_ENDPOINT = '/alerts'
DEFENDERATP_EXPOSURE_ENDPOINT = '/exposureScore'
DEFENDERATP_SECURE_ENDPOINT = '/configurationScore'
DEFENDERATP_ALERTS_ID_ENDPOINT = '/alerts/{input}'
DEFENDERATP_IP_ALERTS_ENDPOINT = '/ips/{input}/alerts'
DEFENDERATP_DOMAIN_ALERTS_ENDPOINT = '/domains/{input}/alerts'
DEFENDERATP_FILE_ALERTS_ENDPOINT = '/files/{input}/alerts'
DEFENDERATP_ISOLATE_ENDPOINT = '/machines/{device_id}/isolate'
DEFENDERATP_UNISOLATE_ENDPOINT = '/machines/{device_id}/unisolate'
DEFENDERATP_SESSIONS_ENDPOINT = '/machines/{device_id}/logonusers'
DEFENDERATP_FILE_QUARANTINE_ENDPOINT = '/machines/{device_id}/StopAndQuarantineFile'
DEFENDERATP_MACHINEACTIONS_ENDPOINT = '/machineactions/{action_id}'
DEFENDERATP_SCAN_DEVICE_ENDPOINT = '/machines/{device_id}/runAntiVirusScan'
DEFENDERATP_UNBLOCK_HASH_ENDPOINT = '/files/{file_hash}/unblock'
DEFENDERATP_FILE_BLOCK_ENDPOINT = '/files/{file_hash}/block'
DEFENDERATP_FILE_INFO_ENDPOINT = '/files/{file_hash}'
DEFENDERATP_MACHINE_FILES_ENDPOINT = '/files/{file_hash}/machines'
DEFENDERATP_USER_FILES_ENDPOINT = '/users/{file_hash}/machines'
DEFENDERATP_VULNERABILITIES_ENDPOINT = '/machines/{device_id}/vulnerabilities'
DEFENDERATP_INSTALLED_SOFTWARE_ENDPOINT = '/machines/{device_id}/software'
DEFENDERATP_RESTRICT_APP_EXECUTION_ENDPOINT = '/machines/{device_id}/restrictCodeExecution'
DEFENDERATP_REMOVE_APP_RESTRICTION_ENDPOINT = '/machines/{device_id}/unrestrictCodeExecution'
DEFENDERATP_DOMAIN_PREVALENCE_ENDPOINT = '/domains/{domain}/stats'
DEFENDERATP_IP_PREVALENCE_ENDPOINT = '/ips/{ip}/stats'
DEFENDERATP_FILE_PREVALENCE_ENDPOINT = '/files/{id}/stats'
DEFENDERATP_LIST_INDICATORS_ENDPOINT = '/indicators'
DEFENDERATP_RUN_QUERY_ENDPOINT = '/advancedqueries/run'
DEFENDERATP_LIVE_RESPONSE_ENDPOINT = '/machines/{device_id}/runliveresponse'
DEFENDERATP_LIVE_RESPONSE_RESULT_ENDPOINT = '/machineactions/{action_id}/GetLiveResponseResultDownloadLink(index=0)'
DEFENDERATP_MISSING_KBS_ENDPOINT = '/machines/{device_id}/getmissingkbs'
DEFENDERATP_IP_PARAM_CONST = "ip"
DEFENDERATP_DOMAIN_PARAM_CONST = "domain"
DEFENDERATP_FILE_PARAM_CONST = "file_hash"
DEFENDERATP_LOOK_BACK_HOURS_PARAM_CONST = "look_back_hours"
DEFENDERATP_NO_DATA_FOUND = "No data found"
DEFENDERATP_INVALID_LOOK_BACK_HOURS = "Invalid look_back_hours parameter was given, must be greater than zero and lower or equal to 720."
DEFENDERATP_TOKEN_EXPIRED = 'Status Code: 401'
DEFENDERATP_TOKEN_NOT_AVAILABLE_MSG = 'Token not available. Please run test connectivity first'
DEFENDERATP_BASE_URL_NOT_FOUND_MSG = 'Phantom Base URL not found in System Settings. ' \
                                     'Please specify this value in System Settings'
DEFENDERATP_TEST_CONNECTIVITY_FAILED_MSG = 'Test connectivity failed'
DEFENDERATP_TEST_CONNECTIVITY_PASSED_MSG = 'Test connectivity passed'
DEFENDERATP_AUTHORIZE_USER_MSG = 'Please authorize user in a separate tab using URL'
DEFENDERATP_CODE_RECEIVED_MSG = 'Code Received'
DEFENDERATP_MAKING_CONNECTION_MSG = 'Making Connection...'
DEFENDERATP_OAUTH_URL_MSG = 'Using OAuth URL:'
DEFENDERATP_GENERATING_ACCESS_TOKEN_MSG = 'Generating access token'
DEFENDERATP_ALERTS_INFO_MSG = 'Getting info about alerts'
DEFENDERATP_RECEIVED_ALERT_INFO_MSG = 'Received alert info'
DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG = 'Action ID not available. Please try again after sometime'
DEFENDERATP_FILE_HASH_UNBLOCKED_SUCCESS_MSG = 'File hash unblocked successfully'
DEFENDERATP_PARAM_VALIDATION_FAILED_MSG = 'Parameter validation failed. Invalid {}'
DEFENDERATP_INPUT_REQUIRED_MSG = 'Input is required for the given type'
DEFENDERATP_CONFIG_TENANT_ID = 'tenant_id'
DEFENDERATP_CONFIG_CLIENT_ID = 'client_id'
DEFENDERATP_CONFIG_CLIENT_SECRET = 'client_secret'
DEFENDERATP_ALL_CONST = 'All'
DEFENDERATP_IP_CONST = 'IP'
DEFENDERATP_DOMAIN_CONST = 'Domain'
DEFENDERATP_FILE_HASH_CONST = 'File Hash'
DEFENDERATP_JSON_LIMIT = 'limit'
DEFENDERATP_JSON_TIMEOUT = 'timeout'
DEFENDERATP_JSON_INPUT = 'input'
DEFENDERATP_JSON_QUERY = 'query'
DEFENDERATP_JSON_DEVICE_ID = 'device_id'
DEFENDERATP_JSON_SCAN_TYPE = 'scan_type'
DEFENDERATP_JSON_COMMENT = 'comment'
DEFENDERATP_JSON_FILE_HASH = 'file_hash'
DEFENDERATP_JSON_FILE_NAME = 'file_name'
DEFENDERATP_JSON_SCRIPT_NAME = 'script_name'
DEFENDERATP_JSON_SCRIPT_ARGS = 'script_args'
DEFENDERATP_JSON_USER_ID = 'user_id'
DEFENDERATP_JSON_STATUS = 'status'
DEFENDERATP_JSON_ASSIGNED_TO = 'assigned_to'
DEFENDERATP_JSON_CLASSIFICATION = 'classification'
DEFENDERATP_JSON_DETERMINATION = 'determination'
DEFENDERATP_JSON_TYPE = 'type'
DEFENDERATP_JSON_FILE_PATH = 'file_path'
DEFENDERATP_EVENT_ID = 'event_id'
DEFENDERATP_ALERT_ID = 'alert_id'
DEFENDERATP_JSON_INPUT_TYPE = 'input_type'
DEFENDERATP_STATUS_PROGRESS = 'InProgress'
DEFENDERATP_STATUS_PENDING = 'Pending'
DEFENDERATP_STATUS_SUCCESS = 'Succeeded'
DEFENDERATP_STATUS_FAILED = 'Failed'
DEFENDERATP_TOKEN_STRING = 'token'
DEFENDERATP_ACCESS_TOKEN_STRING = 'access_token'
DEFENDERATP_REFRESH_TOKEN_STRING = 'refresh_token'
DEFENDERATP_CLIENT_CREDENTIALS_STRING = 'client_credentials'
DEFENDERATP_TC_FILE = 'oauth_task.out'
DEFENDERATP_GET_FILE_COMMAND = 'GetFile'
DEFENDERATP_PUT_FILE_COMMAND = 'PutFile'
DEFENDERATP_RUN_SCRIPT_COMMAND = 'RunScript'
DEFENDERATP_STATUS_CHECK_DEFAULT = 30
DEFENDERATP_STATUS_CHECK_SLEEP = 5
DEFENDERATP_TC_STATUS_SLEEP = 3
DEFENDERATP_AUTHORIZE_WAIT_TIME = 15
DEFENDERATP_ALERT_DEFAULT_LIMIT = 100
DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT = 60
DEFENDERATP_SCAN_TIMEOUT_MAX_LIMIT = 3600
DEFENDERATP_LIVE_RESPONSE_DEFAULT = 300
DEFENDERATP_RUN_SCRIPT_MAX_LIMIT = 600
DEFENDERATP_MAX_LOOK_BACK_HOURS = 720

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Windows Defender ATP Server. Please check the asset configuration and|or the action parameters"

# Constants relating to '_validate_integer'
VALID_INTEGER_MSG = "Please provide a valid integer value in the {}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-zero positive integer value in the {}"
POSITIVE_INTEGER_MSG = "Please provide non-zero positive integer in {}"
LOOK_BACK_HOURS_KEY = "'look_back_hours' action parameter"
TIMEOUT_KEY = "'timeout' action parameter"
LIMIT_KEY = "'limit' action parameter"

# Constants relating to value_list check
INPUT_TYPE_VALUE_LIST_ALERTS = ["All", "Domain", "File Hash", "IP"]
TYPE_VALUE_LIST = ["Full", "Selective"]
SCAN_TYPE_VALUE_LIST = ["Quick", "Full"]
INPUT_TYPE_VALUE_LIST_DEVICES = ["All", "Domain", "File Hash"]
INDICATOR_SEVERITY_LIST = ["", "Informational", "Low", "Medium", "High", None]

# Constants relating to 'Indicators'
DEFENDERATP_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DEFENDERATP_JSON_FILTER = 'filter'
DEFENDERATP_JSON_ACTION = 'action'
DEFENDERATP_JSON_SEVERITY = 'severity'
DEFENDERATP_JSON_APPLICATION = 'application'
DEFENDERATP_JSON_EXPIRATION_TIME = 'expiration_time'
DEFENDERATP_JSON_INDICATOR_ID = 'indicator_id'
DEFENDERATP_JSON_INDICATOR_TITLE = 'title'
DEFENDERATP_JSON_INDICATOR_DESCRIPTION = 'description'
DEFENDERATP_JSON_INDICATOR_TYPE = 'indicator_type'
DEFENDERATP_JSON_INDICATOR_VALUE = 'indicator_value'
DEFENDERATP_JSON_RECOMMENDED_ACTIONS = 'recommended_actions'
DEFENDERATP_JSON_RBAC_GROUP_NAMES = 'rbac_group_names'
DEFENDERATP_PAST_TIME_ERR = 'Invalid {0}, can not be lesser than or equal to current UTC time.'
DEFENDERATP_INVALID_TIME_ERR = 'Invalid {0}, supports ISO date format only. e.g. 2019-10-17T00:00:00Z.'
DEFENDERATP_INVALID_RBAC_GROUP_NAMES = 'Please provide valid comma-separated RBAC group names.'
DEFENDERATP_INVALID_INDICATOR_TYPE = 'Please provide a valid "indicator type" value. Possible indicator types are "FileSha1", "FileSha256", "IpAddress", "DomainName", "Url".'
DEFENDERATP_INVALID_ACTION = 'Please provide a valid "action" value. Possible action values are "Alert", "AlertAndBlock", "Allowed".'
DEFENDERATP_INVALID_SEVERITY = 'Please provide a valid "severity" value. Possible severity values are "Informational", "Low", "Medium", "High".'
DEFENDERATP_SUBMIT_INDICATOR_PARSE_ERR = 'Submitted indicator but not able to parse the response'
DEFENDERATP_SUBMIT_INDICATOR_ID_PARSE_ERR = 'Submitted indicator but not able to parse the Indicator ID'
DEFENDERATP_INVALID_LIST_JSON_ERR = "Please provide valid JSON formatted list in the '{0}' parameter."
DEFENDERATP_INVALID_EVENT_ID_ERR = "Event id status: '{0}'. The status of event_id must be 'Succeeded' in order to execute the action"
DEFENDERATP_INVALID_COMMAND_ERR = "The given event_id does not corrospond to {0} command"
DEFENDERATP_REQUIRED_PARAMETER_ERR = "Please provide either event_id or ({0}, device_id and comment)"
