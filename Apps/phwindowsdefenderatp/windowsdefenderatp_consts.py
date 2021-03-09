# File: windowsdefenderatp_consts.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

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
DEFENDERATP_TOKEN_EXPIRED = 'Status Code: 401. Error: Empty response and no information in the header'
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
DEFENDERATP_JSON_TYPE = 'type'
DEFENDERATP_EVENT_ID = 'event_id'
DEFENDERATP_JSON_INPUT_TYPE = 'input_type'
DEFENDERATP_STATUS_PROGRESS = 'InProgress'
DEFENDERATP_TOKEN_STRING = 'token'
DEFENDERATP_ACCESS_TOKEN_STRING = 'access_token'
DEFENDERATP_REFRESH_TOKEN_STRING = 'refresh_token'
DEFENDERATP_CLIENT_CREDENTIALS_STRING = 'client_credentials'
DEFENDERATP_TC_FILE = 'oauth_task.out'
DEFENDERATP_STATUS_CHECK_DEFAULT = 30
DEFENDERATP_STATUS_CHECK_SLEEP = 5
DEFENDERATP_TC_STATUS_SLEEP = 3
DEFENDERATP_AUTHORIZE_WAIT_TIME = 15
DEFENDERATP_ALERT_DEFAULT_LIMIT = 100
DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT = 60
DEFENDERATP_SCAN_TIMEOUT_MAX_LIMIT = 3600

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Windows Defender ATP Server. Please check the asset configuration and|or the action parameters"

# Constants relating to '_validate_integer'
VALID_INTEGER_MSG = "Please provide a valid integer value in the {}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-zero positive integer value in the {}"
TIMEOUT_KEY = "'timeout' action parameter"
LIMIT_KEY = "'limit' action parameter"

# Constants relating to value_list check
INPUT_TYPE_VALUE_LIST_ALERTS = ["All", "Domain", "File Hash", "IP"]
TYPE_VALUE_LIST = ["Full", "Selective"]
SCAN_TYPE_VALUE_LIST = ["Quick", "Full"]
INPUT_TYPE_VALUE_LIST_DEVICES = ["All", "Domain", "File Hash"]
