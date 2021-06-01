# File: code42_consts.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

CODE42_CONFIG_USERNAME = 'username'
CODE42_CONFIG_PASSWORD = 'password'
CODE42_CONFIG_SERVER_URL = 'server_url'
CODE42_AUTH_TOKEN_ENDPOINT = '/api/AuthToken'
CODE42_ENVIRONMENT_ENDPOINT = '/api/ServerEnv'
CODE42_USERS_ENDPOINT = '/api/Users'
CODE42_GET_USER_INFO_ENDPOINT = '/api/Users/{userId}'
CODE42_USER_DEACTIVATION_ENDPOINT = '/api/UserDeactivation/{userId}'
CODE42_DEVICES_ENDPOINT = '/api/Computer'
CODE42_BLOCK_DEVICE_ENDPOINT = '/api/ComputerBlock/{device_id}'
CODE42_DEACTIVATE_DEVICE_ENDPOINT = '/api/ComputerDeactivation/{device_id}'
CODE42_DEAUTHORIZE_DEVICE_ENDPOINT = '/api/ComputerDeauthorization/{device_id}'
CODE42_LIST_ORGANIZATIONS_ENDPOINT = '/api/Org'
CODE42_CHANGE_ORGANIZATION_ENDPOINT = '/api/UserMoveProcess'
CODE42_CHECK_RESTORE_STATUS_ENDPOINT = '/api/RestoreRecord/{restore_id}'
CODE42_PUSH_RESTORE_JOB_ENDPOINT = '/api/PushRestoreJob'
CODE42_WEB_RESTORE_SESSION_ENDPOINT = '/api/WebRestoreSession'
CODE42_DATA_KEY_TOKEN_ENDPOINT = '/api/DataKeyToken'
CODE42_V3_TOKEN_AUTH_ENDPOINT = '/c42api/v3/auth/jwt?useBody=true'
CODE42_ACCESS_LOCK_ENDPOINT = '/c42api/v3/AccessLock'
CODE42_ORGANIZATION_INFO_ENDPOINT = '/c42api/v3/customer/my'
CODE42_DEPARTING_EMPLOYEE_ENDPOINT = '/svc/api/v1/departingemployee/create'
CODE42_FORENSIC_SEARCH_ENDPOINT = '/forensic-search/queryservice/api/v1/fileevent'
CODE42_CREATE_DETECTION_LIST_PROFILE_ENDPOINT = '/svc/api/v2/user/create'
CODE42_DEPARTING_EMPLOYEE_V2_ENDPOINT = '/svc/api/v2/departingemployee/add'
CODE42_GET_PROFILE_BY_USERNAME = '/svc/api/v2/user/getbyusername'
CODE42_UPDATE_CLOUD_USERNAMES = '/svc/api/v2/user/addcloudusernames'
CODE42_UPDATE_NOTES = '/svc/api/v2/user/updatenotes'
CODE42_JSON_DEVICE_ID = 'device_id'
CODE42_JSON_DATA = 'data'
CODE42_JSON_USER = 'user'
CODE42_JSON_ORG = 'organization'
CODE42_JSON_BLOCK_USER = 'block_user'
CODE42_JSON_UNBLOCK_USER = 'unblock_user'
CODE42_JSON_FILE_HASH = 'file_hash'
CODE42_JSON_START_TIME = 'start_time'
CODE42_JSON_END_TIME = 'end_time'
CODE42_JSON_FILE_NAME = 'file_name'
CODE42_JSON_FILE_PATH = 'file_path'
CODE42_JSON_FILE_EVENT = 'file_event'
CODE42_JSON_HOST_NAME = 'hostname'
CODE42_JSON_PUBLIC_IP = 'public_ip'
CODE42_JSON_PRIVATE_IP = 'private_ip'
CODE42_JSON_QUERY = 'query'
CODE42_MAX_RESULTS = 'max_results'
CODE42_JSON_RESTORE_ID = 'restore_id'
CODE42_JSON_WEB_RESTORE_SESSION_ID = "web_restore_session_id"
MAX_RESULTS_KEY = "max_results"
CODE42_TIMEOUT = 30
CODE42_PAGINATION = 1
CODE42_DEFAULT_PAGE_SIZE = 100
CODE42_INVALID_DEVICE_ID_MSG = "Invalid value for parameter 'device_id'"
CODE42_INVALID_USER_ID_MSG = "Provided value of parameter 'user' is either invalid or not exist"
CODE42_INVALID_DEPARTING_USER_MSG = "Provided value of parameter 'departing_user' is either invalid or not exist"
CODE42_INVALID_ORG_ID_MSG = "Provided value of parameter 'organization' is either invalid or not exist"
CODE42_START_TIME_END_TIME_REQUIRED = "Parameters 'start_time' and 'end_time are required when parameter 'query' is " \
                                      "not provided"
CODE42_INVALID_START_TIME_MSG = "Invalid value for parameter 'start_time'"
CODE42_INVALID_END_TIME_MSG = "Invalid value for parameter 'end_time'"
CODE42_INVALID_TIME_RANGE = "Invalid time range. 'end_time' should be greater than 'start_time'."
CODE42_USER_NOT_FOUND_MSG = "No user found with username {user_name}"
CODE42_USER_DEACTIVATION_ID_SUCCESS_MSG = 'User with ID {user} deactivated successfully'
CODE42_USER_DEACTIVATION_USERNAME_SUCCESS_MSG = 'User named {user} deactivated successfully'
CODE42_USER_ACTIVATION_ID_SUCCESS_MSG = 'User with ID {user} activated successfully'
CODE42_USER_ACTIVATION_USERNAME_SUCCESS_MSG = 'User named {user} activated successfully'
CODE42_DEVICE_BLOCKED_SUCCESS_MSG = 'Device with ID {device_id} blocked successfully'
CODE42_DEVICE_UNBLOCKED_SUCCESS_MSG = 'Device with ID {device_id} unblocked successfully'
CODE42_DEVICE_DEACTIVATED_SUCCESS_MSG = 'Device with ID {device_id} deactivated successfully'
CODE42_DEVICE_ACTIVATED_SUCCESS_MSG = 'Device with ID {device_id} activated successfully'
CODE42_DEVICE_DEAUTHORIZED_SUCCESS_MSG = 'Device with ID {device_id} deauthorized successfully'
CODE42_CHANGE_ORGANIZATION_USERID_ORGID_SUCCESS_MSG = 'User with ID {user} moved to organization with ID {org} ' \
                                                      'successfully'
CODE42_CHANGE_ORGANIZATION_USERID_ORGNAME_SUCCESS_MSG = 'User with ID {user} moved to organization named {org} ' \
                                                        'successfully'
CODE42_CHANGE_ORGANIZATION_USERNAME_ORGID_SUCCESS_MSG = 'User named {user} moved to organization with ID {org} ' \
                                                        'successfully'
CODE42_CHANGE_ORGANIZATION_USERNAME_ORGNAME_SUCCESS_MSG = 'User named {user} moved to organization named {org} ' \
                                                          'successfully'
CODE42_LOCK_SUCCESS_MSG = 'Device with ID {device_id} locked successfully'
CODE42_USER_ALREADY_ACTIVATED_MSG = 'The user is already Active'
CODE42_USER_ALREADY_DEACTIVATED_MSG = 'The user is already Deactivated'
CODE42_DEVICE_ALREADY_ACTIVATED_MSG = 'The device is already Active'
CODE42_DEVICE_ALREADY_DEACTIVATED_MSG = 'The device is already Deactivated'
CODE42_DEVICE_ALREADY_BLOCKED_MSG = 'The device is already Blocked'
CODE42_DEVICE_ALREADY_UNBLOCKED_MSG = 'The device is already Unblocked'
CODE42_DEVICE_ALREADY_DEAUTHORIZED_MSG = 'The device is already Deauthorized'
CODE42_LOCK_ALREADY_ENABLED_MSG = 'The device is already under access lock'
CODE42_LOCK_ALREADY_DISABLED_MSG = 'The device is already removed from access lock'
CODE42_ORG_ALREADY_SET_MSG = 'The user is already under this organization'
CODE42_CONNECTION_MSG = 'Querying endpoint to verify the credentials provided'
CODE42_TOKEN_SUCCESS_MSG = 'Token generated'
CODE42_TEST_CONNECTIVITY_FAILED_MSG = 'Test connectivity failed'
CODE42_TEST_CONNECTIVITY_PASSED_MSG = 'Test connectivity passed'
CODE42_DEVICE_TOKEN_GENERATION_FAILED = 'Failed to generate DataKeyToken. See error message for details'
CODE42_RESTORE_SESSION_CREATION_FAILED = 'Failed to create WebRestoreSession. See error message for details'
CODE42_RESTORE_NO_PATHS_SUPPLIED = 'Either \"files\" or \"directories\" parameters must be supplied! Please fill at least one of these parameters and execute the action again'
CODE42_FILE_EVENT_INVALID = "Please provide a valid 'file_event' parameter"
CODE42_CONNECTION_FAILED = "Unable to connect to server"

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Code42 Server. Please check the asset configuration and|or the action parameters"

# Constants for _validate_integer method
CODE42_ERR_INVALID_INTEGER_VALUE = 'Please provide a valid {msg} integer value in the "{param}" action parameter'

# value list for file_event parameter in run query action
FILE_EVENT_LIST = [
                    "New file",
                    "Modified",
                    "No longer observed"
                ]
