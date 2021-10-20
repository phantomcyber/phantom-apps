# File: crowdstrikeoauthapi_consts.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Json keys specific to the app's input parameters/config and the output result
CROWDSTRIKE_JSON_URL_OAuth = "url"
CROWDSTRIKE_CLIENT_ID = "client_id"
CROWDSTRIKE_CLIENT_SECRET = "client_secret"
CROWDSTRIKE_OAUTH_TOKEN_STRING = "oauth2_token"
CROWDSTRIKE_OAUTH_ACCESS_TOKEN_STRING = "access_token"
CROWDSTRIKE_JSON_COUNT_ONLY = "count_only"
CROWDSTRIKE_GET_PROCESS_DETAIL_FALCON_PROCESS_ID = "falcon_process_id"
CROWDSTRIKE_GET_DEVICE_DETAIL_DEVICE_ID = "id"
CROWDSTRIKE_JSON_ID = "id"
CROWDSTRIKE_RESOLVE_DETECTION_TO_STATE = "state"
PAYLOAD_SECURITY_API_KEY = 'api_key'
CROWDSTRIKE_JSON_IOC = "ioc"
CROWDSTRIKE_GET_PROCESSES_RAN_ON_FALCON_DEVICE_ID = "id"
CROWDSTRIKE_IOCS_EXPIRATION = "expiration"
CROWDSTRIKE_IOCS_POLICY = "policy"
CROWDSTRIKE_IOCS_ACTION = "action"
CROWDSTRIKE_IOCS_TYPE = "type"
CROWDSTRIKE_IOCS_LIMIT = "limit"
CROWDSTRIKE_IOCS_VALUE = "value"
CROWDSTRIKE_IOCS_SORT = "sort"
CROWDSTRIKE_IOCS_METADATA = "metadata"
CROWDSTRIKE_IOCS_SHARE_LEVEL = "share_level"
CROWDSTRIKE_IOCS_SOURCE = "source"
CROWDSTRIKE_IOCS_PLATFORMS = "platforms"
CROWDSTRIKE_IOCS_SEVERITY = "severity"
CROWDSTRIKE_IOCS_HOSTS = "host_groups"
CROWDSTRIKE_IOCS_ALL_HOSTS = "applied_globally"
CROWDSTRIKE_IOCS_TAGS = "tags"
CROWDSTRIKE_IOC_DATE_ADDED = "date_added"
CROWDSTRIKE_IOC_LAST_MODIFIED = "last_modified"
CROWDSTRIKE_IOC_EXPIRATION_DATE = "expiration_date"
CROWDSTRIKE_IOCS_FILENAME = "filename"
CROWDSTRIKE_IOCS_DESCRIPTION = "description"
CROWDSTRIKE_SEARCH_IOCS_TYPE = "indicator_type"
CROWDSTRIKE_SEARCH_IOCS_FROM_EXPIRATION = "from_expiration"
CROWDSTRIKE_SEARCH_IOCS_TO_EXPIRATION = "to_expiration"
CROWDSTRIKE_JSON_LIST_IOC = "indicator_value"
CROWDSTRIKE_POLL_INTERVAL = "detonate_timeout"
CROWDSTRIKE_RESOURCE_ID = "resource_id"

DEFAULT_POLLNOW_EVENTS_COUNT = 2000
DEFAULT_EVENTS_COUNT = 10000
DEFAULT_BLANK_LINES_ALLOWABLE_LIMIT = 50

# Status messages for the app
CROWDSTRIKE_SUCC_CONNECTIVITY_TEST = "Test connectivity passed"
CROWDSTRIKE_ERR_CONNECTIVITY_TEST = "Test connectivity failed"
CROWDSTRIKE_ERR_CONNECTING = "Error connecting to server"
CROWDSTRIKE_ERR_FROM_SERVER = "Error from Server, Status Code: {status}, Message: {message}"
CROWDSTRIKE_ERR_END_TIME_LT_START_TIME = "End time less than start time"
CROWDSTRIKE_INVALID_LIMIT = 'Please provide non-zero positive integer in limit parameter'
CROWDSTRIKE_HTML_ERROR = 'Bad Request - Invalid URL HTTP Error 400. The request URL is invalid'
CROWDSTRIKE_NO_PARAMETER_ERROR = "One of the parameters (device_id or hostname) must be provided"
CROWDSTRIKE_INVALID_INPUT_ERROR = "Please provide valid inputs"
CROWDSTRIKE_INVALID_DEVICE_ID_AND_HOSTNAME_ERROR = "Please provide valid device_id and hostname parameters"
CROWDSTRIKE_INVALID_DEVICE_ID_ERROR = "Please provide valid device_id parameter"
CROWDSTRIKE_INVALID_HOSTNAME_ERROR = "Please provide valid hostname parameter"
CROWDSTRIKE_ERR_UNSUPPORTED_HASH_TYPE = "Unsupported hash type"
CROWDSTRIKE_ERR_API_UNSUPPORTED_METHOD = "Unsupported method"
CROWDSTRIKE_ERR_SERVER_CONNECTION = "Connection failed"
CROWDSTRIKE_ERR_JSON_PARSE = "Unable to parse reply as a Json, raw string reply: '{raw_text}'"
CROWDSTRIKE_ERR_FROM_SERVER = "API failed, Status code: {status}, Detail: {detail}"
CROWDSTRIKE_SUCC_SET_STATUS = "Successfully set status"
CROWDSTRIKE_NO_MORE_FEEDS_AVAILABLE = "No more feeds available"
CROWDSTRIKE_MSG_GETTING_EVENTS = "Getting maximum {max_events} events from id {lower_id} onwards (ids might not be contiguous)"
CROWDSTRIKE_ERR_CONNECTING = "Error connecting to server"
CROWDSTRIKE_ERR_FROM_SERVER = "Error from Server, Status Code: {status}, Message: {message}"
CROWDSTRIKE_USING_BASE_URL = "Using base url: {base_url}"
CROWDSTRIKE_ERR_META_KEY_EMPTY = "Meta key empty or not present"
CROWDSTRIKE_ERR_RESOURCES_KEY_EMPTY = "Resources key empty or not present. Please try after sometime"
CROWDSTRIKE_ERR_DATAFEED_EMPTY = "Datafeed key empty or not present"
CROWDSTRIKE_ERR_SESSION_TOKEN_NOT_FOUND = "Session token, not found"
PAYLOAD_SECURITY_MSG_SUBMITTING_FILE = 'Submitting file/url to Falcon Sandbox'
CROWDSTRIKE_ERR_UNSUPPORTED_HASH_TYPE = "Unsupported hash type"
CROWDSTRIKE_ERR_EVENTS_FETCH = "Error occurred while fetching the DetectionSummaryEvents from the CrowdStrike server datafeed URL stream"
CROWDSTRIKE_LIMIT_VALIDATION_ALLOW_ZERO_MSG = "Please provide zero or a valid positive integer value in the {parameter} parameter"
CROWDSTRIKE_LIMIT_VALIDATION_MSG = "Please provide a valid non-zero positive integer value in the {parameter} parameter"
CROWDSTRIKE_SUCC_GET_ALERT = "Indicator fetched successfully"
CROWDSTRIKE_SUCC_POST_ALERT = "Indicator uploaded successfully"
CROWDSTRIKE_SUCC_DELETE_ALERT = "Indicator deleted successfully"
CROWDSTRIKE_SUCC_UPDATE_ALERT = "Indicator updated successfully"
CROWDSTRIKE_MISSING_PARAMETER_ERROR_MESSAGE = "Please either provide 'resource id' or 'indicator type' and 'indicator value'"
CROWDSTRIKE_MISSING_INDICATOR_VALUE_ERROR_MESSAGE = "Please provide indicator value"
CROWDSTRIKE_MISSING_INDICATOR_TYPE_ERROR_MESSAGE = "Please provide indicator type"
CROWDSTRIKE_COMPLETED = "Completed {0:.0%}"
CROWDSTRIKE_VALIDATE_INTEGER_MESSAGE = "Please provide a valid integer value in the {key} parameter"
CROWDSTRIKE_ERROR_CODE_MESSAGE = "Error code unavailable"
CROWDSTRIKE_ERROR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or action parameters."
CROWDSTRIKE_UNICODE_DAMMIT_TYPE_ERROR_MESSAGE = "Error occurred while connecting to the Crowdstrike server. Please check the asset configuration and|or the action parameters."
CROWDSTRIKE_CODE_MESSAGE = "Error code: 404"
CROWDSTRIKE_STATUS_CODE_MESSAGE = "Status Code: 404"
CROWDSTRIKE_NO_DATA_MESSAGE = "No data found"
CROWDSTRIKE_PULLED_EVENTS_MSG = "Pulled {0} events of type 'DetectionSummaryEvent'"
CROWDSTRIKE_NO_DATA_MSG = "No data, terminating loop"
CROWDSTRIKE_REACHED_CR_LF_COUNT_MSG = "CR/LF received on iteration: {} - terminating loop"
CROWDSTRIKE_RECEIVED_CR_LF_MSG = "CR/LF received on iteration {} - continuing"
CROWDSTRIKE_BLANK_LINES_COUNT_MSG = "Total blank lines count: {}"
CROWDSTRIKE_GOT_EVENTS_MSG = "Got {0} events of type 'DetectionSummaryEvent'"

CROWDSTRIKE_FILTER_REQUEST_STR = '{0}rest/container?page_size=0'\
                                 '&_filter_asset={1}'\
                                 '&_filter_name__contains="{2}"'\
                                 '&_filter_start_time__gte="{3}"'
CROWDSTRIKE_FILTER_GET_IOC = "type:'{}'+value:'{}'"
CROWDSTRIKE_FILTER_GET_CUSTOM_IOC = "(type:'{}' + value:'{}') + (deleted:'true', deleted: 'false')"
CROWDSTRIKE_FILTER_GET_CUSTOM_IOC_RESOURCE_ID = "id:'{}' + (deleted:'true', deleted: 'false')"
# endpoint
CROWDSTRIKE_OAUTH_TOKEN_ENDPOINT = "/oauth2/token"
CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT = "/devices/queries/devices/v1"
CROWDSTRIKE_GET_DEVICE_DETAILS_ENDPOINT = "/devices/entities/devices/v1"
CROWDSTRIKE_GET_DEVICE_SCROLL_ENDPOINT = "/devices/queries/devices-scroll/v1"
CROWDSTRIKE_GET_HOST_GROUP_ID_ENDPOINT = "/devices/queries/host-groups/v1"
CROWDSTRIKE_GET_HOST_GROUP_DETAILS_ENDPOINT = "/devices/entities/host-groups/v1"
CROWDSTRIKE_DEVICE_ACTION_ENDPOINT = "/devices/entities/devices-actions/v2"
CROWDSTRIKE_GROUP_DEVICE_ACTION_ENDPOINT = "/devices/entities/host-group-actions/v1"

CROWDSTRIKE_RTR_SESSION_ENDPOINT = "/real-time-response/entities/sessions/v1"
CROWDSTRIKE_GET_RTR_SESSION_ID_ENDPOINT = "/real-time-response/queries/sessions/v1"
CROWDSTRIKE_GET_RTR_SESSION_DETAILS_ENDPOINT = "/real-time-response/entities/sessions/GET/v1"
CROWDSTRIKE_COMMAND_ACTION_ENDPOINT = "/real-time-response/entities/active-responder-command/v1"
CROWDSTRIKE_RTR_ADMIN_GET_PUT_FILES = "/real-time-response/queries/put-files/v1"
CROWDSTRIKE_RTR_ADMIN_PUT_FILES = "/real-time-response/entities/put-files/v1"
CROWDSTRIKE_ADMIN_COMMAND_ENDPOINT = "/real-time-response/entities/admin-command/v1"
CROWDSTRIKE_RUN_COMMAND_ENDPOINT = "/real-time-response/entities/command/v1"

CROWDSTRIKE_GET_RTR_FILES_ENDPOINT = "/real-time-response/entities/file/v1"
CROWDSTRIKE_GET_EXTRACTED_RTR_FILE_ENDPOINT = "/real-time-response/entities/extracted-file-contents/v1"
CROWDSTRIKE_GET_INDICATOR_ENDPOINT = "/iocs/entities/indicators/v1"
CROWDSTRIKE_GET_DEVICE_COUNT_APIPATH = "/indicators/aggregates/devices-count/v1"
CROWDSTRIKE_GET_CUSTOM_INDICATORS_ENDPOINT = "/iocs/queries/indicators/v1"
CROWDSTRIKE_GET_COMBINED_CUSTOM_INDICATORS_ENDPOINT = "/iocs/combined/indicator/v1"
CROWDSTRIKE_GET_DEVICES_RAN_ON_APIPATH = "/indicators/queries/devices/v1"
CROWDSTRIKE_GET_PROCESSES_RAN_ON_APIPATH = "/indicators/queries/processes/v1"
CROWDSTRIKE_GET_PROCESS_DETAIL_APIPATH = "/processes/entities/processes/v1"
CROWDSTRIKE_RESOLVE_DETECTION_APIPATH = "/detects/entities/detects/v2"
CROWDSTRIKE_LIST_INCIDENTS_ENDPOINT = "/incidents/queries/incidents/v1"
CROWDSTRIKE_LIST_BEHAVIORS_ENDPOINT = "/incidents/queries/behaviors/v1"
CROWDSTRIKE_GET_INCIDENT_DETAILS_ID_ENDPOINT = "/incidents/entities/incidents/GET/v1"
CROWDSTRIKE_GET_INCIDENT_BEHAVIORS_ID_ENDPOINT = "/incidents/entities/behaviors/GET/v1"
CROWDSTRIKE_LIST_CROWDSCORES_ENDPOINT = "/incidents/combined/crowdscores/v1"
CROWDSTRIKE_UPDATE_INCIDENT_ENDPOINT = "/incidents/entities/incident-actions/v1"
CROWDSTRIKE_LIST_USERS_UIDS_ENDPOINT = "/users/queries/user-uuids-by-cid/v1"
CROWDSTRIKE_GET_USER_INFO_ENDPOINT = "/users/entities/users/v1"
CROWDSTRIKE_GET_USER_ROLES_ENDPOINT = "/user-roles/queries/user-role-ids-by-user-uuid/v1"
CROWDSTRIKE_GET_ROLE_ENDPOINT = "/user-roles/entities/user-roles/v1"
CROWDSTRIKE_LIST_USER_ROLES_ENDPOINT = "/user-roles/queries/user-role-ids-by-cid/v1"
CROWDSTRIKE_QUERY_REPORT_ENDPOINT = "/falconx/queries/reports/v1"
CROWDSTRIKE_QUERY_FILE_ENDPOINT = "/falconx/queries/submissions/v1"
CROWDSTRIKE_GET_REPORT_SUMMARY_ENDPOINT = "/falconx/entities/report-summaries/v1"
CROWDSTRIKE_GET_FULL_REPORT_ENDPOINT = "/falconx/entities/reports/v1"
CROWDSTRIKE_DOWNLOAD_REPORT_ENDPOINT = "/falconx/entities/artifacts/v1"
CROWDSTRIKE_UPLOAD_FILE_ENDPOINT = "/samples/entities/samples/v2"
CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT = "/falconx/entities/submissions/v1"

CROWDSTRIKE_BASE_ENDPOINT = "/sensors/entities/datafeed/v2"
CROWDSTRIKE_FALCONX_API_LIMIT = 5000
CROWDSTRIKE_ENVIRONMENT_ID_DICT = {
    'linux ubuntu 16.04, 64-bit': 300,
    'android (static analysis)': 200,
    'windows 10, 64-bit': 160,
    'windows 7, 64-bit': 110,
    'windows 7, 32-bit': 100
}

CROWDSTRIKE_SORT_FOR_CRITERIA_IOC_DICT = {
    CROWDSTRIKE_SEARCH_IOCS_TYPE: 'type',
    CROWDSTRIKE_JSON_LIST_IOC: 'value',
    CROWDSTRIKE_IOCS_ACTION: 'action',
    CROWDSTRIKE_IOCS_SEVERITY: 'severity',
    CROWDSTRIKE_IOC_DATE_ADDED: 'created_on',
    CROWDSTRIKE_IOC_LAST_MODIFIED: 'modified_on'
}

CROWDSTRIKE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

CROWDSTRIKE_DELETE_RESOURCE_NOT_FOUND = 'Failed to delete resource. Resource not found'
CROWDSTRIKE_GET_RESOURCE_NOT_FOUND = 'Indicator not found'
CROWDSTRIKE_MISSING_PARAMETER_ERROR_MESSAGE_DELETE_IOC = 'Please provide at least one of the parameter'
CROWDSTRIKE_VALUE_LIST_ERROR_MESSAGE = "Please enter valid value in '{}' parameter"
CROWDSTRIKE_SORT_CRITERIA_LIST = ["indicator_type.asc", "indicator_value.asc", "action.asc", "severity.asc", "date_added.asc", "last_modified.asc",
"indicator_type.desc", "indicator_value.desc", "action.desc", "severity.desc", "date_added.desc", "last_modified.desc"]
