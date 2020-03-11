# File: carbonblack_consts.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#


CARBONBLACK_JSON_DEVICE_URL = "device_url"
CARBONBLACK_JSON_API_TOKEN = "api_token"
CARBONBLACK_JSON_HASH = "hash"
CARBONBLACK_JSON_NAME = "name"
CARBONBLACK_JSON_QUERY = "query"
CARBONBLACK_JSON_READONLY = "read_only"
CARBONBLACK_JSON_ALERT_TYPE = "type"
CARBONBLACK_JSON_TOTAL_WATCHLISTS = "total_alerts"
CARBONBLACK_JSON_TOTAL_ENDPOINTS = "total_endpoints"
CARBONBLACK_JSON_NUM_RESULTS = "number_of_results"
CARBONBLACK_JSON_QUERY_TYPE = "type"
CARBONBLACK_JSON_ADDED_WL_ID = "new_watchlist_id"
CARBONBLACK_JSON_RANGE = "range"
CARBONBLACK_JSON_IPS = "ips"
CARBONBLACK_JSON_SENSOR_ID = "sensor_id"
CARBONBLACK_JSON_SESSION_ID = "session_id"
CARBONBLACK_JSON_FILE_DETAILS = "file_details"
CARBONBLACK_JSON_FILE_CB_URL = "cb_url"
CARBONBLACK_JSON_COMMENT = "comment"
CARBONBLACK_JSON_DOWNLOAD = "download"
CARBONBLACK_JSON_PID = "pid"
CARBONBLACK_JSON_PROCESS_NAME = "process_name"
CARBONBLACK_JSON_CB_ID = "carbonblack_process_id"
CARBONBLACK_JSON_VAULT_ID = "vault_id"
CARBONBLACK_JSON_DESTINATION_PATH = "destination"

CARBONBLACK_MSG_MORE_THAN_ONE = "More than one ONLINE system matched the input endpint ip/name."
CARBONBLACK_MSG_MORE_THAN_ONE += "<br>Please specify input params that matches a single ONLINE endpoint.<br>Systems Found:<br>{systems_error}"

CARBONBLACK_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
CARBONBLACK_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
CARBONBLACK_ERR_PROCESS_SEARCH = "Process search failed"
CARBONBLACK_ERR_INVALID_QUERY_TYPE = "Invalid query type, valid types are '{types}'"
CARBONBLACK_ERR_INVALID_RANGE = "Invalid range, please specify in the format of start-end"
CARBONBLACK_SUCC_SYNC_EVENTS = "Successfully synchronized sensor events."
CARBONBLACK_SUCC_QUARANTINE = "Quarantine action succeeded. It might take some time for endpoint to get isolated."
CARBONBLACK_SUCC_UNQUARANTINE = "Unquarantine action succeeded. It might take some time for endpoint to take effect."
CARBONBLACK_SUCC_BLOCK = "Block hash action succeeded. It might take some time for blacklisting to take effect."
CARBONBLACK_SUCC_UNBLOCK = "Unblock hash action succeeded. It might take some time for unblocking to take effect."
CARBONBLACK_MSG_FILE_NOT_FOUND = "File Not Found"
CARBONBLACK_ERR_NO_ENDPOINTS = "Unable to find any endpoints with hostname/IP {0}"
CARBONBLACK_SUCC_RESET_SESSION = "Sensor {session_id} successfully reset"
CARBONBLACK_ERR_RESET_SESSION = "Session {session_id} not found or is in an invalid state to keep alive"

CARBONBLACK_ADDED_WATCHLIST = "Added alert"
CARBONBLACK_ADDING_WATCHLIST = "Adding alert"
CARBONBLACK_DOING_SEARCH = "Doing {query_type} search"
CARBONBLACK_FETCHING_WATCHLIST_INFO = "Fetching watchlist info"
CARBONBLACK_USING_BASE_URL = "Using base url: {base_url}"
CARBONBLACK_RUNNING_QUERY = "Running query"
CARBONBLACK_DISPLAYING_RESULTS_TOTAL = "Displaying {displaying} '{query_type}' results of total {total}"

CARBONBLACK_QUERY_TYPE_BINARY = 'binary'
CARBONBLACK_QUERY_TYPE_PROCESS = 'process'

VALID_QUERY_TYPE = [CARBONBLACK_QUERY_TYPE_BINARY,
                    CARBONBLACK_QUERY_TYPE_PROCESS]

CARBONBLACK_SLEEP_SECS = 5
CARBONBLACK_COMMAND_FAILED = "Command {command} failed with code: {code}, desc: {desc}"
CARBONBLACK_ERR_POLL_TIMEOUT = 'Could not get a connection to a live active session on the endpoint after {max_tries} polls.'
CARBONBLACK_ERR_MULTI_ENDPOINTS = "{num_endpoints} endpoints matched (see results for a list). Please specify an IP/Host Name that uniquely identifies an online endpoint."
CARBONBLACK_ERR_FILE_EXISTS = "File id for sensor already exists. "
CARBONBLACK_ERR_INVALID_INTEGER_VALUE = "Please provide a valid integer sensor_id"
MAX_POLL_TRIES = 10

CARBONBLACK_FINISHED_PROCESSESING = "Finished Processing {0:.0%}"
