# --
# File: chronicle_consts.py
#
# Copyright (c) 2020-2021 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# --

# Chronicle search endpoints
GC_LIST_IOC_DETAILS_ENDPOINT = '/v1/artifact/listiocdetails'
GC_LIST_ASSETS_ENDPOINT = '/v1/artifact/listassets'
GC_LIST_EVENTS_ENDPOINT = '/v1/asset/listevents'
GC_LIST_IOCS_ENDPOINT = '/v1/ioc/listiocs'
GC_LIST_ALERTS_ENDPOINT = '/v1/alert/listalerts'

# Chronicle Detection Engine endpoints
GC_LIST_RULES_ENDPOINT = '/v2/detect/rules'
GC_LIST_DETECTIONS_ENDPOINT = '/v2/detect/rules/{rule_id}/detections'

# Regex pattern
GC_TIME_RANGE_PATTERN = r"^[1-9]\d*(d|h|m|s)$"
GC_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

# Ingestion run mode constants
GC_IOC_RUN_MODE_KEY = "IoC Domain Matches"
GC_ALERT_RUN_MODE_KEY = "Assets with Alerts"
GC_USER_ALERT_RUN_MODE_KEY = "User Alerts"
GC_ALERTING_DETECTION_RUN_MODE_KEY = "Alerting Detections"
GC_NOT_ALERTING_DETECTION_RUN_MODE_KEY = "Not-alerting Detections"

# Contains for the different artifact keys
GC_URL_CONTAINS = ["url"]
GC_TIME_VALUE_CONTAINS = ["gc time"]
GC_ARTIFACT_VALUE_CONTAINS = ["domain"]
GC_ASSET_VALUE_CONTAINS = ["gc mac", "gc product id", "hostname", "ip"]
GC_USER_VALUE_CONTAINS = ["gc username", "email"]
GC_RULE_ID_CONTAINS = ["gc rule id"]

# Constants for Alert Type Action Parameter
GC_ASSET_ALERTS_MODE = ["Asset Alerts", "All"]
GC_USER_ALERTS_MODE = ["User Alerts", "All"]

# Run Mode constants for the On-Poll action
GC_RM_IOC_DOMAINS = "ioc"
GC_RM_ASSET_ALERTS = "alert"
GC_RM_USER_ALERTS = "user_alert"
GC_RM_ALERTING_DETECTIONS = "alerting_detection"
GC_RM_NOT_ALERTING_DETECTIONS = "not_alerting_detection"
# Time related constant for the On Poll action

GC_RM_ON_POLL_DICT = {
    GC_IOC_RUN_MODE_KEY: [GC_RM_IOC_DOMAINS],
    GC_ALERT_RUN_MODE_KEY: [GC_RM_ASSET_ALERTS],
    GC_USER_ALERT_RUN_MODE_KEY: [GC_RM_USER_ALERTS],
    "All Alerts": [GC_RM_ASSET_ALERTS, GC_RM_USER_ALERTS],
    GC_ALERTING_DETECTION_RUN_MODE_KEY: [GC_RM_ALERTING_DETECTIONS],
    GC_NOT_ALERTING_DETECTION_RUN_MODE_KEY: [GC_RM_NOT_ALERTING_DETECTIONS],
    "All Detections": [GC_RM_ALERTING_DETECTIONS, GC_RM_NOT_ALERTING_DETECTIONS],
    "All": [GC_RM_IOC_DOMAINS, GC_RM_ASSET_ALERTS, GC_RM_USER_ALERTS, GC_RM_ALERTING_DETECTIONS, GC_RM_NOT_ALERTING_DETECTIONS]
}
# Define your constants here
GC_SCOPE_KEY = 'scopes'
GC_LIMIT_KEY = 'limit'
GC_KEY_JSON_KEY = 'key_json'
GC_BASE_URL_KEY = 'base_url'
GC_WAIT_TIMEOUT_PERIOD_KEY = 'wait_timeout_period'
GC_NO_OF_RETRIES_KEY = 'no_of_retries'
GC_START_TIME_KEY = 'start_time'
GC_END_TIME_KEY = 'end_time'
GC_REFERENCE_TIME_KEY = 'reference_time'
GC_RULE_IDS_KEY = 'rule_ids'
GC_TIME_RANGE_KEY = 'time_range'
GC_ALERT_STATE_KEY = 'alert_state'
GC_ALERT_TYPE_KEY = 'alert_type'
GC_DEFAULT_DETECTION_TYPE = 'RULE_DETECTION'
GC_CONFIG_WAIT_TIMEOUT_PERIOD_KEY = "'Retry Wait Period(in seconds)' asset configuration"
GC_CONFIG_NO_OF_RETRIES_KEY = "'Number Of Retries' asset configuration"
GC_CONFIG_KEY_DICT_KEY = "'Contents of service account JSON file' asset configuration"
GC_CONFIG_SCOPE_KEY = "'Chronicle API Scope' asset configuration"
GC_CONFIG_MALICIOUS_CATEGORY = "'Malicious Categories for Reputation' asset configuration"
GC_CONFIG_MALICIOUS_SEVERITY = "'Malicious Severity for Reputation' asset configuration"
GC_CONFIG_MALICIOUS_STR_CONFIDENCE = "'Malicious Str Confidence Score for Reputation' asset configuration"
GC_CONFIG_MALICIOUS_INT_CONFIDENCE = "'Malicious Int Confidence Score Range for Reputation' asset configuration"
GC_CONFIG_SUSPICIOUS_CATEGORY = "'Suspicious Categories for Reputation' asset configuration"
GC_CONFIG_SUSPICIOUS_SEVERITY = "'Suspicious Severity for Reputation' asset configuration"
GC_CONFIG_SUSPICIOUS_STR_CONFIDENCE = "'Suspicious Str Confidence Score for Reputation' asset configuration"
GC_CONFIG_SUSPICIOUS_INT_CONFIDENCE = "'Suspicious Int Confidence Score Range for Reputation' asset configuration"
GC_CONFIG_ALERT_SEVERITY = "'Alert Severity to Ingest Alerts' asset configuration"
GC_CONFIG_MAX_ARTIFACTS = "'Max allowed artifacts in a single container' asset configuration"
GC_CONFIG_MAX_LIMIT_POLL_NOW = "'Max results for POLL NOW' asset configuration"
GC_CONFIG_MAX_LIMIT_POLL = "'Max results for scheduled/interval POLL' asset configuration"
GC_CONFIG_TIME_POLL_NOW = "'Time range for POLL NOW' or 'Start time for the scheduled/interval POLL' asset configuration parameter"
GC_CONFIG_TIME_RANGE_POLL_NOW = "'Time range for POLL NOW' asset configuration parameter"

GC_DEFAULT_WAIT_TIMEOUT_PERIOD = 3
GC_NUMBER_OF_RETRIES = 3
GC_DEFAULT_PAGE_SIZE = 10000

# Errors
GC_TECHNICAL_ERROR = 'Technical Error while making an API call to Chronicle. Empty response received'
GC_RESPONSE_ERROR = 'Retrieved unknown response while making an API call to Chronicle. Unknown response received'

GC_UNABLE_CREATE_CLIENT_ERR = "Unable to create Chronicle API client"
GC_PARSE_TIME_PARAM_ERROR = "Error occured while parsing time parameters"
GC_INTERNAL_SERVER_ERROR = 'Internal server error occurred, please try again later'
GC_INVALID_RESPONSE_FORMAT = 'Invalid response format while making an API call to Chronicle. Response not in JSON format.'
GC_RATE_LIMIT_EXCEEDED = 'API rate limit exceeded. Please try after sometime.'
GC_INVALID_ERR_RESPONSE_FORMAT = 'Invalid error response received from Chronicle. Error response not in JSON format.'
GC_LIMIT_VALIDATION_ALLOW_ZERO_MSG = "Please provide zero or positive integer value in the {parameter} parameter."
GC_LIMIT_VALIDATION_MSG = "Please provide a valid non-zero positive integer value in the {parameter} parameter."
GC_TIME_RANGE_VALIDATION_MSG = "Please provide valid 'Time range' value in the action parameters. Format: <digit><d/h/m/s> e.g. 3d (three days)"
GC_UTC_SINCE_TIME_ERROR = "Please provide time in the span of UTC time since Unix epoch 1970-01-01T00:00:00Z."
GC_INVALID_TIME_ERR = 'Invalid {0}, supports ISO date format only. e.g. 2019-10-17T00:00:00Z.'
GC_GREATER_TIME_ERR = 'Invalid {0}, can not be greater than current UTC time.'
GC_GREATER_EQUAL_TIME_ERR = 'Invalid {0}, can not be greater than or equal to current UTC time'
GC_INVALID_TIME_PERIOD = 'Invalid time period. End time must be later than Start time.'
GC_INVALID_LIST_JSON_ERR = "Please provide valid JSON formatted list in '{0}' parameter(s)."
GC_INVALID_DICT_JSON_ERR = "Please provide valid JSON formatted dictionary in {0} parameter."
GC_JSON_ERROR = "Unable to load the json for {0} parameter. {1}"
GC_TIME_PARAM_ERROR = "Please provide proper time related parameters for the search. You can provide time period either in the time range action parameter or "
GC_TIME_PARAM_ERROR += "in the start time and end time action parameters according to available action parameters."
GC_INT_RANGE_CONFIDENCE_ERROR = "Please provide exactly 2 positive integer values as comma-separated string in '{0}' parameter(s)."
GC_ON_POLL_INVALID_TIME_ERROR = "Please provide valid time related parameters "
GC_ON_POLL_INVALID_TIME_ERROR += "('Time range for POLL NOW' or 'Start time for the scheduled/interval POLL') for the ingestion action."
GC_STATE_FILE_CORRUPT_ERROR = "Error occurred while loading the state file due to its unexpected format. Resetting the state file with the default format. Please try again."
GC_INVALID_RULE_IDS_MSG = "Provided Rule ID(s) are invalid. Please provide valid Rule ID(s)"
