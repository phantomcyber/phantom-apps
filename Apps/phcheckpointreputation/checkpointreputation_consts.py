# File: checkpointreputation_consts.py
# Copyright (c) 2016-2021 Mathieu A. Cormier
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

API_BASE_URL = "https://rep.checkpoint.com"
API_ENDPOINT_AUTH = "/rep-auth/service/v1.0/request"
API_ENDPOINT_IP = "/ip-rep/service/v2.0/query"
API_ENDPOINT_URL = "/url-rep/service/v2.0/query"
API_ENDPOINT_FILE = "/file-rep/service/v2.0/query"

CONFIG_API_KEY = "api_key"

STATE_TOKEN = "token"

ACTION_PARAM_RESOURCE = "resource"
ACTION_PARAM_RESOURCE_TEST = "google.com"

ACTION_ID_IP = "ip_reputation"
ACTION_ID_URL = "url_reputation"
ACTION_ID_FILE = "file_reputation"
ACTION_ID_TEST = "test_connectivity"

REST_CALL_FAILURE = "REST call failed"

RESPONSE = "response"
RESPONSE_STATUS = "status"
RESPONSE_STATUS_LABEL = "label"
RESPONSE_STATUS_LABEL_SUCCESSES = ["SUCCESS", "PARTIAL_SUCCESS"]
RESPONSE_STATUS_LABEL_ERROR = "FAILED"

RESPONSE_STATUS_MESSAGE = "message"
RESPONSE_STATUS_MESSAGE_DEFAULT = "No message"
RESPONSE_STATUS_MESSAGE_SUCCESS = "Risk: {risk}, Classification: {classification}, Confidence: {confidence}"

RESPONSE_RISK = "risk"
RESPONSE_REPUTATION = "reputation"

ERROR_HTTP = "Rest call returned an HTTP error: {response}"
ERROR_JSON = "Failed to decode JSON response: {response}"
ERROR_TIMEOUT = "Rest call timed out. Try again later."
ERROR_OTHER = "Unknown error"
