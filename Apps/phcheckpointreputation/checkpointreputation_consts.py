# File: checkpointreputation_consts.py
#
# Copyright (c) 2021 Splunk Inc.
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
#
#
# Endpoints
API_BASE_URL = "https://rep.checkpoint.com"
API_ENDPOINT_AUTH = "/rep-auth/service/v1.0/request"
API_ENDPOINT_IP = "/ip-rep/service/v2.0/query"
API_ENDPOINT_URL = "/url-rep/service/v2.0/query"
API_ENDPOINT_FILE = "/file-rep/service/v2.0/query"

CONFIG_API_KEY = "api_key"

STATE_TOKEN = "token"

ACTION_PARAM_RESOURCE = "resource"
ACTION_PARAM_RESOURCE_TEST = "google.com"

# Action names
ACTION_ID_IP = "ip_reputation"
ACTION_ID_URL = "url_reputation"
ACTION_ID_FILE = "file_reputation"
ACTION_ID_TEST = "test_connectivity"

RESPONSE = "response"
RESPONSE_STATUS = "status"
RESPONSE_STATUS_LABEL = "label"
RESPONSE_STATUS_LABEL_SUCCESSES = ["SUCCESS", "PARTIAL_SUCCESS"]
RESPONSE_STATUS_LABEL_ERROR = "FAILED"

RESPONSE_STATUS_MESSAGE = "message"
RESPONSE_STATUS_MESSAGE_DEFAULT = "No message"
RESPONSE_STATUS_MESSAGE_SUCCESS = "Risk: {risk}, Classification: {classification}, Confidence: {confidence}"

RESPONSE_REPUTATION = "reputation"

# Error messages
ERROR_HTTP = "Rest call returned an HTTP error: {response}"
ERROR_JSON = "Failed to decode JSON response"
ERROR_TIMEOUT = "Rest call timed out. Please try again later"
ERROR_OTHER = "Unknown error"
ERROR_CODE_MSG = "Error code unavailable"
ERROR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERROR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
