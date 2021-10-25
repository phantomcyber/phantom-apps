# File: symantecatp_consts.py
#
# Copyright (c) 2017-2019 Splunk Inc.
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
SYMANTEC_CONFIG_SERVER = "server"
SYMANTEC_CONFIG_CLIENT_ID = "client_id"
SYMANTEC_CONFIG_CLIENT_SECRET = "client_secret"
SYMANTEC_CONFIG_SERVER_CERT = "verify_server_cert"
SYMANTEC_CONFIG_POLL_NOW_INGESTION_LIMIT = "poll_now_ingestion_limit"
SYMANTEC_CONFIG_POLL_NOW_INGESTION_SPAN = "poll_now_ingestion_span"
SYMANTEC_CONFIG_FIRST_SCHEDULED_INGESTION_SPAN = "first_scheduled_ingestion_span"
SYMANTEC_CONFIG_FIRST_SCHEDULED_INGESTION_LIMIT = "first_scheduled_ingestion_limit"
SYMANTEC_TOKEN_ENDPOINT = "/atpapi/oauth2/tokens"
SYMANTEC_GET_INCIDENTS = "/atpapi/v1/incidents"
SYMANTEC_GET_EVENTS = "/atpapi/v1/incidentevents"
SYMANTEC_HUNT_FILE = "/atpapi/v1/files/{0}?hash_type={1}"
SYMANTEC_CONNECTION_TEST_ERR_MSG = "Connectivity test failed"
SYMANTEC_CONNECTION_TEST_INVALID_URL_MSG = "Device URL configured: {url}"
SYMANTEC_CONNECTION_TEST_SUCC_MSG = "Connectivity test succeeded"
SYMANTEC_CONNECTION_TEST_MSG = "Querying endpoint to verify the credentials \
provided"
SYMANTEC_SUCCESS_API_CODE = 200
SYMANTEC_BAD_REQUEST_ERROR_CODE = 400
SYMANTEC_BAD_REQUEST_ERROR_MSG = "Client provided bad data to the Server. The Server did nothing with it."
SYMANTEC_FORBIDDEN_ERROR_CODE = 403
SYMANTEC_FORBIDDEN_ERROR_MSG = "Request rejected because user administrator has blocked access."
SYMANTEC_NOT_FOUND_ERROR_CODE = 404
SYMANTEC_NOT_FOUND_ERROR_MSG = "Client referenced a nonexistent resource or collection. The Server did nothing."
SYMANTEC_REQUEST_TIMEOUT_ERROR_CODE = 408
SYMANTEC_REQUEST_TIMEOUT_ERROR_MSG = "Request timed-out."
SYMANTEC_INTERNAL_SERVER_ERROR_ERROR_CODE = 500
SYMANTEC_INTERNAL_SERVER_ERROR_ERROR_MSG = "Server encountered an error. The consumer has no knowledge if the request \
was successful."
SYMANTEC_REQUEST_TOO_LARGE_ERROR_CODE = 413
SYMANTEC_REQUEST_TOO_LARGE_ERROR_MSG = 'List of target is too long.'
SYMANTEC_ERR_SERVER_CONNECTION = "Connection failed"
SYMANTEC_ERR_FROM_SERVER = "API failed\nStatus code: {status}\nDetail: \
{detail}"
SYMANTEC_REST_RESP_OTHER_ERROR_MSG = "Unknown error occurred"
SYMANTEC_ERR_JSON_PARSE = 'Unable to parse the fields parameter into a \
dictionary. \n    Response text - {raw_text}'
SYMANTEC_DEFAULT_POLL_NOW_CONTAINER_COUNT = 20
SYMANTEC_DEFAULT_POLL_NOW_DAYS = 10
SYMANTEC_DEFAULT_FIRST_SCHEDULED_CONTAINER_COUNT = 20
SYMANTEC_DEFAULT_FIRST_SCHEDULED_DAYS = 10
SYMANTEC_CONTAINER_ERROR = "Error while creating container"
SYMANTEC_ARTIFACTS_DESC = "Artifact created by Symantec ATP app"
SYMANTEC_ARTIFACTS_ERROR = "Error while creating artifact"
SYMANTEC_QUARANTINE_ENDPOINT = '/atpapi/v1/commands'
SYMANTEC_COMMAND_ENDPOINT = '/atpapi/v1/commands/'
SYMANTEC_QUARANTINE_RESPONSE_COMMAND_ID = 'command_id: {command_id}'
SYMANTEC_MAX_LIMIT = 1000
SYMANTEC_MAX_SPAN_DAYS = 30
SYMANTEC_NO_INCIDENTS_FOUND_MSG = "No incidents found"
