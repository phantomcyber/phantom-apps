# File: rsasa_consts.py
#
# Copyright (c) 2017-2021 Splunk Inc.
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
RSASA_JSON_URL = "url"
RSASA_JSON_USERNAME = "username"
RSASA_JSON_PASSWORD = "password"
RSASA_JSON_LAST_DATE_TIME = "last_date_time"
RSASA_JSON_INCIDENT_MANAGER = "incident_manager"
RSASA_JSON_EXTRACT_COMPONENTS = "extract_components"
RSASA_JSON_POLL_NOW_DAYS = "poll_now_ingestion_span"
RSASA_JSON_VERIFY_SERVER_CERT = "verify_server_cert"
RSASA_JSON_SCHEDULED_POLL_DAYS = "first_scheduled_ingestion_span"

RSASA_ERR_SERVER_CONNECTION = "Connection failed"
RSASA_ERR_NO_DEVICES = "Found no devices on RSA SA"
RSASA_ERR_TEST_CONNECTIVITY = "Test connectivity failed"
RSASA_ERR_NO_ID = "Could not find specified device ID/name"
RSASA_ERR_JSON_PARSE = "Unable to parse reply, raw string reply: '{raw_text}'"
RSASA_REST_CALL_FAIL = "Call to server failed with error code: {0}, message: {1}"

RSASA_DEFAULT_PAGE_SIZE = 100
RSASA_DEFAULT_ALERT_LIMIT = 100
RSASA_DEFAULT_EVENT_LIMIT = 100
RSASA_DEFAULT_CONTAINER_COUNT = 100
RSASA_DEFAULT_INCIDENT_LIMIT = 1000
RSASA_DEFAULT_START_TIME = 100000000000

RSASA_NO_INCIDENTS = "No incidents to ingest"
