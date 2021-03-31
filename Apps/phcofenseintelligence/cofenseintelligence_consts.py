# File: cofenseintelligence_consts.py
# Copyright (c) 2020-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

PHISHME_API_SEARCH = "https://www.threathq.com/apiv1"
PHISHME_API_THREAT_UPDATE = "/threat/updates"
PHISHME_ENDPOINT = "/threat/search"
PHISHME_ENDPOINT_GET_REPORT_MALWARE = '/threat/malware/'
PHISHME_ERR_API_UNSUPPORTED_METHOD = "Unsupported method {method}"
PHISHME_CONNECTION_TEST_MSG = "Querying endpoint to verify the credentials \
provided"
PHISHME_CONNECTION_TEST_ERR_MSG = "Test Connectivity Failed"
PHISHME_CONNECTION_TEST_SUCC_MSG = "Test Connectivity Passed"
PHISHME_ERR_SERVER_CONNECTION = "Connection failed"
PHISHME_LOGIN_ERROR = "API Username or API Password not configured"
PHISHME_ERR_JSON_PARSE = 'Unable to parse the fields parameter into a \
dictionary. \n    Response text - {raw_text}'
PHISHME_ERR_FROM_SERVER = "API failed\nStatus code: {status}\nDetail: \
{detail}"
PHISHME_CONFIG_API_USERNAME = "username"
PHISHME_CONFIG_API_PASSWORD = "password"
PHISHME_CONFIG_POLL_NOW_DAYS = "poll_now_ingestion_span"
PHISHME_CONFIG_INGEST = "first_scheduled_ingestion_span"
PHISHME_JSON_FILE = "hash"
PHISHME_JSON_URL = "url"
PHISHME_JSON_IP = "ip"
PHISHME_JSON_DOMAIN = "domain"
PHISHME_JSON_RESOURCE_NOT_FOUND = "resource_not_found"
PHISHME_JSON_MAX_THREAT_COUNT = "max_threat_count"
PHISHME_THREAT_COUNT_ERROR = "Maximum threats to be fetched must be greater than 0"
PHISHME_DEFAULT_POLL_NOW_CONTAINER_COUNT = 5
PHISHME_DEFAULT_POLL_NOW_SPAN_DAYS = 15
PHISHME_DEFAULT_FIRST_INGEST_SPAN_DAYS = 10
PHISHME_DEFAULT_MAX_THREAT_COUNT = 100
PHISHME_REST_RESP_SUCCESS = 200
PHISHME_REST_RESP_SYNTAX_INCORRECT = 400
PHISHME_REST_RESP_SYNTAX_INCORRECT_MSG = 'Bad request due to malformed syntax'
PHISHME_REST_RESP_FAILED_AUTHORIZATION = 401
PHISHME_REST_RESP_FAILED_AUTHORIZATION_MSG = 'Failed to authorize'
PHISHME_REST_RESP_SERVER_ERROR = 500
PHISHME_REST_RESP_SERVER_ERROR_MSG = 'Server Error'
PHISHME_REST_RESP_SERVER_UNREACHABLE = 503
PHISHME_REST_RESP_SERVER_UNREACHABLE_MSG = 'Service Temporarily Unavailable'
PHISHME_REST_RESP_RESOURCE_NOT_FOUND = 404
PHISHME_REST_RESP_RESOURCE_NOT_FOUND_MSG = 'Data not available'
PHISHME_REST_RESP_OTHER_ERROR_MSG = "Unknown Error occurred"
PHISHME_CONTAINER_DESC = "Details for threat id: {0}"
PHISHME_CONTAINER_ERROR = "Error while creating container"
PHISHME_ARTIFACTS_DESC = "Artifact created by Cofense Intelligence app"
PHISHME_ARTIFACTS_ERROR = "Error while creating artifact"
PHISHME_THREAT_DATA_ERROR = "Error while getting details for threat ID {id}. Response message: {message}"
PHISHME_INVALID_LIMIT_MSG = "Please provide a non-zero positive integer in the poll_now_ingestion_span and first_scheduled_ingestion_span parameters."
