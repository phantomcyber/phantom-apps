# File: netskope_consts.py
# Copyright (c) 2018-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

NETSKOPE_CONFIG_SERVER_URL = 'server_url'
NETSKOPE_CONFIG_API_KEY = 'api_key'
NETSKOPE_CONNECTIVITY_ENDPOINT = '/api/v1/clients'
NETSKOPE_QUARANTINE_ENDPOINT = '/api/v1/quarantine'
NETSKOPE_ON_POLL_ENDPOINT = '/api/v1/alerts'
NETSKOPE_EVENTS_ENDPOINT = '/api/v1/events'
NETSKOPE_PARAM_LIST_FILES = 'get-files'
NETSKOPE_PARAM_IP = 'ip'
NETSKOPE_PARAM_START_TIME = 'start_time'
NETSKOPE_PARAM_END_TIME = 'end_time'
NETSKOPE_QUERY_PARAM = 'srcip eq {srcip} or dstip eq {dstip}'
NETSKOPE_INVALID_START_TIME = "Parameter 'start_time' failed validation"
NETSKOPE_INVALID_END_TIME = "Parameter 'end_time' failed validation"
NETSKOPE_INVALID_TIME_RANGE = "Invalid time range. 'end_time' should be greater than 'start_time'"
NETSKOPE_INVALID_TIME = 'Invalid time. Time cannot be negative'
NETSKOPE_VALID_TIME = 'TIme validation successful'
NETSKOPE_CONNECTIVITY_PASS_MSG = 'Test Connectivity Passed'
NETSKOPE_CONNECTIVITY_FAIL_MSG = 'Test Connectivity Failed'
NETSKOPE_CONNECTION_MSG = 'Querying endpoint to verify the credentials provided'
NETSKOPE_ERROR_CONNECTING_SERVER = 'Error while connecting to server'
NETSKOPE_JSON_FILE = 'file'
NETSKOPE_JSON_PROFILE = 'profile'
NETSKOPE_TEST_CONNECTIVITY_LIMIT = 1
NETSKOPE_24_HOUR_GAP = 86400
NETSKOPE_INITIAL_SKIP_VALUE = 0
NETSKOPE_UPDATE_SKIP_VALUE = 5000
NETSKOPE_DEFAULT_LIMIT = 50
