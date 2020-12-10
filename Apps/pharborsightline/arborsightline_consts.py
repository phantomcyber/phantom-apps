# File: arborsightline_consts.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
ARBORSIGHTLINE_GET_ALERTS_FAILED_MSG = 'An error occurred during alerts retrieval'
ARBORSIGHTLINE_GET_ALERTS_PROGRESS_MSG = 'Fetching next {alerts_no} alerts from page {page_no}'
ARBORSIGHTLINE_GET_ALERTS_OK = 'Fetched {total} alerts'
ARBORSIGHTLINE_GET_ALERTS_EMPTY_MSG = 'No alerts found'
ARBORSIGHTLINE_CREATE_CONTAINER_FAILED_MSG = 'Container creation failed: {msg}'
ARBORSIGHTLINE_PARSE_ALERTS_FAILED_MSG = 'An error occurred while parsing alerts data'
ARBORSIGHTLINE_GET_ALERTS_PAGINATION_FAILED_MSG = 'An error occurred while fetching alerts using pagination'
ARBORSIGHTLINE_GENERIC_ERROR_MSG = 'Please check the asset configuration and|or action parameters.'
ARBORSIGHTLINE_ALERTS_DATA_KEY_UNAVAILABLE_MSG = 'The key "data" is unavailable in the alerts API response.'
ARBORSIGHTLINE_CREATE_ARTIFACT_FAILED_MSG = 'Artifact creation failed: {msg}'

ARBORSIGHTLINE_API_URL = '/api/sp/'
ARBORSIGHTLINE_GET_ALERTS_ENDPOINT = ARBORSIGHTLINE_API_URL + 'alerts/'
ARBORSIGHTLINE_GET_ALERTS_FILTER = '/data/attributes/alert_type = dos_host_detection AND /data/attributes/start_time > {time}'
