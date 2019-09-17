# File: sumologic_consts.py
# Copyright (c) 2016-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

SUMOLOGIC_JSON_QUERY = "query"
SUMOLOGIC_JSON_ENVIRONMENT = "environment"
SUMOLOGIC_JSON_ACCESS_ID = "access_id"
SUMOLOGIC_JSON_ACCESS_KEY = "access_key"
SUMOLOGIC_JSON_FROM_TIME = "from_time"
SUMOLOGIC_JSON_TO_TIME = "to_time"
SUMOLOGIC_JSON_TIMEZONE = "timezone"
SUMOLOGIC_JSON_LIMIT = "limit"
SUMOLOGIC_JSON_TYPE = "type"
SUMOLOGIC_JSON_JOB_ID = "search_id"
SUMOLOGIC_JSON_COLLECTOR_ID = "collector_id"
SUMOLOGIC_JSON_NAME = "name"
SUMOLOGIC_JSON_DESCRIPTION = "description"
SUMOLOGIC_JSON_CATEGORY = "category"
SUMOLOGIC_US1_API_ENDPOINT = "https://api.sumologic.com/api/v1"
SUMOLOGIC_COLLECTOR_ENDPOINT = "https://collectors.sumologic.com"
SUMOLOGIC_OTHER_API_ENDPOINT = "https://api.{environment}.sumologic.com/api/v1"

SUMOLOGIC_ERR_CONNECTION_FAILED = "Connection to the SumoLogic API has failed."

SUMOLOGIC_PROG_CREATING_SEARCH_JOB = "Creating search job..."
SUMOLOGIC_PROG_POLLING_JOB = "Polling job for success..."
SUMOLOGIC_POLLING_TIME_LIMIT = 60
SUMOLOGIC_JSON_DEFAULT_RESPONSE_LIMIT = 100
SUMOLOGIC_JSON_DEFAULT_RESPONSE_TYPE = "messages"
SUMOLOGIC_JSON_DEFAULT_COLLECTOR_LIMIT = 1000
MILLISECONDS = 100
SUMOLOGIC_FIVE_DAYS_IN_SECONDS = 432000
