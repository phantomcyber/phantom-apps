# File: arcsight_consts.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Json keys
ARCSIGHT_JSON_BASE_URL = "base_url"
ARCSIGHT_JSON_CASE_NAME = "name"
ARCSIGHT_JSON_CASE_ID = "id"
ARCSIGHT_JSON_PARENT_GROUP = "parent_group"
ARCSIGHT_JSON_USERNAME = "username"
ARCSIGHT_JSON_PASSWORD = "password"
ARCSIGHT_JSON_UPDATE_FIELDS = "update_fields"
ARCSIGHT_JSON_QUERY = "query"
ARCSIGHT_JSON_TYPE = "type"
ARCSIGHT_JSON_RANGE = "range"

# Status messages for success or failure
ARCSIGHT_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
ARCSIGHT_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
ARCSIGHT_ERR_API_UNSUPPORTED_METHOD = "Unsupported method"
ARCSIGHT_ERR_UNABLE_TO_PARSE_REPLY = "Unable to parse reply"
ARCSIGHT_ERR_FROM_SERVER = "API failed, Status code: {status}, Message: {message}"
ARCSIGHT_ERR_SERVER_CONNECTION = "Connection failed"

# Progress messages

# Consts
ARCSIGHT_LIST_SERVICES_ENDPOINT = "/www/manager-service/services/listServices"
ARCSIGHT_CASESERVICE_WSDL_ENDPOINT = "/www/manager-service/services/CaseService?wsdl"
ACRSIGHT_LOGIN_ENDPOINT = "/www/core-service/rest/LoginService/login"
ARCSIGHT_CASESERVICE_ENDPOINT = "/www/manager-service/rest/CaseService"
ARCSIGHT_SECURITYEVENTSERVICE_ENDPOINT = "/www/manager-service/rest/SecurityEventService"
ARCSIGHT_RESOURCESERVICE_ENDPOINT = "/www/manager-service/rest/ResourceService"
ARCSIGHT_MANAGERSEARCHSERVICE_ENDPOINT = "/www/manager-service/rest/ManagerSearchService"
ARCSIGHT_GROUPSERVICE_ENDPOINT = "/www/manager-service/rest/GroupService"

ARCSIGHT_DEFAULT_CONTAINER_COUNT = 10
ARCSIGHT_DEFAULT_ARTIFACT_COUNT = 100

ARCSIGHT_64VAL_NOT_FILLED = -9223372036854775808
ARCSIGHT_32VAL_NOT_FILLED = -2147483648
ARCSIGHT_DEFAULT_PARENT_GROUP = "/All Cases/All Cases"
