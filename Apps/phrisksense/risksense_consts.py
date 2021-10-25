# --
# File: risksense_consts.py
#
# Copyright (c) RiskSense, 2020
#
# This unpublished material is proprietary to RiskSense.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of RiskSense.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Define your constants here

RISKSENSE_LIST_CLIENTS_ENDPOINT = "/client"
RISKSENSE_GET_CLIENT_ENDPOINT = "/client/{client_id}"
RISKSENSE_LIST_FILTER_ATTRIBUTES_ENDPOINT = "/client/{client_id}/{asset_type}/filter"
RISKSENSE_LIST_TAGS_ENDPOINT = "/client/{client_id}/tag/search"
RISKSENSE_LIST_USERS_ENDPOINT = "/client/{client_id}/user/search"
RISKSENSE_LIST_HOSTS_ENDPOINT = "/client/{client_id}/host/search"
RISKSENSE_LIST_APPS_ENDPOINT = "/client/{client_id}/application/search"
RISKSENSE_LIST_HOST_FINDINGS_ENDPOINT = "/client/{client_id}/hostFinding/search"
RISKSENSE_LIST_UNIQUE_HOST_FINDINGS_ENDPOINT = "/client/{client_id}/uniqueHostFinding/search"
RISKSENSE_ASSOCIATE_TAG_ENDPOINT = "/client/{client_id}/{asset_type}/tag"
RISKSENSE_SEARCH_ASSET_DATA_ENDPOINT = "/client/{client_id}/{asset_type}/search"
RISKSENSE_CREATE_TAG_ENDPOINT = "/client/{client_id}/tag"

RISKSENSE_PROJECTION_DETAIL = "detail"
RISKSENSE_PROJECTION_BASIC = "basic"
RISKSENSE_DEFAULT_MAX_RESULTS = 1000
RISKSENSE_DEFAULT_PAGE_INDEX = 0
RISKSENSE_DEFAULT_NUM_RETRIES = 2
RISKSENSE_DEFAULT_BACKOFF_FACTOR = 0.3
RISKSENSE_EXCLUSIVITY_DICTIONARY = {
    "true": True,
    "false": False
}

# RiskSense Configuration and Action Parameter Keys
RISKSENSE_ACTION_LIMIT_KEY = "'max results' action"
RISKSENSE_ACTION_PAGE_KEY = "'page' action"
RISKSENSE_ACTION_HOST_ID_KEY = "'host id' action"
RISKSENSE_ACTION_HOST_FINDING_ID_KEY = "'host finding id' action"
RISKSENSE_ACTION_APP_ID_KEY = "'app id' action"
RISKSENSE_CONFIG_NUM_RETRIES_KEY = "'Maximum number of retries to attempt' asset configuration"
RISKSENSE_ACTION_TAG_OWNER_ID_KEY = "'tag owner id' action"

# RiskSense Error Messages
RISKSENSE_INSUFFICIENT_PARAM_GET_HOSTS_MESSAGE = "Please provide either 'host id' or 'host name' to fetch the host details"
RISKSENSE_INSUFFICIENT_PARAM_CREATE_TAG_MESSAGE = "Please provide 'tag type', 'tag description', 'tag owner id', and 'tag colour' action parameters in order to create a new tag"
RISKSENSE_INVALID_STATUS_PARAM_MESSAGE = "Please provide a valid value in status parameter. Valid values are: Closed, Open"
RISKSENSE_INVALID_EXCLUSIVITY_PARAM_MESSAGE = "Please provide valid value in exclusivity parameter. Valid values are: true, false"
RISKSENSE_LENGTH_VALIDATION_ERROR_MESSAGE = "Please provide same length of input in {} parameters"
RISKSENSE_LIMIT_VALIDATION_ALLOW_ZERO_MESSAGE = "Please provide zero or a valid positive integer value in the {parameter} parameter"
RISKSENSE_LIMIT_VALIDATION_MESSAGE = "Please provide a valid non-zero positive integer value in the {parameter} parameter"
RISKSENSE_BACKOFF_FACTOR_VALIDATION_MESSAGE = "Please provide a valid non-zero positive float value in the 'Backoff factor' asset configuration parameter"
RISKSENSE_UNKNOWN_ERROR_CODE_MESSAGE = "Error code unavailable"
RISKSENSE_UNKNOWN_ERROR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or the action parameters."
RISKSENSE_UNICODE_DAMMIT_TYPE_ERROR_MESSAGE = "Error occurred while connecting to the RiskSense server. Please check the asset configuration and|or the action parameters."
