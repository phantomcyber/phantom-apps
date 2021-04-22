# File: googlecloudiam_consts.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Define your constants here
IAM_SERVICE_NAME = 'iam'
IAM_SERVICE_VERSION = 'v1'

ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
API_CLIENT_ERR_MSG = "Could not create API client"
INVALID_SERVICE_ACCOUNT_JSON = "Please provide a valid value in the 'Contents of Service Account JSON file' asset configuration parameter"
LIST_SERVICE_ACCOUNT_KEY_SUCCESS_MSG = "Successfully retrieved the service account key(s)"
GET_SERVICE_ACCOUNT_KEY_SUCCESS_MSG = "Successfully retrieved the service account key"
DELETE_SERVICE_ACCOUNT_KEY_SUCCESS_MSG = "Successfully deleted the service account key"
CREATE_SERVICE_ACCOUNT_KEY_SUCCESS_MSG = "Successfully created the service account key"
GET_SERVICE_ACCOUNT_SUCCESS_MSG = "Successfully retrieved the service account"
DISABLE_SERVICE_ACCOUNT_SUCCESS_MSG = "Successfully disabled the service account"
ENABLE_SERVICE_ACCOUNT_SUCCESS_MSG = "Successfully enabled the service account"
