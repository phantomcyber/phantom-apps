# File: googlecloudiam_consts.py
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
