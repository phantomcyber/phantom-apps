# File: detectionondemand_consts.py
#
# Copyright (c) FireEye, 2020
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
DOD_API_AUTH_HEADER = 'feye-auth-key'

DOD_HEALTH_ENDPOINT = '/health'
DOD_FILES_ENDPOINT = '/files'
DOD_HASHES_ENDPOINT = '/hashes'
DOD_REPORTS_ENDPOINT = '/reports'
DOD_PRESIGNED_URL_ENDPOINT = '/presigned-url'

PRESIGNED_URL_EXPIRY_KEY = "'presigned_url_expiry' action parameter"
POLL_ATTEMPTS_KEY = "'poll_attempts' action parameter"
POLL_INTERVAL_KEY = "'poll_interval' action parameter"

ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Detection on Demand Server. Please check the asset configuration and|or the action parameters"
