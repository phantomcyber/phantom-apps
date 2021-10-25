# File: bitglass_consts.py
#
# Copyright (c) 2021 Bitglass App Inc.
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
# Regex and datetime patterns
GC_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

# Ingestion run mode constants
GC_ALERT_USER_MATCH_KEY = 'User Alert Matches (by Asset Patterns)'

# Contains for the different artifact keys
GC_BG_USERNAME_CONTAINS = ['user name']

# # Error message constants
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Message constants
INVALID_PARAMS_ERR_MSG = "Please provide valid action parameters value"
INVALID_PARAM_ERR_MSG = "Please provide a valid action parameter value"
