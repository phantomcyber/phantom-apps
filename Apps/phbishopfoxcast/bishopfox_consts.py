# File: bishopfox_consts.py
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
SEVERITY_MAP = {
    "Critical": "High",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low"
}

STATUS_CODES = {
    "new": "0",
    "acknowledged": "1",
    "request re-test": "2",
    "re-test validated": "3",
    "re-test failed": "4",
    "remediated": "5",
    "won't fix": "6",
    "not applicable": "7"
}

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
