# File: redcanary_consts.py
#
# Copyright (c) Red Canary, 2021
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
RC_DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_PER_PAGE = 50
STR_LAST_RUN = "last_run"
STR_META = "meta"
STR_TOTAL_ITEMS = "total_items"
STR_NOT_FOUND = "not_found"
STR_PER_PAGE = "per_page="
STR_SINCE = "since="
STR_PAGE = "page="
DETECTION_ID_KEY = "'detection_id' action"

# Constants related to _get_error_message_from_exception
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Constants related to _validate_integer
INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the {} parameter"
NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-negative integer value in the {} parameter"
