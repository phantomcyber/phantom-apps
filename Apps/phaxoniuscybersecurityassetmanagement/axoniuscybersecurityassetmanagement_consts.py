# File: axoniuscybersecurityassetmanagement_consts.py
#
# Copyright (c) Axonius, 2018-2021
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
API_KEY = "api_key"
API_SECRET = "api_secret"
URL_KEY = "url"
PROXY_URL_KEY = "proxy_url"
SQ_NAME_KEY = "sq_name"
MAX_ROWS_KEY = "max_rows"
HOSTNAME_KEY = "hostname"
IP_KEY = "ip"
MAC_KEY = "mac"
MAIL_KEY = "mail"
USERNAME_KEY = "username"
ADDITIONAL_FIELDS_KEY = "additional_fields"

# Maximum number of assets to allow user to fetch
MAX_ROWS = 25

# Fields to remove from each asset if found
SKIPS = ["specific_data.data.image"]

# Fields to try and convert to date time if they have these words in them
FIELDS_TIME = ["seen", "fetch", "time", "date"]

# exception handling
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = (
    "Error message unavailable. Please check the asset configuration and|or action"
    " parameters"
)

# Integer validation constants
VALID_INTEGER_MSG = "Please provide a valid integer value for the parameter '{key}'"
NON_NEGATIVE_INTEGER_MSG = (
    "Please provide a valid non-negative integer value for the parameter '{key}'"
)

STATE_FILE_CORRUPT_ERR = (
    "Error occurred while loading the state file due to its unexpected format."
    " Resetting the state file with the default format. Please try again"
)
