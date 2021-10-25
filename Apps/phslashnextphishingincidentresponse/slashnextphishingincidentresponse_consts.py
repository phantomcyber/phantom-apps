# File: slashnextphishingincidentresponse_consts.py
#
# Copyright (c) 2019-2020 SlashNext Inc. (www.slashnext.com)
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
BASE_API = 'https://oti.slashnext.cloud/api'
HOST_REPUTE_API = '/oti/v1/host/reputation'
URL_SCAN_API = '/oti/v1/url/scan'
URL_SCANSYNC_API = '/oti/v1/url/scansync'
HOST_REPORT_API = '/oti/v1/host/report'
DL_SC_API = '/oti/v1/download/screenshot'
DL_HTML_API = '/oti/v1/download/html'
DL_TEXT_API = '/oti/v1/download/text'
API_QUOTA = '/oti/v1/quota/status'

# Constants relating to '_get_error_message_from_exception'

ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the SlashNext Phishing Incident Response Server. Please check the asset configuration and|or the action parameters"

# Constants relating to '_validate_integer'

INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the {}"
INVALID_NON_NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-negative integer value in the {}"

LIMIT_KEY = "'limit' action parameter"
TIMEOUT_KEY = "'timeout' action parameter"
