# File: googlepeople_consts.py
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
GOOGLE_CONTACTS_SCOPE = 'https://www.googleapis.com/auth/contacts'
GOOGLE_OTHER_CONTACTS_SCOPE_READ_ONLY = 'https://www.googleapis.com/auth/contacts.other.readonly'
GOOGLE_DIRECTORY_SCOPE_READ_ONLY = 'https://www.googleapis.com/auth/directory.readonly'
GOOGLE_PROFILE_SCOPE = 'https://www.googleapis.com/auth/userinfo.profile'
OTHER_CONTACTS_RESOURCE_NAME_PREFIX = 'otherContacts/'

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Constants relating to '_validate_integer'
INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the {}"
INVALID_NON_ZERO_NON_NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-zero positive integer value in the {}"
INVALID_COMMA_SEPARATED_ERR_MSG = "Please provide valid comma-seprated value in the '{}' action parameter"

LIMIT_KEY = "'limit' action parameter"

GOOGLE_CREATE_CLIENT_FAILED_MSG = "Failed to create the Google People client"
GOOGLE_LIST_OTHER_CONTACTS_FAILED_MSG = "Failed to list other contacts"
GOOGLE_LIST_PEOPLE_FAILED_MSG = "Failed to list people"
GOOGLE_LIST_DIRECTORY_FAILED_MSG = "Failed to list directory"
GOOGLE_COPY_CONTACT_FAILED_MSG = "Failed to copy contact"
GOOGLE_GET_USER_PROFILE_FAILED_MSG = "Failed to get user profile"
