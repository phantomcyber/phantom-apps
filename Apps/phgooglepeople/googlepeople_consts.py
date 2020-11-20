# File: googlepeople_consts.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

GOOGLE_CONTACTS_SCOPE = 'https://www.googleapis.com/auth/contacts'
GOOGLE_OTHER_CONTACTS_SCOPE_READ_ONLY = 'https://www.googleapis.com/auth/contacts.other.readonly'
GOOGLE_DIRECTORY_SCPOPE_READ_ONLY = 'https://www.googleapis.com/auth/directory.readonly'
GOOGLE_PROFILE_SCOPE = 'https://www.googleapis.com/auth/userinfo.profile'
OTHER_CONTACTS_RESOURCE_NAME_PREFIX = 'otherContacts/'

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Google People Server. Please check the asset configuration and|or the action parameters"

# Constants relating to '_validate_integer'
INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the {}"
INVALID_NON_NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-negative integer value in the {}"

PAGE_SIZE_KEY = "'page_size' action parameter"
