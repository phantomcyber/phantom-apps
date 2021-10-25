# File: okta_consts.py
#
# Copyright (c) 2018-2021 Splunk Inc.
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
OKTA_BASE_URL = "base_url"
OKTA_API_TOKEN = "api_key"
OKTA_PAGINATED_ACTIONS_LIST = [
    'list_users', 'list_user_groups', 'list_providers', 'list_roles']

OKTA_RESET_PASSWORD_SUCC = "Successfully created one-time token for user to reset password"

OKTA_LIMIT_INVALID_MSG_ERR = "Please provide a valid positive integer value for 'limit' action parameter"
OKTA_LIMIT_NON_ZERO_POSITIVE_MSG_ERR = "Please provide a valid non-zero positive integer value for 'limit' action parameter"
OKTA_PAGINATION_MSG_ERR = "Error occurred while fetching paginated response for action: {action_name}"

OKTA_DISABLE_USER_SUCC = "Successfully disabled the user"
OKTA_ALREADY_DISABLED_USER_ERR = "User is already disabled"

OKTA_ENABLE_USER_SUCC = "Successfully enabled the user"
OKTA_ALREADY_ENABLED_USER_ERR = "User is already enabled"

OKTA_SET_PASSWORD_SUCC = "Successfully set user password"

OKTA_ASSIGN_ROLE_SUCC = "Successfully assigned role to user"
OKTA_ALREADY_ASSIGN_ROLE_ERR = "Role is already assigned to user"

OKTA_UNASSIGN_ROLE_SUCC = "Successfully unassigned role to user"
OKTA_ALREADY_UNASSIGN_ROLE_ERR = "Role is not assigned to user"

OKTA_ALREADY_ADDED_GROUP_ERR = "Group already added to organization"
OKTA_ADDED_GROUP_SUCCESS_MSG = "Group has been added successfully"

OKTA_GET_GROUP_SUCC = "Successfully retrieved group"
OKTA_GET_USER_SUCC = "Successfully retrieved user"

OKTA_TEST_CONNECTIVITY_FAILED = "Test Connectivity Failed"
OKTA_TEST_CONNECTIVITY_PASSED = "Test Connectivity Passed"

OKTA_INVALID_USER_MSG = "Please provide a valid user_id"

OKTA_CLEAR_USER_SESSIONS_SUCC = "Successfully cleared user sessions"
OKTA_SEND_PUSH_NOTIFICATION_ERR_MSG = "Please configure factor_type '{factor_type}' for the user '{user_id}'"

# DO NOT MODIFY!
# A fixed field used by Okta to the integration
OKTA_APP_USER_AGENT_BASE = "SplunkPhantom/"
UNEXPECTED_RESPONSE_MSG = "Unexpected response received"

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Okta Server. Please check the asset configuration and|or the action parameters"

# Constants relating to value_list check
FACTOR_TYPE_VALUE_LIST = ["push", "sms (not yet implemented)", "token:software:totp (not yet implemented)"]
RECEIVE_TYPE_VALUE_LIST = ["Email", "UI"]
IDENTITY_PROVIDERS_TYPE_VALUE_LIST = ["SAML2", "FACEBOOK", "GOOGLE", "LINKEDIN", "MICROSOFT"]
ROLE_TYPE_VALUE_LIST = ["SUPER_ADMIN", "ORG_ADMIN", "API_ACCESS_MANAGEMENT_ADMIN", "APP_ADMIN", "USER_ADMIN", "MOBILE_ADMIN", "READ_ONLY_ADMIN"]
VALUE_LIST_VALIDATION_MSG = "Please provide valid input from {} in '{}' action parameter"
