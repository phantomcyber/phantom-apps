# --
# File: okta_consts.py
#
# Copyright (c) 2018-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

OKTA_BASE_URL = "base_url"
OKTA_API_TOKEN = "api_key"
OKTA_PAGINATED_ACTIONS_LIST = [
    'list_users', 'list_user_groups', 'list_providers', 'list_roles']

OKTA_RESET_PASSWORD_SUCC = "Successfully created one-time token for user to reset password"

OKTA_LIMIT_INVALID_MSG_ERR = "Please provide a valid positive integer value for limit"
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

OKTA_TEST_CONNECTIVITY_FAILED = "Test Connectivity Failed."
OKTA_TEST_CONNECTIVITY_PASSED = "Test Connectivity Passed."

OKTA_INVALID_USER_MSG = "Kindly provide valid user_id."

# DO NOT MODIFY!
# A fixed field used by Okta to the integration
OKTA_APP_USER_AGENT_BASE = "SplunkPhantom/"
