# File: airlockdigital_consts.py
#
# Copyright (c) Domenico Perre & Airlock Digital Pty Ltd, 2020
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
# endpoints
AIRLOCK_LICENSE_GET_ENDPOINT = "/license/get"
AIRLOCK_HASH_BLOCKLIST_REMOVE_ALL_ENDPOINT = "/hash/blocklist/remove/all"
AIRLOCK_HASH_BLOCKLIST_REMOVE_ENDPOINT = "/hash/blocklist/remove"
AIRLOCK_HASH_APPLICATION_REMOVE_ALL_ENDPOINT = "/hash/application/remove/all"
AIRLOCK_HASH_APPLICATION_REMOVE_ENDPOINT = "/hash/application/remove"
AIRLOCK_HASH_BLOCKLIST_ADD_ENDPOINT = "/hash/blocklist/add"
AIRLOCK_HASH_ADD_ENDPOINT = "/hash/add"
AIRLOCK_HASH_APPLICATION_ADD_ENDPOINT = "/hash/application/add"
AIRLOCK_BLOCKLIST_ENDPOINT = "/blocklist"
AIRLOCK_BASELINE_ENDPOINT = "/baseline"
AIRLOCK_APPLICATION_ENDPOINT = "/application"
AIRLOCK_GROUP_ENDPOINT = "/group"
AIRLOCK_GROUP_POLICIES_ENDPOINT = "/group/policies"
AIRLOCK_AGENT_MOVE_ENDPOINT = "/agent/move"
AIRLOCK_AGENT_FIND_ENDPOINT = "/agent/find"
AIRLOCK_OTP_REVOKE_ENDPOINT = "/otp/revoke"
AIRLOCK_OTP_RETRIEVE_ENDPOINT = "/otp/retrieve"
AIRLOCK_HASH_QUERY_ENDPOINT = "/hash/query"

# exception handling
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Airlock Digital Server. Please check the asset configuration and|or the action parameters"

# validate integer
ERR_VALID_INT_MSG = "Please provide a valid integer value in the {}"
ERR_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the {}"
STATUS_INT_PARAM = "'status' action parameter"
