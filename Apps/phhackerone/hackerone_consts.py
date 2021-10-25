# File: hackerone_consts.py
#
# Copyright (c) 2020-2021 Splunk Inc.
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
# Constants for actions
ACTION_ID_GET_ALL = 'get_reports'
ACTION_ID_GET_UPDATED = 'get_updated_reports'
ACTION_ID_GET_ONE = 'get_report'
ACTION_ID_UPDATE = 'update_id'
ACTION_ID_UNASSIGN = 'unassign'
ACTION_ID_ON_POLL = 'on_poll'
ACTION_ID_TEST = 'test_asset_connectivity'

# Constants for error messages
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the HackerOne Server. Please check the asset configuration and|or the action parameters"
INT_VALIDATION_ERR_MSG = "Please provide a valid integer value in the {}"
NEG_INT_VALIDATION_ERR_MSG = "Please provide a valid non-negative integer value in the {}"

# Constants for params
RANGE_KEY = "'range' action parameter"
CONTAINER_COUNT_KEY = "'container_count' action parameter"
