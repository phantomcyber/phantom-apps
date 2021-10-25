# File: endace_consts.py
#
# Copyright (C) Endace Technology Limited, 2018-2021
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
# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"

# Constants relating to 'validate_integer'
VALID_INT_MSG = "Please provide a valid integer value in the {param}"
NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in {param}"
NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the {param}"
SPAN_BEFORE_KEY = "'span_before' action parameter"
SPAN_AFTER_KEY = "'span_after' action parameter"
PORT1_KEY = "'port1' action parameter"
PORT2_KEY = "'port2' action parameter"
MAX_PCAP_SIZE_KEY = "'max_pcap_size' asset configuration parameter"
