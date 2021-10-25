# File: anyrun_consts.py
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
#
#
# API Endpoints
ANYRUN_TEST_CONNECTIVITY_ENDPOINT = 'environment'
ANYRUN_DETONATE_FILE_ENDPOINT = 'analysis'
ANYRUN_GET_REPORT_ENDPOINT = 'analysis/{taskid}'

ANYRUN_ERR_CODE_MSG = "Error code unavailable"
ANYRUN_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
ANYRUN_PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
ANYRUN_ERR_UNABLE_TO_FETCH_FILE = "Unable to fetch the {key} file"
