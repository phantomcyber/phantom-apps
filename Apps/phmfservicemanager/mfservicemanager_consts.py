# File: mfservicemanager_consts.py
#
# Copyright (c) 2020 Splunk Inc.
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
HPSM_INCIDENTS_ENDPOINT = "/SM/9/rest/incidents"
HPSM_CHANGES_ENDPOINT = "/SM/9/rest/changes"
HPSM_CONFIGITEMS_ENDPOINT = "/SM/9/rest/devices"
HPSM_ENDPOINT_BUILDER = "/SM/9/rest/{project_key}"
HPSM_GET_RESOURCE = "/SM/9/rest/{project_key}/{id}"
HPSM_CLOSE_RESOURCE = "/SM/9/rest/{project_key}/{id}/action/close"
HPSM_MOVE_RESOURCE_PHASE = "/SM/9/rest/{project_key}/{id}/action/MoveToNextPhase"

HPSM_DEFAULT_UPDATE_MESSAGE = [
    "Updating record from HPSM app on Phantom"
]

HPSM_DEFAULT_CHANGE_PHASE = "Registration, Plan & Schedule"
HPSM_DEFAULT_CHANGE_CATEGORY = "Standard Change"
