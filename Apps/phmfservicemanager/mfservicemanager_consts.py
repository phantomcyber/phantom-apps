# File: mfservicemanager_consts.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

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
