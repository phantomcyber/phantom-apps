# File: mfservicemanager_consts.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL – Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

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
