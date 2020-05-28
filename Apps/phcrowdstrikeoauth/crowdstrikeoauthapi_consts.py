# File: crowdstrikeoauthapi_consts.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Json keys specific to the app's input parameters/config and the output result
CROWDSTRIKE_JSON_URL_OAuth = "url"
CROWDSTRIKE_CLIENT_ID = "client_id"
CROWDSTRIKE_CLIENT_SECRET = "client_secret"
CROWDSTRIKE_OAUTH_TOKEN_STRING = "oauth2_token"
CROWDSTRIKE_OAUTH_ACCESS_TOKEN_STRING = "access_token"

# Status messages for the app
CROWDSTRIKE_SUCC_CONNECTIVITY_TEST = "Test connectivity passed"
CROWDSTRIKE_ERR_CONNECTIVITY_TEST = "Test connectivity failed"
CROWDSTRIKE_ERR_CONNECTING = "Error connecting to server"
CROWDSTRIKE_ERR_FROM_SERVER = "Error from Server, Status Code: {status}, Message: {message}"
CROWDSTRIKE_ERR_END_TIME_LT_START_TIME = "End time less than start time"
CROWDSTRIKE_UNABLE_TO_PARSE_DATA = "Unable to parse data from server"
CROWDSTRIKE_INVALID_LIMIT = 'Please provide non-zero positive integer in limit'
CROWDSTRIKE_HTML_ERROR = 'Bad Request - Invalid URL HTTP Error 400. The request URL is invalid'
CROWDSTRIKE_NO_PARAMETER_ERROR = "One of the parameters (device_id or hostname) must be provided"
CROWDSTRIKE_INVALID_INPUT_ERROR = "Please provide valid inputs"
CROWDSTRIKE_INVALID_DEVICE_ID_AND_HOSTNAME_ERROR = "Please provide valid device_id and hostname"
CROWDSTRIKE_INVALID_DEVICE_ID_ERROR = "Please provide valid device_id"
CROWDSTRIKE_INVALID_HOSTNAME_ERROR = "Please provide valid hostname"

# endpoint
CROWDSTRIKE_OAUTH_TOKEN_ENDPOINT = "/oauth2/token"
CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT = "/devices/queries/devices/v1"
CROWDSTRIKE_GET_DEVICE_DETAILS_ENDPOINT = "/devices/entities/devices/v1"
CROWDSTRIKE_GET_HOST_GROUP_ID_ENDPOINT = "/devices/queries/host-groups/v1"
CROWDSTRIKE_GET_HOST_GROUP_DETAILS_ENDPOINT = "/devices/entities/host-groups/v1"
CROWDSTRIKE_DEVICE_ACTION_ENDPOINT = "/devices/entities/devices-actions/v2"
CROWDSTRIKE_GROUP_DEVICE_ACTION_ENDPOINT = "/devices/entities/host-group-actions/v1"
# Incident Endpoints
CROWDSTRIKE_LIST_CROWDSCORES_ENDPOINT = "/incidents/combined/crowdscores/v1"
CROWDSTRIKE_GET_INCIDNET_BEHAVIORS_ID_ENDPOINT = "/incidents/entities/behaviors/GET/v1"
CROWDSTRIKE_UPDATE_INCIDENT_ENDPOINT = "/incidents/entities/incident-actions/v1"
CROWDSTRIKE_GET_INCIDENT_DETAILS_ID_ENDPOINT = "/incidents/entities/incidents/GET/v1"
CROWDSTRIKE_LIST_BEHAVIORS_ENDPOINT = "/incidents/queries/behaviors/v1"
CROWDSTRIKE_LIST_INCIDENTS_ENDPOINT = "/incidents/queries/incidents/v1"
# User Endpoints
CROWDSTRIKE_GET_ROLE_ENDPOINT = "/user-roles/entities/user-roles/v1"
CROWDSTRIKE_GET_USER_ROLES_ENDPOINT = "/user-roles/queries/user-role-ids-by-user-uuid/v1"
CROWDSTRIKE_LIST_USER_ROLES_ENDPOINT = "/user-roles/queries/user-role-ids-by-cid/v1"
CROWDSTRIKE_GET_USER_INFO_ENDPOINT = "/users/entities/users/v1"
CROWDSTRIKE_LIST_USERS_EMAILS_ENDPOINT = "/users/queries/emails-by-cid/v1"
CROWDSTRIKE_LIST_USERS_UIDS_ENDPOINT = "/users/queries/user-uuids-by-cid/v1"
CROWDSTRIKE_GET_USER_BY_EMAIL_ENDPOINT = "/users/queries/user-uuids-by-email/v1"
