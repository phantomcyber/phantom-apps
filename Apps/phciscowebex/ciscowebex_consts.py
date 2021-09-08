# File: ciscowebex_consts.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

SCOPE = 'spark-admin%3Abroadworks_subscribers_write%20meeting%3Arecordings_read%20meeting%3Aadmin_preferences_write%20spark%3Aall%20meeting%3Aadmin_preferences_read%20meeting' \
        '%3Aparticipants_read%20analytics%3Aread_all%20meeting%3Aadmin_participants_read%20meeting%3Apreferences_write%20meeting%3Aadmin_recordings_read%20meeting' \
        '%3Atranscripts_read%20meeting%3Aschedules_write%20meeting%3Acontrols_read%20spark-admin%3Ahybrid_clusters_read%20spark-admin%3Abroadworks_enterprises_write%20meeting' \
        '%3Aadmin_schedule_read%20spark-compliance%3Ameetings_write%20meeting%3Aadmin_schedule_write%20meeting%3Aschedules_read%20spark-admin%3Aroles_read%20meeting' \
        '%3Arecordings_write%20meeting%3Apreferences_read%20spark-compliance%3Arooms_read%20spark-admin%3Abroadworks_subscribers_read%20spark%3Akms%20meeting%3Acontrols_write' \
        '%20meeting%3Aadmin_recordings_write%20spark-admin%3Ahybrid_connectors_read%20audit%3Aevents_read%20meeting%3Aparticipants_write%20spark-compliance%3Arooms_write' \
        '%20meeting%3Aadmin_transcripts_read '
BASE_URL = 'https://webexapis.com'
AUTHORIZATION_URL = '/v1/authorize?client_id={client_id}&response_type={response_type}&redirect_uri={redirect_uri}&scope={scope}&state={state}'

UNKNOWN_ERR_MSG = "Unknown error occurred. Please check the asset configuration and|or action parameters"
UNKNOWN_ERR_CODE_MSG = "Error code unavailable"

OAUTH_WAIT_INTERVALS = 35
OAUTH_WAIT_TIME = 3

WEBEX_STR_CODE = 'code'
WEBEX_STR_TEXT = "text/plain"
WEBEX_STR_ACCESS_TOKEN = 'access_token'
WEBEX_STR_TOKEN = 'token'
WEBEX_STR_REFRESH_TOKEN = 'refresh_token'
WEBEX_STR_CLIENT_ID = 'client_id'
WEBEX_STR_SECRET = 'client_secret'
WEBEX_STR_GRANT_TYPE = 'grant_type'
WEBEX_STR_REDIRECT_URI = 'redirect_uri'

WEBEX_SUCCESS_CODE_RECEIVED_MESSAGE = 'Code received. Please close this window, the action will continue to get new token'
WEBEX_SUCCESS_TEST_CONNECTIVITY = "Test Connectivity Passed"
WEBEX_SUCCESS_SEND_MESSAGE = "Message sent successfully"

WEBEX_ERR_EMPTY_RESPONSE = "Empty response and no information in the header"
WEBEX_ERR_ASSET_NAME_NOT_FOUND = 'Asset Name for id: {0} not found'
WEBEX_ERR_PHANTOM_BASE_URL_NOT_FOUND = 'Phantom Base URL not found in System Settings. Please specify this value in System Settings'
WEBEX_ERR_TIMEOUT = 'Timeout. Please try again later'
WEBEX_ERR_TOKEN_NOT_AVAILABLE = 'Token not available. Please run Test Connectivity first'
WEBEX_ERR_TEST_CONNECTIVITY = 'Test Connectivity Failed'
WEBEX_ERR_REQUIRED_CONFIG_PARAMS = "Please provide either api_key or client_id and client secret in config for authentication"
WEBEX_ERR_USER_NOT_FOUND = 'User not found'

PHANTOM_ASSET_ENDPOINT = '/asset/{asset_id}'
PHANTOM_SYSTEM_INFO_ENDPOINT = '/system_info'

WEBEX_ACCESS_TOKEN_ENDPOINT = '/v1/access_token'
WEBEX_GET_ROOMS_ENDPOINT = '/v1/rooms'
WEBEX_GET_USER_ENDPOINT = "/v1/people?email={0}"
WEBEX_SEND_MESSAGE_ENDPOINT = "/v1/messages"
