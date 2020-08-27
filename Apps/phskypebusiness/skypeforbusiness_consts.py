# File: skypeforbusiness_consts.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# Define your constants here

SKYPE4B_LOGIN_BASE_URL = 'https://login.microsoftonline.com'
SKYPE4B_AUTHORIZE_URL = '/{tenant_id}/oauth2/authorize?client_id={client_id}&redirect_uri={redirect_uri}' \
                       '&response_type={response_type}&state={state}&resource={resource}'
SKYPE4B_SERVER_TOKEN_URL = '/{tenant_id}/oauth2/token'
SKYPE4B_FIRST_HUB_URL_ENDPOINT = 'https://webdir.online.lync.com/autodiscover/autodiscoverservice.svc/root'
SKYPE4B_AUTODISCOVERY_ENDPOINT = '/autodiscover/autodiscoverservice.svc/root/oauth/user'
SKYPE4B_PHANTOM_BASE_URL = '{phantom_base_url}rest'
SKYPE4B_PHANTOM_SYS_INFO_URL = '/system_info'
SKYPE4B_PHANTOM_ASSET_INFO_URL = '/asset/{asset_id}'
SKYPE4B_APPLICATIONS_ENDPOINT = '/ucwa/oauth/v1/applications'
SKYPE4B_REST_URL_NOT_AVAILABLE_MSG = 'Rest URL not available. Error: {error}'
SKYPE4B_TEST_CONNECTIVITY_FAILED_MSG = 'Test connectivity failed'
SKYPE4B_TEST_CONNECTIVITY_PASSED_MSG = 'Test connectivity passed'
SKYPE4B_OAUTH_URL_MSG = 'Using OAuth URL:'
SKYPE4B_BASE_URL_NOT_FOUND_MSG = 'Phantom Base URL not found in System Settings. ' \
                                'Please specify this value in System Settings.'
SKYPE4B_AUTHORIZE_USER_MSG = 'Please authorize user in a separate tab using URL'
SKYPE4B_TOKEN_NOT_AVAILABLE_MSG = 'Token not available. Please run test connectivity first.'
SKYPE4B_RUN_TEST_CONN_MSG = 'Resource URL not available. Please run test connectivity first.'
SKYPE4B_JSON_CONTACT = 'contact_email'
SKYPE4B_JSON_MESSAGE = 'message'
SKYPE4B_CONFIG_CLIENT_ID = 'client_id'
SKYPE4B_CONFIG_CLIENT_SECRET = 'client_secret'
SKYPE4B_CONFIG_TENANT = 'tenant'
SKYPE4B_DEFAULT_TENANT = 'common'
SKYPE4B_ACCESS_TOKEN = 'access_token'
SKYPE4B_REFRESH_TOKEN = 'refresh_token'
SKYPE4B_TOKEN_STRING = 'token'
SKYPE4B_TC_FILE = 'oauth_task.out'
SKYPE4B_HEADERS_APP_JSON = 'application/json'
SKYPE4B_AUTHORIZE_WAIT_TIME = 15
SKYPE4B_TC_STATUS_SLEEP = 3
