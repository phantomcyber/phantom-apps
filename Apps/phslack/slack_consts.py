# File: slack_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

SLACK_BASE_URL = "https://slack.com/api/"
SLACK_MESSAGE_LIMIT = 4000
SLACK_DEFAULT_LIMIT = 100

SLACK_JSON_BOT_TOKEN = "bot_token"
SLACK_JSON_VERIFICATION_TOKEN = "verification_token"

SLACK_PHANTOM_ASSET_INFO_URL = "{url}rest/asset/{asset_id}"
SLACK_PHANTOM_SYS_INFO_URL = "{url}rest/system_info"
SLACK_PHANTOM_ICON = "https://www.phantom.us/img/phantom_icon_160x160.png"

SLACK_CHANNEL_CREATE_ENDPOINT = "conversations.create"
SLACK_INVITE_TO_CHANNEL = "conversations.invite"
SLACK_LIST_CHANNEL = "conversations.list"
SLACK_AUTH_TEST = "auth.test"
SLACK_USER_LIST = "users.list"
SLACK_USER_INFO = "users.info"
SLACK_SEND_MESSAGE = "chat.postMessage"
SLACK_UPLOAD_FILE = "files.upload"

SLACK_TC_STATUS_SLEEP = 2
SLACK_TC_FILE = "slack_auth_task.out"

SLACK_SUCC_MESSAGE = "Slack message post successful"

SLACK_ERR_MESSAGE_RETURNED_NO_DATA = "Message post did not receive response"
SLACK_ERR_SERVER_CONNECTION = "Connection to server failed"
SLACK_ERR_UNSUPPORTED_METHOD = "Unsupported method"
SLACK_ERR_FROM_SERVER = "Got unknown error from slack server"
SLACK_ERR_NOT_IN_VAULT = "No item in vault has the supplied ID"
SLACK_ERR_CODE_UNAVAILABLE = "Error code unavailable"
SLACK_ERR_MESSAGE_UNKNOWN = "Unknown error occurred. Please check the asset configuration and|or action parameters"
SLACK_UNICODE_DAMMIT_TYPE_ERR_MESSAGE = "Error occurred while connecting to the Slack server. Please check the asset configuration and|or the action parameters"
SLACK_ERR_INVALID_INT = "Please provide a valid integer value in the {key} parameter"
SLACK_ERR_NEGATIVE_AND_ZERO_INT = "Please provide a valid non-zero positive integer value in the {key} parameter"
SLACK_ERR_UNABLE_TO_FETCH_FILE = "Unable to fetch the file {key}"

SLACK_RESP_POLL_INTERVAL_KEY = "'How often to poll for a response (in seconds)' configuration"
SLACK_TIMEOUT_KEY = "'Question timeout (in minutes)' configuration"
SLACK_TOTAL_RESP_KEY = "'Total number of responses to keep' configuration"
SLACK_LIMIT_KEY = "'limit' action"
