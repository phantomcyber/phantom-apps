# File: agari_consts.py
#
# Copyright (c) Agari, 2021
#
# This unpublished material is proprietary to Agari.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Agari.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

AGARI_USER_AGENT = "AgariPhantom APDIntegration/v1.0.0 PhantomServer/{product_version}"
AGARI_OAUTH_TOKEN_STRING = "token"
AGARI_OAUTH_ACCESS_TOKEN_STRING = "access_token"
AGARI_ACTION_HANDLER_MSG = "In action handler for: {identifier}"
AGARI_AUTHORIZATION_HEADER = "Bearer {token}"
AGARI_DEFAULT_LIMIT = 200
AGARI_DEFAULT_OFFSET = 0
AGARI_DEFAULT_MAX_RESULTS = 100
AGARI_API_SUPPORT_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.000-00:00'
AGARI_DEFAULT_NUM_RETRIES = 5
AGARI_DEFAULT_MAX_WORKERS = 1
AGARI_DEFAULT_BACKOFF_FACTOR = 0.3
AGARI_DEFAULT_UPDATE_STATE_AFTER = 1
AGARI_DEFAULT_DAYS = 14
AGARI_MAX_DAYS = 14
AGARI_LAST_INGESTED_POLICY_EVENT_DATE = 'last_ingested_policy_event_date'
AGARI_LAST_INGESTED_POLICY_EVENT_ID = 'last_ingested_policy_event_id'

# Endpoints
AGARI_BASE_URL = "https://api.agari.com/v1/ep"
AGARI_TOKEN_ENDPOINT = "/token"
AGARI_LIST_POLICY_EVENTS_ENDPOINT = '/policy_events'
AGARI_LIST_MESSAGES_ENDPOINT = '/messages'
AGARI_GET_POLICY_EVENT_ENDPOINT = '/policy_events/{id}'
AGARI_GET_MESSAGE_ENDPOINT = '/messages/{id}'
AGARI_REMEDIATE_MESSAGE_ENDPOINT = '/messages/{id}/remediate'

# Constants relating to 'get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters."

# Constants relating to 'validate_integer'
AGARI_VALID_INT_MSG = "Please provide a valid integer value in the '{param}' parameter"
AGARI_NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in '{param}' parameter"
AGARI_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the '{param}' parameter"

# Constants relating to error messages
AGARI_ERR_EMPTY_RESPONSE = "Status Code {code}. Empty response and no information in the header."
AGARI_UNABLE_TO_PARSE_ERR_DETAIL = "Cannot parse error details"
AGARI_ERR_UNABLE_TO_PARSE_JSON_RESPONSE = "Unable to parse response as JSON. {error}"
AGARI_ERR_CONNECTING_TO_SERVER = "Error connecting to server. Details: {error}"
AGARI_ERR_TEST_CONN_FAILED = "Test Connectivity Failed"
AGARI_SUCC_TEST_CONN_PASSED = "Test Connectivity Passed"
AGARI_ERR_INVALID_SORT = "Please provide a valid value in the '{param}' parameter. The valid format is '<field_name> ASC/DESC'."
AGARI_ERR_INVALID_FIELDS = "Please provide a valid value in the '{field}' parameter"
AGARI_STATE_FILE_CORRUPT_ERR = "Error occurred while loading the state file due to its unexpected format. Resetting the state file with the default format. Please try again."
AGARI_ERR_PARSE_DATE = "Error occurred while parsing date. Please provide a valid value in ISO format for '{param}' parameter."
AGARI_ERR_END_DATE_LESS_THAN_START_DATE = "Please provide valid values in 'start_date' and 'end_date' parameters. The provided 'end_date' is less than the 'start_date'."
AGARI_ERR_CREATING_SESSION_OBJECT = "Error occurred while creating the session object"
AGARI_ERR_DATE_NOT_IN_RANGE = "Please provide a valid value in the '{key}' parameter. The provided '{key}' is not in range (last 14 days)."
AGARI_ERR_INVALID_JSON = "Failed to parse the JSON string. Please enter the value in JSON format in the 'cef_mapping' parameter."
AGARI_ERR_SKIP_POLICY_EVENT = "Skipping policy event {} and its associated message"
AGARI_ERR_ADD_FIELDS = "The specified add_fields parameter is not allowed:"
AGARI_ERR_NO_POLICY_EVENT_INGESTED = "Error occurred while ingesting the policy events. ID: {} policy events are not ingested."
AGARI_SUCC_NO_POLICY_EVENT_TO_INGEST = "No policy events to ingest"

# Constants relating to success messages
AGARI_SUCC_GET_MESSAGE = "Message fetched successfully"
AGARI_SUCC_GET_POLICY_EVENT = "Policy Event fetched successfully"
AGARI_SUCC_REMEDIATE_MESSAGE = "Message remediated successfully"
AGARI_INGESTION_STATUS_UPDATED = "Ingestion time and policy event ID updated"

# Constants relating to value list
AGARI_SORT_VALUE_LIST = ['ASC', 'DESC']
AGARI_POLICY_ACTION_VALUE_LIST = ['deliver', 'move', 'delete', 'inbox', 'none', 'all']
AGARI_EXCLUDE_ALERT_TYPES_VALUE_LIST = ['MessageAlert', 'SystemAlert', 'None']
AGARI_POLICY_ENABLED_VALUE_LIST = ['True', 'False', 'All']
AGARI_ERR_INVALID_SORT_TYPE = "Please provide a valid sort type. Expected values are 'ASC' or 'DESC'."
AGARI_ERR_INVALID_VALUE_LIST_PARAMETER = "Please provide a valid value in the '{param}' parameter. Expected values are '{value_list}'."
