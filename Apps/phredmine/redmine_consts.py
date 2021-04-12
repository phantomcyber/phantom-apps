# File: redmine_consts.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

REDMINE_BACKFILL_DAYS = 7
REDMINE_TICKET_ARTIFACT_LABEL = "redmine_ticket"

REDMINE_TICKET_JSON_ID = "id"

REDMINE_TICKET_JSON_PROJECT_ID = "project_id"
REDMINE_TICKET_JSON_PROJECT_NAME = "project_name"

REDMINE_TICKET_JSON_TRACKER_ID = "tracker_id"
REDMINE_TICKET_JSON_TRACKER_NAME = "tracker_name"

REDMINE_TICKET_JSON_STATUS_ID = "status_id"
REDMINE_TICKET_JSON_STATUS_NAME = "status_name"

REDMINE_TICKET_JSON_PRIORITY_ID = "priority_id"
REDMINE_TICKET_JSON_PRIORITY_NAME = "priority_name"

REDMINE_TICKET_JSON_AUTHOR_ID = "author_id"
REDMINE_TICKET_JSON_AUTHOR_NAME = "author_name"

REDMINE_TICKET_JSON_SUBJECT = "subject"
REDMINE_TICKET_JSON_DESCRIPTION = "description"

REDMINE_TICKET_JSON_CREATED_ON = "created_on"
REDMINE_TICKET_JSON_UPDATED_ON = "updated_on"
REDMINE_TICKET_JSON_CLOSED_ON = "closed_on"

REDMINE_TICKET_STATUSES_KEY = "issue_statuses"
REDMINE_TICKET_STATUSES_ENDPONT = "/issue_statuses.json"

# Constants relating to 'get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters."

# Constants relating to 'validate_integer'
REDMINE_VALID_INT_MSG = "Please provide a valid integer value in the {param}"
REDMINE_NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in {param}"
REDMINE_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the {param}"
REDMINE_START_INDEX_KEY = "'start_index' action parameter"
REDMINE_MAX_RESULTS_KEY = "'max_results' action parameter"
REDMINE_CONTAINER_COUNT_KEY = "'Maximum containers' configuration parameter"

# Constants relating to error messages
REDMINE_ERR_EMPTY_RESPONSE = "Status Code {code}. Empty response and no information in the header."
REDMINE_UNABLE_TO_PARSE_ERR_DETAILS = "Cannot parse error details"
REDMINE_ERR_UNABLE_TO_PARSE_JSON_RESPONSE = "Unable to parse response as JSON. {error}"
REDMINE_ERR_CONNECTING_TO_SERVER = "Error connecting to server. Details: {error}"
REDMINE_ERR_INVALID_URL = "Error connecting to server. Invalid URL"
REDMINE_ERR_CONNECTION_REFUSED = "Error connecting to server. Connection Refused from the server."
REDMINE_ERR_INVALID_SCHEMA = "Error connecting to server. No connection adapters were found."
REDMINE_ERR_TEST_CONN_FAILED = "Test Connectivity Failed. Could not connect to server."
REDMINE_SUCC_TEST_CONN_PASSED = "Test Connectivity Passed"
REDMINE_ERR_INVALID_CUSTOM_FIELDS = "Please provide a valid value in 'custom fields' config parameter"
REDMINE_ERR_PARSING_CUSTOM_FIELDS = "Could not parse custom fields: {error}"
REDMINE_ERR_RETRIEVE_DEFINITIONS = "Could not retrieve definitions on '{endpoint}'"
REDMINE_ERR_MAPPING_NOT_FOUND = "Could not find mapping for provided value on '{endpoint}'"
REDMINE_ERR_PROCESSING_ENUMERATION = "Error occurred while processing the response of the Redmine enumeration"
REDMINE_ERR_PROCESSING_UPLOAD_DICT = "Error occurred while processing the upload dictionary"
REDMINE_ERR_CREATE_TICKET = "Could not create ticket"
REDMINE_ERR_PARSE_UPDATE_FIELDS = "Could not parse update_fields into JSON: {error}"
REDMINE_ERR_INVALID_VAULT_ID = "Invalid Vault ID: '{vault_id}'"
REDMINE_ERR_OPENING_FILE = "Error opening file. {error}"
REDMINE_ERR_GETTING_FILE_INFO = "Error occurred while getting 'File Info'. {error}"
REDMINE_ERR_UPLOAD_ATTACHMENT = "Could not upload attachment"
REDMINE_ERR_UPDATE_TICKET = "Failed to update ticket"
REDMINE_ERR_RETRIEVE_TICKET = "Could not retrieve ticket"
REDMINE_ERR_ADD_COMMENT = "Could not add comment to ticket '{id}'"
REDMINE_ERR_GET_TICKET = "Could not get ticket '{id}'"
REDMINE_ERR_DELETE_TICKET = "Could not delete ticket '{id}'"
REDMINE_ERR_RETRIEVE_TICKETS = "Could not retrieve tickets"
REDMINE_ERR_LIST_TICKETS = "Could not list tickets"
REDMINE_ERR_FETCHING_TICKETS = "Error occurred while fetching tickets: {error}"
REDMINE_ERR_GETTING_VAULT_INFO = "Error occurred while getting 'Vault Info'"
REDMINE_ERR_GETTING_FILE_PATH = "Error occurred while getting 'File Path'"

# Constants relating to success messages
REDMINE_SUCC_CREATE_TICKET = "Ticket created successfully"
REDMINE_SUCC_UPDATE_TICKET = "Ticket updated successfully"
REDMINE_SUCC_ADD_COMMENT = "Comment added successfully"
REDMINE_SUCC_GET_TICKET = "Ticket fetched successfully"
REDMINE_SUCC_DELETE_TICKET = "Ticket deleted successfully"
REDMINE_SUCC_SET_STATUS = "Updated ticket status successfully"
