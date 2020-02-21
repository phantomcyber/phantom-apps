# File: jira_consts.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
# --


JIRA_JSON_DEVICE_URL = "device_url"
JIRA_JSON_DESCRIPTION = "description"
JIRA_JSON_ISSUE_ASSIGNEE = "assignee"
JIRA_JSON_ISSUE_PRIORITY = "priority"
JIRA_JSON_ISSUE_TYPE = "issue_type"
JIRA_JSON_PROJECT_KEY = "project_key"
JIRA_JSON_COMMENT = "comment"
JIRA_JSON_COMMENT_VISIBILITY_TYPE = "comment_visibility_type"
JIRA_JSON_COMMENT_VISIBILITY = "comment_visibility"
JIRA_JSON_SUMMARY = "summary"
JIRA_JSON_PROJECT_ID = "id"
JIRA_JSON_PROJECT_NAME = "name"

JIRA_JSON_ISSUE_ID = "id"
JIRA_JSON_WATCHER = "username"
JIRA_JSON_QUERY = "query"
JIRA_JSON_START_INDEX = "start_index"
JIRA_JSON_MAX_RESULTS = "max_results"
JIRA_TOTAL_ISSUES = "total_issues"
JIRA_TOTAL_PROJECTS = "total_projects"

JIRA_JSON_ATTACHMENT = "vault_id"

JIRA_JSON_NAME = "name"
JIRA_JSON_ID = "id"
JIRA_JSON_PRIORITY = "priority"
JIRA_JSON_RESOLUTTION = "resolution"
JIRA_JSON_STATUS = "status"
JIRA_JSON_REPORTER = "reporter"
JIRA_JSON_UPDATE_FIELDS = "update_fields"
JIRA_JSON_RESOLUTION = "resolution"
JIRA_JSON_FIELDS = "fields"
JIRA_JSON_FROM_ID = "from_id"
JIRA_JSON_TO_ID = "to_id"
JIRA_JSON_LINK_TYPE = "link_type"
JIRA_JSON_UPDATED_AT = "updated_at"
JIRA_JSON_CONTAINER = 'container'
JIRA_JSON_SDI = 'source_data_identifier'
JIRA_JSON_LABEL = 'label'
JIRA_JSON_CEF = 'cef'
JIRA_JSON_UNRESOLVED = 'Unresolved'
JIRA_JSON_CUSTOM_FIELDS = 'custom_fields'

JIRA_INVALID_LIMIT = "Please provide non-zero positive integer in limit"
JIRA_ERR_FETCH_CUSTOM_FIELDS = "Error occurred while fetching the custom fields metadata"
JIRA_ERR_API_INITIALIZATION = "API Initialization failed"
JIRA_ERR_API_TIMEOUT = "Timed out waiting for API to initialize. Please verify the asset configuration parameters, username, and password."
JIRA_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
JIRA_ERR_PROJECTS_INFO = "Error getting projects info"
JIRA_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
JIRA_ERR_TICKET_ASSIGNMENT_FAILED = "Ticket assignment to user '{0}' failed. {1}"
JIRA_ERR_CREATE_TICKET_FAILED = "Ticket creation failed"
JIRA_SUCC_TICKET_CREATED = "Created ticket with id: {id}, key: {key}"
JIRA_ERR_FILE_NOT_IN_VAULT = "Could not find specified vault ID in vault"
JIRA_ERR_ATTACH_FAILED = "Adding attachment failed. {0}"
JIRA_ERR_LIST_TICKETS_FAILED = "Failed to get ticket listing"
JIRA_ERR_GET_TICKET = "Failed to get ticket info"
JIRA_ERR_FIELDS_JSON_PARSE = "Unable to parse the '{field_name}' parameter into a dictionary"
JIRA_ERR_ISSUE_VALID_TRANSITIONS = "Input status does not seem to be a valid status that can be set for this issue"
JIRA_ERR_ISSUE_VALID_RESOLUTION = "Input resolution does not seem to be valid"
JIRA_ERR_UPDATE_NO_PARAM = "Either the Vault ID or the JSON field must be filled out to perform this action"
JIRA_ERR_UPDATE_FAILED = "Unable to update the ticket with the given JSON"
JIRA_ERR_COMMENT_SET_STATUS_FAIL = "Comment could not be added successfully due to either permissions or configuration issue "
JIRA_ERR_COMMENT_SET_STATUS_FAIL += "(changing the status of the ticket to Closed and then, trying to add comment to it is one such scenario)."
JIRA_SUCC_TICKET_UPDATED = "Successfully updated the ticket"
JIRA_SUCC_TICKET_DELETED = "Successfully deleted the ticket"
JIRA_ERR_INPUT_FIELDS_NOT_THE_ONLY_ONE = "Invalid fields value"
JIRA_ERR_INPUT_FIELDS_NOT_THE_ONLY_ONE += " The input json has a 'fields' key in it in addition to other keys"
JIRA_ERR_INPUT_FIELDS_NOT_THE_ONLY_ONE += " Either specify a dictionary with only one parent 'fields' key or multiple keys without the 'fields' key"
JIRA_ERR_FAILURES = "Some tickets had issues during ingestion, see logs for the details"
JIRA_ERR_NEGATIVE_INPUT = "'start_index' cannot be a negative value"

JIRA_CREATED_TICKET = "Created ticket"
JIRA_USING_BASE_URL = "Using URL: {base_url}"

DEFAULT_MAX_RESULTS = 100
DEFAULT_START_INDEX = 0
JIRA_START_TIMEOUT = 30
JIRA_TIME_FORMAT = "%Y/%m/%d %H:%M"
