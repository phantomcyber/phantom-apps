# File: cofensetriagev2_consts.py
#
# Copyright (c) 2021 Cofense
#
# This unpublished material is proprietary to Cofense.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Cofense.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

COFENSE_OAUTH_TOKEN_STRING = "token"
COFENSE_OAUTH_ACCESS_TOKEN_STRING = "access_token"
COFENSE_ERROR_CODE_MESSAGE = "Error code unavailable"
COFENSE_ERROR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or action parameters"
COFENSE_STATE_FILE_CORRUPT_ERROR = "Error occurred while loading the state file due to its unexpected format. Resetting the state file with the default format. Please try again"

PHANTOM_VAULT_DIR = '/opt/phantom/vault/tmp/'

COFENSE_TRIAGE_STATUS_ENDPOINT = "/api/public/v2/system/status"
COFENSE_TRIAGE_TOKEN_ENDPOINT = "/oauth/token"

COFENSE_REPORTS_ENDPOINT = "/api/public/v2/reports"
COFENSE_REPORT_ENDPOINT = "/api/public/v2/reports/{report_id}"
COFENSE_REPORTERS_ENDPOINT = "/api/public/v2/reporters"
COFENSE_CATEGORIZE_REPORT_ENDPOINT = "/api/public/v2/reports/{report_id}/categorize"
COFENSE_GET_CATEGORY_ID_BY_CATEGORY_NAME = "/api/public/v2/categories?filter[name_cont]={category_name}"
COFENSE_REPORTER_ENDPOINT = "/api/public/v2/reporters/{reporter_id}"
COFENSE_URLS_ENDPOINT = "/api/public/v2/urls"
COFENSE_URL_ENDPOINT = "/api/public/v2/urls/{url_id}"
COFENSE_THREAT_INDICATORS_ENDPOINT = '/api/public/v2/threat_indicators'
COFENSE_RESPONSE_ENDPOINT = "/api/public/v2/responses"
COFENSE_CATEGORIES_ENDPOINT = "/api/public/v2/categories"
COFENSE_EMAIL_ENDPOINT = '/api/public/v2/reports/{report_id}/download'
COFENSE_COMMENT_ENDPOINT = "/api/public/v2/comments/{comment_id}"
COFENSE_COMMENTS_ENDPOINT = "/api/public/v2/comments"
COFENSE_ATTACHMENT_PAYLOADS_ENDPOINT = "/api/public/v2/attachment_payloads"
COFENSE_RULES_ENDPOINT = "/api/public/v2/rules"
COFENSE_RULE_ENDPOINT = "/api/public/v2/rules/{rule_id}"

COFENSE_LABEL_STRING = "'label'"
COFENSE_TENANT_STRING = "'tenant'"
COFENSE_SORT_STRING = "'sort'"
COFENSE_REPORT_ID_STRING = "'report_id'"
COFENSE_TYPE_STRING = "'type'"
COFENSE_REPORT_LAST_INGESTED_DATE_STRING = "report_last_ingested_date"
COFENSE_THREAT_LAST_INGESTED_DATE_STRING = "threat_last_ingested_date"
COFENSE_START_DATE_FILTER = "filter[updated_at_gteq]"
COFENSE_ACCEPT_HEADER = COFENSE_CONTENT_TYPE_HEADER = "application/vnd.api+json"
COFENSE_AUTHORIZATION_HEADER = "Bearer {0}"
COFENSE_ACTION_HANDLER_MSG = "In action handler for: {0}"
COFENSE_ARTIFACT_NAME = "{} Artifact"
COFENSE_CATEGORY_ID_TO_SEVERITY = {
    "High": ["4"],
    "Medium": ["3"],
    "Low": ["1", "2", "5"],
}
COFENSE_DEFAULT_SEVERITY = "Low"
COFENSE_THREAT_LEVEL_TO_SEVERITY = {
    "High": ["malicious"],
    "Medium": ["suspicious"],
    "Low": ["benign"],
}
COFENSE_THREAT_LEVELS = ["malicious", "suspicious", "benign"]
COFENSE_THREAT_TYPES = ["hostname", "header", "url", "md5", "sha256"]
COFENSE_DEFAULT_THREAT_SOURCE = "Splunk_Phantom-UI"
COFENSE_REPORT_LOCATIONS = ["inbox", "reconnaissance", "processed", "all"]
COFENSE_SORT_VALUES = ["oldest_first", "latest_first"]
COFENSE_LEVEL_VALUES = ["malicious", "suspicious", "benign", "all"]
COFENSE_TYPE_VALUES = ['hostname', 'url', 'md5', 'sha256', 'header', 'all']
COFENSE_OPERATORS = ["eq", "not_eq", "lt", "lteq", "gt", "gteq"]
COFENSE_INGESTION_TYPES = ["reports", "threat_indicators"]
COFENSE_INGESTION_COMMON_KEYS = ["ingest_subfields", "cef_mapping", "sort", "max_results"]
COFENSE_INGESTION_REPORT_KEYS = ["match_priority", "category_id", "tags", "categorization_tags"]
COFENSE_COMMENT_BODY_FORMATS = ["text", "json", "all"]
COFENSE_INTEGRATION_TYPES = ["url", "md5", "sha256"]
COFENSE_RULE_CONTEXTS = ["internal safe", "unwanted", "threat hunting", "phishing tactic", "cleanup", "unknown", "all"]
COFENSE_REPORT_FILTER_MAPPING = {
    "location": "filter[location]",
    "from_address": "filter[from_address]",
    "match_priority": "filter[match_priority]",
    "subject": "filter[subject_cont]",
    "start_date": "filter[updated_at_gteq]",
    "end_date": "filter[updated_at_lt]",
    "categorization_tags": "filter[categorization_tags_any]",
    "tags": "filter[tags_any]",
}
COFENSE_THREAT_FILTER_MAPPING = {
    "level": "filter[threat_level]",
    "type": "filter[threat_type]",
    "source": "filter[threat_source]",
    "value": "filter[threat_value]",
    "start_date": "filter[updated_at_gteq]",
    "end_date": "filter[updated_at_lt]",
    "sort": "sort",
}
COFENSE_RULE_FILTER_MAPPING = {
    "name": "filter[name_cont]",
    "description": "filter[description_cont]",
    "priority": "filter[priority]",
    "tags": "filter[tags_any]",
    "scope": "filter[scope]",
    "author_name": "filter[author_name_cont]",
    "context": "filter[rule_context]",
    "active": "filter[active]",
    "start_date": "filter[updated_at_gteq]",
    "end_date": "filter[updated_at_lt]",
    "sort": "sort",
}

COFENSE_INVALID_PARAMETER = "Please provide a valid value in the {} parameter"
COFENSE_EMPTY_PARAMETER = "Please provide a value in the {} parameter"
COFENSE_DATA_NOT_FOUND = "Error: {} data not found in user_info"
COFENSE_INVALID_REPORTER_EMAIL = "Error: reporter with the provided email doesn't exist"
COFENSE_CATEGORY_ID_NAME_NOT_EXIST_ERR_MSG = "Please provide either category id or category name"
COFENSE_CATEGORIZE_REPORT_SUCC_MSG = "Successfully categorized the report"
COFENSE_INVALID_JSON_PARAMETER = "Please enter the value in JSON format in the {} parameter"
COFENSE_PARAM_VALIDATION_MSG = "Validating the parameters"
COFENSE_RETRIEVING_DATA_MSG = "Retrieving {} from Cofense Triage"

# Constants relating to "_validate_integer"
COFENSE_INVALID_INTEGER_ERR_MSG = "Please provide a valid integer value in the {} parameter"
COFENSE_NEGATIVE_INTEGER_ERR_MSG = "Please provide a valid non-negative integer value in the {} parameter"
COFENSE_ZERO_INTEGER_ERR_MSG = "Please provide a valid non-zero integer value in the {} parameter"

COFENSE_INVALID_INTEGER_LIST_ERR_MSG = "Please provide valid integer value(s) in the {} parameter"
