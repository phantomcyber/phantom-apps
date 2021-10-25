# File: paloaltocortexxdr_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Exception message handling constants
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
ERR_PARSING_RESPONSE = "Error occurred while processing the response"
VALID_VALUE_MSG = "Please provide a valid value in the {key}"

# Integer validation constants
VALID_INTEGER_MSG = "Please provide a valid integer value in the {key}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {key}"

# Parameter Keys
ACTIONID_ACTION_PARAM = "'action_id' action parameter"
INCIDENTID_ACTION_PARAM = "'incident_id' action parameter"
FIRSTSEEN_ACTION_PARAM = "'first_seen' action parameter"
LASTSEEN_ACTION_PARAM = "'last_seen' action parameter"
MODIFICATIONTIME_ACTION_PARAM = "'modification_time' action parameter"
CREATIONTIME_ACTION_PARAM = "'creation_time' action parameter"
SEARCHFROM_ACTION_PARAM = "'search_from' action parameter"
SEARCHTO_ACTION_PARAM = "'search_to' action parameter"
ALERTSLIMIT_ACTION_PARAM = "'alerts_limit' action parameter"
ALERTID_ACTION_PARAM = "'alert_id' action parameter"

SORTORDER_ACTION_PARAM = "'sort_order' action parameter"
SORTFIELD_ACTION_PARAM = "'sort_field' action parameter"
PLATFORM_ACTION_PARAM = "'platform' action parameter"
SCANSTATUS_ACTION_PARAM = "'scan_status' action parameter"
STATUS_ACTION_PARAM = "'status' action parameter"
SEVERITY_ACTION_PARAM = "'severity' action parameter"

# Value Lists
PLATFORMS_LIST = ["windows", "linux", "macos", "android"]
SCAN_STATUSES = ["none", "pending", "in_progress", "canceled", "aborted", "pending_cancellation", "success", "error"]
SORT_ORDERS = ["asc", "desc"]
