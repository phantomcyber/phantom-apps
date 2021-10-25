# File: fireeye_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# Define your constants here
FIREETEETP_API_PATH = "api/v1/"
FIREETEETP_LIST_ALERTS_ENDPOINT = "alerts"
FIREETEETP_GET_ALERT_ENDPOINT = "alerts/{alertId}"
FIREETEETP_GET_ALERT_CASE_FILES_ENDPOINT = "alerts/{alertId}/downloadzip"
FIREETEETP_GET_ALERT_MALWARE_FILES_ENDPOINT = "alerts/{alertId}/downloadmalware"
FIREETEETP_GET_ALERT_PCAP_FILES_ENDPOINT = "alerts/{alertId}/downloadpcap"
FIREETEETP_LIST_MESSAGE_ATTRIBUTES_ENDPOINT = "messages/trace"
FIREETEETP_GET_MESSAGE_ATTRIBUTES_ENDPOINT = "messages/{etp_message_id}"
FIREETEETP_GET_MESSAGE_TRACE_ENDPOINT = "messages"
FIREETEETP_GET_EMAIL_ENDPOINT = "messages/{etp_message_id}/email"
FIREETEETP_REMEDIATE_EMAILS_ENDPOINT = "messages/remediate"
FIREEYEETP_GET_QUARANTINED_EMAIL_ENDPOINT = "quarantine/email/{etp_message_id}"
FIREEYEETP_BULK_RELEASE_QUARANTINE_EMAILS_ENDPOINT = "quarantine/release/"
FIREEYEETP_RELEASE_QUARANTINED_EMAIL_ENDPOINT = "quarantine/release/{etp_message_id}"
FIREEYEETP_BULK_DELETE_QUARANTINE_EMAILS_ENDPOINT = "quarantine/delete/"
FIREEYEETP_DELETE_QUARANTINED_EMAIL_ENDPOINT = "quarantine/delete/{etp_message_id}"
FIREEYEETP_LIST_QUARANTINED_EMAILS_ENDPOINT = "quarantine"

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Fireeye ETP Server. Please check the asset configuration and|or the action parameters"

# Constants relating to '_validate_integer'
VALID_INTEGER_MSG = "Please provide a valid integer value in the {}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {}"
POSITIVE_INTEGER_MSG = "Please provide a valid non-zero positive integer value in the {}"
SIZE_KEY = "'size' action parameter"
LEGACY_ID_KEY = "'legacy_id' action parameter"
NUM_DAYS_KEY = "'num_days' action parameter"
CONTAINER_COUNT_KEY = "'container_count' action parameter"
