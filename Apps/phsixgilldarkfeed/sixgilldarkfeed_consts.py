# File: sixgilldarkfeed_consts.py
#
# Copyright (c) 2021 Cybersixgill Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


SIXGILL_API_ID_CFG = "sixgill_client_id"
SIXGILL_API_SECRET_KEY_CFG = "sixgill_client_secret_key"
SIXGILL_VERIFY_SSL = "verify_ssl"
AUTH_TOKEN = "phantom_auth_token"
SIXGILL_CHANNEL_ID = "d6803eff87582a695d5630f1a52152bf"

SIXGILL_TEST_CONNECTIVITY_MSG = "Testing Configured Cybersixgill Darkfeed API Credentials in the Asset Settings"
SIXGILL_TEST_CONNECTIVITY_MSG_PASS = "Connectivity Test Passed"
SIXGILL_TEST_CONNECTIVITY_MSG_FAIL = "Connectivity Test Failed"

SIXGILL_TEST_CONNECTIVITY_MISC = "Something happened. Please try again..."

SIXGILL_INDICATOR_STATUS = "Open"
SIXGILL_INDICATOR_TYPE = "Type"
SIXGILL_INDICATOR_VALUE = "Value"
PHANTOM_EVENT_TYPE = "Event"

# Sixgill Darkfeed Attributes
SIXGILL_FEED_ACTOR = "sixgill_actor"
SIXGILL_FEED_CONFIDENCE = "sixgill_confidence"
SIXGILL_FEED_FEEDID = "sixgill_feedid"
SIXGILL_FEED_FEEDNAME = "sixgill_feedname"
SIXGILL_FEED_POSTID = "sixgill_postid"
SIXGILL_FEED_POSTTITLE = "sixgill_posttitle"
SIXGILL_FEED_SEVERITY = "sixgill_severity"
SIXGILL_FEED_SOURCE = "sixgill_source"
SIXGILL_FEED_VALID_FROM = "valid_from"
SIXGILL_FEED_MODIFIED = "modified"
SIXGILL_FEED_ID = "id"

# Sixgill Darkfeed Artifacts
SIXGILL_ARTIFACT_IP = "IP"
SIXGILL_ARTIFACT_ACTOR = "Sixgill_Actor"
SIXGILL_ARTIFACT_CONFIDENCE = "Sixgill_Confidence"
SIXGILL_ARTIFACT_FEEDID = "Sixgill_Feed_ID"
SIXGILL_ARTIFACT_FEEDNAME = "Sixgill_Feed_Name"
SIXGILL_ARTIFACT_POSTID = "Sixgill_Post_ID"
SIXGILL_ARTIFACT_POSTTITLE = "Sixgill_Post_Title"
SIXGILL_ARTIFACT_SOURCE = "Sixgill_Source"

# Misc
SIXGILL_DARKFEED = "Sixgill Darkfeed"
SIXGILL_LABELS = "labels"
POSTFIX_ARTIFACT = "Artifact"
CONTAINER_COUNT = "container_count"
COUNT = "count"
DATA = "data"
REST_ARTIFACT_API = "/rest/artifact/"
REST_CONTAINER_API = "/rest/container/"
SOURCE_FEED_ID = "?_filter_source_data_identifier="
CONTAINER_ID = "container"
ARTIFACT_ID = "id"
CONTAINER = "Container"
ARTIFACT_LIST = "Artifact List"
SEVERTITY = "severity"
TRY_AGAIN = "5"
BASE_URL = "https://127.0.0.1"
REVOKED = "revoked"
TRUE = "true"

# default severity and sensitivity
DEFAULT_SEVERITY = "medium"
DEFAULT_SENSITIVITY = "amber"

# mitre and virustotal
SIXGILL_FEED_EXTERNAL_REFERENCE = "external_reference"
SIXGILL_FEED_SOURCENAME = "source_name"
VIRUSTOTAL = "VirusTotal"
MITRE_ATTACK = "mitre-attack"

# mitre tactic and technique
MITRE_ATTACK_TATIC = "mitre_attack_tactic"
MITRE_ATTACK_TATIC_ID = "mitre_attack_tactic_id"
MITRE_ATTACK_TATIC_URL = "mitre_attack_tactic_url"
MITRE_ATTACK_TECHNIQUE = "mitre_attack_technique"
MITRE_ATTACK_TECHNIQUE_ID = "mitre_attack_technique_id"
MITRE_ATTACK_TECHNIQUE_URL = "mitre_attack_technique_url"

# virustotal
VIRUSTOTAL_POSITIVE_RATE = "positive_rate"
VIRUSTOTAL_URL = "url"

# sixgill mitre artifacts
SIXGILL_MITRE_ATTACK_TATIC = "Tactic_Name"
SIXGILL_MITRE_ATTACK_TATIC_ID = "Tactic_ID"
SIXGILL_MITRE_ATTACK_TATIC_URL = "Tactic_URL"
SIXGILL_MITRE_ATTACK_TECHNIQUE = "Technique_Name"
SIXGILL_MITRE_ATTACK_TECHNIQUE_ID = "Technique_ID"
SIXGILL_MITRE_ATTACK_TECHNIQUE_URL = "Technique_URL"

# sixgill virustotal artifacts
SIXGILL_VIRUSTOTAL_POSITIVE_RATE = "Positive_Rate"
SIXGILL_VIRUSTOTAL_URL = "Virus_Total_URL"


# enrichment Actions
SIXGILL_IP = "ip"
SIXGILL_URL = "url"
SIXGILL_HASH = "hash"
SIXGILL_POSTID = "postid"
SIXGILL_ACTOR = "actor"
SIXGILL_DOMAIN = "domain"

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

SIXGILL_ACTION_NOT_SUPPORTED = "The requested action {} is not supported"
