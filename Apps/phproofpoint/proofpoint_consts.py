# File: proofpoint_consts.py
# Copyright (c) 2017-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

PP_API_BASE_URL = "https://tap-api-v2.proofpoint.com"
PP_API_PATH_CLICKS_BLOCKED = "/v2/siem/clicks/blocked"
PP_API_PATH_CLICKS_PERMITTED = "/v2/siem/clicks/permitted"
PP_API_PATH_MESSAGES_BLOCKED = "/v2/siem/messages/blocked"
PP_API_PATH_MESSAGES_DELIVERED = "/v2/siem/messages/delivered"
PP_API_PATH_ISSUES = "/v2/siem/issues"
PP_API_PATH_ALL = "/v2/siem/all"
PP_API_PATH_CAMPAIGN = "/v2/campaign/{}"
PP_API_PATH_FORENSICS = "/v2/forensics"
PP_API_PATH_DECODE = "/v2/url/decode"

#  Constants relating to 'get_error_message_from_exception'
ERROR_CODE_MSG = "Error code unavailable"
ERROR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Proofpoint TAP Server. Please check the asset configuration and|or action parameters."
