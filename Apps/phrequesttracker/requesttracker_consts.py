# File: rt_consts.py
# Copyright (c) 2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


RT_JSON_DEVICE_URL = "device_url"
RT_JSON_PRIORITY = "priority"

RT_JSON_ID = "id"
RT_JSON_ATTACHMENT = "attachment_id"
RT_JSON_VAULT = "vault_id"
RT_JSON_QUEUE = "queue"
RT_JSON_OWNER = "owner"
RT_JSON_CREATOR = "creator"
RT_JSON_SUBJECT = "subject"
RT_JSON_STATUS = "status"
RT_JSON_INITIALPRIORITY = "initial_priority"
RT_JSON_FINALPRIORITY = "final_Priority"
RT_JSON_REQUESTORS = "requestors"
RT_JSON_CC = "cc"
RT_JSON_ADMINCC = "admin_cc"
RT_JSON_CREATED = "created"
RT_JSON_STARTS = "starts"
RT_JSON_STARTED = "started"
RT_JSON_DUE = "due"
RT_JSON_RESOLVED = "resolved"
RT_JSON_TOLD = "told"
RT_JSON_TIMEESTIMATED = "time_estimated"
RT_JSON_TIMEWORKED = "time_worked"
RT_JSON_TIMELEFT = "time_left"
RT_JSON_COMMENT = "comment"
RT_JSON_FIELDS = "fields"

RT_JSON_QUERY = "query"
RT_TOTAL_ISSUES = "total_issues"
RT_JSON_TEXT = "text"
RT_JSON_NEW_TICKET_ID = "new_ticket_id"

RT_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
RT_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
RT_ERR_CREATE_TICKET_FAILED = "Ticket creation failed"
RT_ERR_LIST_TICKETS_FAILED = "Failed to get ticket listing"
RT_ERR_LOGIN_FAILED = "Login to RT server failed. Text from device '{status}'"
RT_CREATED_TICKET = "Created ticket"
RT_USING_BASE_URL = "Using url: {base_url}"
RT_ERR_NO_DATA_FROM_DEVICE = "Did not get valid data from device"
RT_ERR_UPDATE_SUBJECT_FAILED = "Update of subject failed"
RT_ERR_UPDATE_COMMENT_FAILED = "Update of comment failed"

DEFAULT_PRIORITY = "0"
DEFAULT_QUEUE = "1"
RT_TICKET_FOOTNOTE = "Added by Phantom for container id: "
PHANTOM_VAULT_DIR = "/opt/phantom/vault/tmp/"
