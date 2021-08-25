# File: panorama_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

PAN_ERR_REPLY_FORMAT_KEY_MISSING = "None '{key}' missing in reply from device"
PAN_ERR_REPLY_NOT_SUCCESS = "REST call returned '{status}'"
PAN_ERR_UNABLE_TO_PARSE_REPLY = "Unable to parse reply from device"
PAN_SUCC_TEST_CONNECTIVITY_PASSED = "Test connectivity passed"
PAN_ERR_TEST_CONNECTIVITY_FAILED = "Test connectivity failed"
PAN_SUCC_REST_CALL_SUCCEEDED = "REST Api call succeeded"
PAN_ERR_CREATE_UNKNOWN_TYPE_SEC_POL = "Asked to create unknown type of security policy"
PAN_ERR_INVALID_IP_FORMAT = "Invalid ip format"
PAN_ERR_DEVICE_CONNECTIVITY = "Error in connecting to device"
PAN_ERR_PARSE_POLICY_DATA = "Unable to parse security policy config"
PAN_ERR_NO_POLICY_ENTRIES_FOUND = "Could not find any security policies to update"
PAN_ERR_NO_ALLOW_POLICY_ENTRIES_FOUND = "Did not find any policies with an 'allow' action for device group '{dev_sys_value}' and type '{policy_type}'."
PAN_ERR_NO_ALLOW_POLICY_ENTRIES_FOUND += "\nNeed atleast one such policy"
PAN_ERR_POLICY_NOT_PRESENT_CONFIG_DONT_CREATE = "Policy not found. Please verify that provided parameter values are correct"
PAN_ERR_NO_JOB_ID = "Could not find Job ID in response body"
PAN_ERR_CODE_MESSAGE = "Error code unavailable"
PAN_ERR_MESSAGE = "Unknown error occurred. Please check the asset configuration and|or action parameters"
TYPE_ERR_MESSAGE = "Error occurred while connecting to the Panorama server. Please check the asset configuration and|or the action parameters"
PARSE_ERR_MESSAGE = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
PAN_ERR_MSG = "Error occurred while {}. Details: {}"

PAN_PROG_USING_BASE_URL = "Using base URL '{base_url}'"
PAN_PROG_GOT_REPLY = "Got reply, parsing..."
PAN_PROG_PARSED_REPLY = "Done"
PAN_PROG_COMMIT_PROGRESS = "Commit completed {progress}%"
PAN_PROG_COMMIT_ALL_PROGRESS = "Commit on device group: {device_group} completed {progress}%"
PAN_PROG_COMMIT_PROGRESS_PENDING = "Commit completed {progress}%, but still Pending on remote device"

PAN_JSON_DEVICE_GRP = "device_group"
PAN_JSON_URL = "url"
PAN_JSON_APPLICATION = "application"
PAN_JSON_IP = "ip"
PAN_JSON_TOTAL_APPLICATIONS = "total_applications"
PAN_JSON_SEC_POLICY = "sec_policy"
PAN_JSON_POLICY_TYPE = "policy_type"
PAN_JSON_POLICY_NAME = "policy_name"
PAN_JSON_CREATE_POLICY = "create_policy"
PAN_JSON_SOURCE_ADDRESS = "is_source_address"
PAN_JSON_QUERY = "query"
PAN_JSON_LOG_TYPE = "log_type"
PAN_DEFAULT_SOURCE_ADDRESS = False

# Name consts
SEC_POL_NAME = "Phantom {sec_policy_type} Security Policy"
SEC_POL_NAME_SRC = "Phantom src {type} Security Policy"
BLOCK_URL_PROF_NAME = "Phantom URL List for {device_group}"
BLOCK_IP_GROUP_NAME = "Phantom Network List for {device_group}"
BLOCK_IP_GROUP_NAME_SRC = "PhantomNtwrkSrcLst{device_group}"
BLOCK_APP_GROUP_NAME = "Phantom App List for {device_group}"
PHANTOM_ADDRESS_NAME = "Added By Phantom"
PAN_DEV_GRP_SHARED = "shared"

SEC_POL_URL_TYPE = "URL"
SEC_POL_APP_TYPE = "App"
SEC_POL_IP_TYPE = "IP"

MAX_NODE_NAME_LEN = 31
MAX_QUERY_COUNT = 5000

# Various xpaths and elem nodes

# This one is used to get all the policies
SEC_POL_RULES_XPATH = "{config_xpath}/{policy_type}/security/rules"

# This one is used while adding a security policy
SEC_POL_XPATH = "{config_xpath}/{policy_type}/security/rules/entry[@name='{sec_policy_name}']"

SEC_POL_DEF_ELEMS = "<from><member>any</member></from>"
SEC_POL_DEF_ELEMS += "<to><member>any</member></to>"
SEC_POL_DEF_ELEMS += "<source><member>any</member></source>"
SEC_POL_DEF_ELEMS += "<source-user><member>any</member></source-user>"
SEC_POL_DEF_ELEMS += "<category><member>any</member></category>"
SEC_POL_DEF_ELEMS += "<service><member>application-default</member></service>"
SEC_POL_DEF_ELEMS += "<hip-profiles><member>any</member></hip-profiles>"
SEC_POL_DEF_ELEMS += "<description>Created by Phantom for Panorama, please don't edit</description>"

ACTION_NODE_DENY = "<action>deny</action>"
ACTION_NODE_ALLOW = "<action>allow</action>"
URL_PROF_SEC_POL_ELEM = "<profile-setting>"
URL_PROF_SEC_POL_ELEM += "<profiles><url-filtering><member>{url_prof_name}</member></url-filtering></profiles>"
URL_PROF_SEC_POL_ELEM += "</profile-setting>"

IP_GRP_SEC_POL_ELEM = "<destination><member>{ip_group_name}</member></destination>"
IP_GRP_SEC_POL_ELEM_SRC = "<source><member>{ip_group_name}</member></source>"
APP_GRP_SEC_POL_ELEM = "<application><member>{app_group_name}</member></application>"

URL_PROF_XPATH = "{config_xpath}/profiles/url-filtering/entry[@name='{url_profile_name}']"
DEL_URL_CATEGORY_XPATH = "/list/member[text()='{url}']"

# URL_PROF_ELEM for version 8 and below. block-list is no longer supported from 9.0 and above.
URL_PROF_ELEM = "<description>Created by Phantom for Panorama</description>"
URL_PROF_ELEM += "<action>block</action><block-list><member>{url}</member></block-list>"

# URL_PROF_ELEM for version 9 and above.
URL_PROF_ELEM_9 = "<credential-enforcement>"
URL_PROF_ELEM_9 += "<mode><disabled/></mode>"
URL_PROF_ELEM_9 += "<block><member>{url_category_name}</member></block>"
URL_PROF_ELEM_9 += "</credential-enforcement>"
URL_PROF_ELEM_9 += "<block><member>{url_category_name}</member></block>"

URL_CATEGORY_XPATH = "{config_xpath}/profiles/custom-url-category/entry[@name='{url_profile_name}']"

# We can make this work on version 8 and below as well by removing <type>URL List</type>. However, </list><type>URL List</type> is required for version 9 and above.
URL_CATEGORY_ELEM = "<description>Created by Phantom for Panorama</description>"
URL_CATEGORY_ELEM += "<list><member>{url}</member></list>"
URL_CATEGORY_ELEM += "<type>URL List</type>"

DEL_URL_XPATH = "/block-list/member[text()='{url}']"

APP_GRP_XPATH = "{config_xpath}/application-group/entry[@name='{app_group_name}']"
APP_GRP_ELEM = "<members><member>{app_name}</member></members>"
DEL_APP_XPATH = "/members/member[text()='{app_name}']"

ADDR_GRP_XPATH = "{config_xpath}/address-group/entry[@name='{ip_group_name}']"
ADDR_GRP_ELEM = "<static><member>{addr_name}</member></static>"
DEL_ADDR_GRP_XPATH = "/static/member[text()='{addr_name}']"

IP_ADDR_XPATH = "{config_xpath}/address/entry[@name='{ip_addr_name}']"
IP_ADDR_ELEM = "<{ip_type}>{ip}</{ip_type}><tag><member>{tag}</member></tag>"

TAG_CONTAINER_COMMENT = "Phantom Container ID"
TAG_COLOR = "color7"
TAG_XPATH = "{config_xpath}/tag"
TAG_ELEM = "<entry name='{tag}'><color>{tag_color}</color><comments>{tag_comment}</comments></entry>"

APP_LIST_XPATH = "/config/predefined/application"
COMMIT_ALL_DEV_GRP_DEV_CMD = '<commit-all><shared-policy>'
COMMIT_ALL_DEV_GRP_DEV_CMD += '<device-group>'
COMMIT_ALL_DEV_GRP_DEV_CMD += '<entry name="{device_group}"><devices><entry name="{dev_ser_num}"/></devices></entry>'
COMMIT_ALL_DEV_GRP_DEV_CMD += '</device-group>'
COMMIT_ALL_DEV_GRP_DEV_CMD += '</shared-policy></commit-all>'

# Constants relating to value_list check
POLICY_TYPE_VALUE_LIST = ["pre-rulebase", "post-rulebase"]
LOG_TYPE_VALUE_LIST = ["traffic", "url", "corr", "data", "threat", "config", "system", "hipmatch", "wildfire", "corr-categ", "corr-detail"]
DIRECTION_VALUE_LIST = ["backward", "forward"]
VALUE_LIST_VALIDATION_MSG = "Please provide valid input from {} in '{}' action parameter"
